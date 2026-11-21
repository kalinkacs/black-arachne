from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from arachne.events import from_journal
from arachne.mimicry import mimic
from arachne.operations import operational_review, triage
from arachne.store import database, get_run, ingest
from test_arachne import journal
from test_offline import bind_session, sample

READY = datetime(2026, 1, 1, 13, tzinfo=timezone.utc)


class LateActivityTests(unittest.TestCase):
    def test_late_session_activity_reopens_only_the_matched_login_and_only_once(self):
        anchor, events = bind_session(*sample("change-confirmed"))
        first = replace(anchor, source="systemd-journal")
        second = replace(first, id="parallel-login", session_key="2" * 64)
        activity = replace(next(event for event in events if event.kind == "privileged_activity"),
                           source="systemd-journal")
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "records.sqlite3"
            with database(db) as connection:
                ingest(connection, [first, second])
            self.assertEqual(triage(db, now=READY)["investigated"], 2)
            with database(db) as connection:
                ingest(connection, [activity])
            new_id, = triage(db, now=READY)["runs"]
            with database(db) as connection:
                report = get_run(connection, new_id)
                self.assertEqual(report["anchor_id"], first.id)
                self.assertEqual(report["session_attribution"]["linked"], [activity.id])
                self.assertEqual(ingest(connection, [activity]), 0)
                ingest(connection, [replace(activity, id="unbound", session_key=None)])
            self.assertEqual(triage(db, now=READY)["investigated"], 0)

    def test_activity_committed_during_an_investigation_is_seen_on_the_next_pass(self):
        anchor, events = bind_session(*sample("change-confirmed"))
        anchor = replace(anchor, source="systemd-journal")
        activity = next(event for event in events if event.kind == "privileged_activity")
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "records.sqlite3"
            with database(db) as connection:
                ingest(connection, [anchor])

            def ingest_on_other_connection(connection, login, observations, model):
                with database(db) as writer:
                    ingest(writer, [activity])
                return operational_review(connection, login, observations, model)

            with patch("arachne.operations.operational_review", ingest_on_other_connection):
                first_id, = triage(db, now=READY)["runs"]
            second_id, = triage(db, now=READY)["runs"]
            with database(db) as connection:
                self.assertEqual(get_run(connection, first_id)["session_attribution"]["linked"], [])
                self.assertEqual(get_run(connection, second_id)["session_attribution"]["linked"], [activity.id])

    def test_native_ssh_replay_can_enrich_an_existing_unbound_case(self):
        anchor, events = bind_session(*sample("change-confirmed"))
        bound = replace(anchor, source="systemd-journal")
        legacy = replace(bound, machine_id=None, session_key=None)
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "records.sqlite3"
            with database(db) as connection:
                ingest(connection, [legacy])
            prior, = triage(db, now=READY)["runs"]
            with database(db) as connection:
                ingest(connection, [bound])
            new, = triage(db, now=READY)["runs"]
            with database(db) as connection:
                self.assertEqual(get_run(connection, prior)["session_attribution"]["status"], "unbound")
                self.assertEqual(get_run(connection, new)["session_attribution"]["status"], "bound")


class SudoClassificationTests(unittest.TestCase):
    def test_rejected_sudo_request_is_never_counted_as_privilege_activity(self):
        row = journal("operator : user NOT in sudoers ; TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/true",
                      "sudo", "fixture-denial", 0)
        denied = from_journal(row, native=True)
        self.assertEqual(denied.kind, "privilege_denied")
        self.assertNotIn("/usr/bin/true", str(denied))

        accepted = journal("operator : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/true",
                           "sudo", "fixture-allow", 1)
        self.assertEqual(from_journal(accepted, native=True).kind, "privileged_activity")

    def test_repeated_denials_require_review_even_with_an_approved_change(self):
        anchor, events = sample("change-confirmed")
        activity = next(event for event in events if event.kind == "privileged_activity")
        denied = [replace(activity, kind="privilege_denied", id=f"denial-{index}") for index in range(2)]
        self.assertEqual(mimic(anchor, [*events, denied[0]])["recommendation"]["decision"], "close")
        repeated = mimic(anchor, [*events, *denied])
        self.assertEqual(repeated["blue"]["decision"], "review")
        self.assertEqual(repeated["recommendation"]["decision"], "review")
        self.assertEqual(repeated["full_evidence_reference"]["decision"], "review")
