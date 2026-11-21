from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from arachne.events import from_journal
from arachne.operations import operational_review, triage
from arachne.pilot import since_cutoff, summary
from arachne.store import confirm_outcome, database, episode, get_run, ingest, save_run
from test_arachne import journal
from test_offline import bind_session, sample


class SessionTests(unittest.TestCase):
    def test_native_pam_open_and_sudo_rows_share_session_key(self):
        fields = {"_MACHINE_ID": "a" * 32, "_BOOT_ID": "b" * 32, "_AUDIT_SESSION": "12"}
        login = journal("pam_unix(sshd:session): session opened for user operator(uid=1001) by (uid=0)", "sshd", "open", 0)
        sudo = journal("operator : TTY=pts/0 ; COMMAND=/usr/bin/true", "sudo", "sudo", 1)
        anchor = from_journal({**login, **fields}, native=True)
        linked = from_journal({**sudo, **fields}, native=True)
        self.assertEqual(anchor.kind, "ssh_session_open")
        self.assertEqual(anchor.actor, "operator")
        self.assertEqual(anchor.session_key, linked.session_key)
        verbose = journal("Starting session: command for operator from 127.0.0.1 port 12345 id 0", "sshd", "verbose", 0)
        self.assertEqual(from_journal({**verbose, **fields}, native=True).session_key, anchor.session_key)
        self.assertIsNone(from_journal({**login, **fields, "_AUDIT_SESSION": "4294967295"}, native=True))
        self.assertNotEqual(from_journal({**sudo, **fields, "_BOOT_ID": "c" * 32}, native=True).session_key,
                            anchor.session_key)

    def test_parallel_authorized_logins_are_kept_separate_and_unbound_activity_stays_unattributed(self):
        anchor, events = bind_session(*sample("change-confirmed"))
        activity = next(event for event in events if event.kind == "privileged_activity")
        second = replace(anchor, id="parallel-login", session_key="2" * 64)
        unbound = replace(activity, id="unattributed-activity", session_key=None)
        with tempfile.TemporaryDirectory() as directory:
            with database(Path(directory) / "test.sqlite3") as connection:
                ingest(connection, [*events, second, unbound])
                first_report = operational_review(connection, anchor, episode(connection, anchor.host, anchor.id)[1], None)
                other_report = operational_review(connection, second, episode(connection, second.host, second.id)[1], None)
        self.assertIn(activity.id, first_report["session_attribution"]["linked"])
        self.assertIn(activity.id, other_report["session_attribution"]["excluded"])
        self.assertIn(unbound.id, other_report["session_attribution"]["excluded"])
        self.assertEqual(other_report["recommendation"]["decision"], "review")

    def test_bound_accepted_and_pam_records_queue_only_one_dossier(self):
        anchor, _ = bind_session(*sample("change-confirmed"))
        anchor = replace(anchor, source="systemd-journal")
        duplicate = replace(anchor, id="corroborating-login", kind="ssh_session_open",
                            timestamp="2026-01-01T12:10:01.000000+00:00")
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "test.sqlite3"
            with database(db) as connection:
                ingest(connection, [anchor, duplicate])
            now = datetime(2026, 1, 1, 13, tzinfo=timezone.utc)
            result = triage(db, now=now)
            with database(db) as connection:
                record = get_run(connection, result["runs"][0])
            self.assertEqual(result["investigated"], 1)
            self.assertEqual(record["anchor_id"], anchor.id)
            self.assertEqual(triage(db, now=now)["investigated"], 0)

    def test_repeat_import_can_enrich_old_native_metadata(self):
        old, _ = sample("change-confirmed")
        old = replace(old, source="systemd-journal")
        fresh = replace(old, machine_id="a" * 32, session_key="2" * 64)
        with tempfile.TemporaryDirectory() as directory:
            with database(Path(directory) / "test.sqlite3") as connection:
                self.assertEqual(ingest(connection, [old]), 1)
                self.assertEqual(ingest(connection, [fresh]), 0)
                self.assertEqual(episode(connection, fresh.host, fresh.id)[0], fresh)


class PilotSummaryTests(unittest.TestCase):
    def test_counts_latest_dossiers_and_only_confirmed_current_outcomes(self):
        anchor, events = bind_session(*sample("change-confirmed"))
        first = replace(anchor, source="systemd-journal")
        unbound = replace(first, id="unbound-anchor", session_key=None)
        with tempfile.TemporaryDirectory() as directory:
            with database(Path(directory) / "pilot.sqlite3") as connection:
                ingest(connection, [first, unbound])
                operational = operational_review(connection, first, [*events, unbound], None)
                old = save_run(connection, operational)
                confirm_outcome(connection, old["id"], "review", "Earlier review")
                current = save_run(connection, operational)
                save_run(connection, {**operational, "scenario": "excluded-lab"})
                before = summary(connection, since_cutoff(None))
                self.assertEqual(before["cases"]["current"], 1)
                self.assertEqual(before["cases"]["decisions_confirmed"], 0)
                self.assertEqual(before["journal"]["bound_observations"], 1)
                confirm_outcome(connection, current["id"], "review", "Reviewed new evidence")
                after = summary(connection, since_cutoff(None))
                self.assertEqual(after["cases"]["decisions_confirmed"], 1)
                self.assertEqual(after["decisions"]["full_evidence_reference"]["checked"], 1)
