import io
import json
import os
from dataclasses import replace
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from arachne.events import Event, from_journal, read_records
from arachne.lab import run_lab, scenarios
from arachne.agents import model_review
from arachne.reasoning import investigate
from arachne.store import database, episode, get_run, ingest


def journal(message, identifier, cursor, minute):
    return {
        "__CURSOR": cursor, "_HOSTNAME": "test-host",
        "__REALTIME_TIMESTAMP": str((1_767_268_800 + 60 * minute) * 1_000_000),
        "SYSLOG_IDENTIFIER": identifier, "MESSAGE": message,
        "_EXE": {"sshd": "/usr/sbin/sshd", "sshd-session": "/usr/lib/openssh/sshd-session",
                 "sudo": "/usr/bin/sudo"}.get(identifier, "/usr/bin/unknown"),
    }


class EvidenceTests(unittest.TestCase):
    def test_journal_drops_unneeded_fields_and_handles_new_sshd_identifier(self):
        record = journal("Accepted publickey for operator from 192.0.2.1 port 1 ssh2", "sshd-session", "cursor-a", 0)
        event = from_journal(record)
        self.assertEqual((event.host, event.kind, event.actor), ("test-host", "ssh_login", "operator"))
        self.assertNotIn("192.0.2.1", repr(event))
        self.assertEqual(event.id, from_journal(record).id)
        self.assertIsNone(from_journal(journal("other", "sshd", "cursor-b", 1)))

    def test_native_journal_requires_recognized_executable_metadata(self):
        record = journal("Accepted publickey for operator from 192.0.2.1 port 1 ssh2", "sshd", "a", 0)
        self.assertEqual(from_journal(record, native=True).kind, "ssh_login")
        self.assertIsNone(from_journal({**record, "_EXE": "/usr/bin/logger"}, native=True))

    def test_invalid_event_and_oversized_input_are_rejected(self):
        with self.assertRaises(ValueError):
            Event.parse({"id": "incomplete"})
        with self.assertRaises(ValueError):
            list(read_records(io.StringIO("x" * 65_537)))

    def test_ingestion_is_idempotent_and_rolls_back_a_conflict(self):
        _, _, events = next(scenarios())
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "test.sqlite3"
            with database(path) as connection:
                self.assertEqual(ingest(connection, events[:1]), 1)
                self.assertEqual(ingest(connection, events[:1]), 0)
            with self.assertRaisesRegex(ValueError, "Conflicting evidence id"):
                with database(path) as connection:
                    ingest(connection, [events[1], replace(events[0], actor="other")])
            with database(path) as connection:
                self.assertEqual(connection.execute("SELECT count(*) FROM events").fetchone()[0], 1)

    def test_window_is_host_scoped_and_excludes_late_events(self):
        _, _, events = next(scenarios())
        anchor = events[1]
        with tempfile.TemporaryDirectory() as temporary:
            with database(Path(temporary) / "test.sqlite3") as connection:
                ingest(connection, [*events, replace(events[2], host="other", id="other"),
                                    replace(events[2], timestamp="2026-01-01T13:00:00.000000+00:00", id="late")])
                self.assertEqual(episode(connection, anchor.host, anchor.id), (anchor, events))


class InvestigationTests(unittest.TestCase):
    def test_forecast_does_not_see_hidden_confirmation(self):
        _, _, events = next(scenarios())
        reviewed = investigate(events[1], events)
        unverified = investigate(events[1], events[:-1])
        self.assertEqual(reviewed["forecast"], unverified["forecast"])
        self.assertEqual(reviewed["assisted"]["decision"], "close")
        self.assertEqual(unverified["blue"]["decision"], "close")
        self.assertEqual(unverified["assisted"]["decision"], "review")

    def test_mock_model_receives_only_relative_observations(self):
        _, _, events = next(scenarios())
        event = events[1]
        decision = {"check": "change_record", "prediction": "close",
                    "hypothesis": "Check the declaration.", "evidence_ids": ["E1"]}

        def provider(request, timeout):
            body = json.loads(request.data)
            visible = json.loads(body["messages"][1]["content"])["events"]
            self.assertEqual(len(visible), 3)
            self.assertTrue(visible[1]["is_anchor"])
            self.assertEqual(set(visible[1]), {"handle", "is_anchor", "kind", "offset_seconds"})
            self.assertNotIn(event.host, str(visible))
            return io.BytesIO(json.dumps({"choices": [{"message": {"content": json.dumps(decision)}}]}).encode())

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-only"}), patch("arachne.agents.urllib.request.urlopen", provider):
            self.assertEqual(model_review("red_forecast", "test-model", event, events[:-1])["evidence_ids"], [event.id])
            decision["evidence_ids"] = ["unknown"]
            with self.assertRaisesRegex(ValueError, "evidence validation"):
                model_review("red_forecast", "test-model", event, events[:-1])

    def test_synthetic_smoke_results_and_persisted_runs(self):
        with tempfile.TemporaryDirectory() as temporary:
            with database(Path(temporary) / "test.sqlite3") as connection:
                report = run_lab(connection)
                self.assertEqual(report["correct"], {"blue": 3, "standard_review": 4, "assisted": 4})
                self.assertEqual(get_run(connection, report["runs"][1])["label"], "review")

    def test_cli_imports_journal_and_investigates_the_anchor(self):
        with tempfile.TemporaryDirectory() as temporary:
            command = [sys.executable, "-m", "arachne", "--db", str(Path(temporary) / "test.sqlite3")]
            rows = [
                journal("Accepted publickey for operator from 192.0.2.1 port 1 ssh2", "sshd", "a", 0),
                journal("operator : TTY=pts/0 ; COMMAND=/usr/bin/true", "sudo", "b", 1),
            ]
            imported = subprocess.run([*command, "import-journal"], check=True, capture_output=True, text=True,
                                      input="\n".join(map(json.dumps, rows)))
            self.assertEqual(json.loads(imported.stdout)["inserted"], 2)
            anchor = json.loads(subprocess.check_output([*command, "anchors"]))[0]
            report = json.loads(subprocess.check_output([*command, "investigate", anchor["host"], anchor["id"]]))
            self.assertEqual(report["blue"]["decision"], "review")
            self.assertEqual([event["kind"] for event in report["events"]], ["ssh_login", "privileged_activity"])


if __name__ == "__main__":
    unittest.main()
