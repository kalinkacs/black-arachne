from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from arachne.operations import triage
from arachne.provenance import create_key, load_key, sign_record
from arachne.role_runtime import RoleProcess
from arachne.store import database, get_run, import_verifications, ingest
from test_offline import bind_session, sample


class ObjectionJournalTests(unittest.TestCase):
    def test_restart_and_worker_loss_preserve_the_unanswered_objection(self):
        anchor, events = bind_session(*sample("change-confirmed"))
        native = replace(anchor, source="systemd-journal")
        change = next(event for event in events if event.kind == "change_verified")
        identity = replace(change, id="identity-answer", kind="identity_verified", source="identity-management")
        login_time = datetime.fromisoformat(anchor.timestamp)
        failures = [
            replace(native, id=f"preceding-failure-{index}", kind="ssh_failure",
                    timestamp=(login_time - timedelta(seconds=index + 1)).isoformat(timespec="microseconds"))
            for index in range(3)
        ]
        with TemporaryDirectory() as folder:
            db = Path(folder) / "cases.sqlite3"
            change_path = Path(folder) / "change.json"
            identity_path = Path(folder) / "identity.json"
            create_key(change_path, "change", change.source, anchor.host)
            create_key(identity_path, "identity", identity.source, anchor.host)
            with database(db) as connection:
                ingest(connection, [native, *failures,
                                    *(event for event in events if event.id != anchor.id)])
            result = subprocess.check_output(
                [sys.executable, "-m", "arachne", "--db", str(db), "triage", "--offline"],
                text=True, timeout=15,
            )
            first_id, = json.loads(result)["runs"]

            stopped = []

            class InterruptedBlue(RoleProcess):
                def call(self, phase, payload):
                    if self.role == "blue" and phase == "reconsider" and not stopped:
                        stopped.append(self.process.pid)
                        self.process.kill()
                        self.process.wait(timeout=2)
                    return super().call(phase, payload)

            with database(db) as connection:
                key = load_key(change_path)
                import_verifications(connection, key, [sign_record(key, anchor.id, change)])
            now = datetime(2026, 1, 1, 13, tzinfo=timezone.utc)
            with patch("arachne.mimicry.RoleProcess", InterruptedBlue):
                second_id, = triage(db, now=now)["runs"]
            self.assertEqual(len(stopped), 1)
            with database(db) as connection:
                first = get_run(connection, first_id)["objection_journal"]
                second = get_run(connection, second_id)
                self.assertEqual([item["check"] for item in first["items"] if item["open"]],
                                 ["change_record", "identity_record"])
                journal = second["objection_journal"]
                self.assertEqual(journal["previous_run_id"], first_id)
                self.assertEqual([(item["check"], item["open"], item["evidence_ids"]) for item in journal["items"]],
                                 [("change_record", False, [change.id]), ("identity_record", True, [])])
                self.assertNotEqual(second["recommendation"]["decision"], "close")
                self.assertTrue(any(item.get("replaced_worker") for item in second["role_runtime"]["trace"]))
                key = load_key(identity_path)
                import_verifications(connection, key, [sign_record(key, anchor.id, identity)])

            result = subprocess.check_output(
                [sys.executable, "-m", "arachne", "--db", str(db), "triage", "--offline"],
                text=True, timeout=15,
            )
            third_id, = json.loads(result)["runs"]
            with database(db) as connection:
                journal = get_run(connection, third_id)["objection_journal"]
                self.assertEqual(journal["previous_run_id"], second_id)
                self.assertFalse(any(item["open"] for item in journal["items"]))
                self.assertEqual(journal["items"][1]["evidence_ids"], [identity.id])
            self.assertEqual(triage(db, now=now)["runs"], [])
