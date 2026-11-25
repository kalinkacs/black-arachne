from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from arachne.dead_souls import import_touches, register_decoy
from arachne.operations import triage
from arachne.provenance import create_key, load_key, sign_record
from arachne.store import database, get_run, import_verifications, ingest
from test_offline import bind_session, sample


class DecoyCaseTests(unittest.TestCase):
    def test_signed_touch_and_gap_reach_only_their_native_session_after_restart(self):
        anchor, events = bind_session(*sample("change-confirmed"))
        anchor = replace(anchor, source="systemd-journal")
        neighbour = replace(anchor, id="parallel-login", session_key="2" * 64)
        change = next(event for event in events if event.kind == "change_verified")
        touch = replace(change, id="touch-one", kind="decoy_touch", source="decoy-monitor",
                        decoy_id="archive", decoy_action="write_attempt")
        gap = replace(touch, id="gap-one", kind="decoy_sensor_gap", decoy_id=None, decoy_action=None)
        recovered = replace(gap, id="recovered-one", kind="decoy_sensor_recovered",
                            timestamp=(datetime.fromisoformat(gap.timestamp) + timedelta(seconds=10)).isoformat(timespec="microseconds"))
        raw_touch = {"id": touch.id, "decoy_id": "archive", "sensor": "decoy-a",
                     "timestamp": touch.timestamp, "action": "write_attempt"}
        now = datetime(2026, 1, 1, 13, tzinfo=timezone.utc)
        with TemporaryDirectory() as folder:
            db = Path(folder) / "cases.sqlite3"
            key_file = Path(folder) / "decoy.key"
            change_file = Path(folder) / "change.key"
            create_key(key_file, "decoy-a", "decoy-monitor", anchor.host)
            create_key(change_file, "change-a", change.source, anchor.host)
            key, changes = load_key(key_file), load_key(change_file)
            with database(db) as connection:
                ingest(connection, [anchor, neighbour, *(event for event in events if event.id != anchor.id)])
                import_verifications(connection, changes, [sign_record(changes, anchor.id, change)])
                register_decoy(connection, "archive", "file")
                import_touches(connection, [raw_touch])

            original = triage(db, now=now)["runs"]
            with database(db) as connection:
                by_anchor = {report["anchor_id"]: report for run in original if (report := get_run(connection, run))}
                self.assertNotIn("decoy_evidence", by_anchor[anchor.id])
                self.assertEqual(by_anchor[anchor.id]["recommendation"]["decision"], "close")
                self.assertNotIn("decoy_evidence", by_anchor[neighbour.id])
                with self.assertRaisesRegex(ValueError, "login session"):
                    import_verifications(connection, key, [sign_record(key, neighbour.id, touch)])
                with self.assertRaisesRegex(ValueError, "does not match the imported sensor"):
                    altered = replace(touch, decoy_action="read")
                    import_verifications(connection, key, [sign_record(key, anchor.id, altered)])
                missing_session = replace(touch, session_key=None)
                with self.assertRaisesRegex(ValueError, "exact machine and session"):
                    import_verifications(connection, key, [sign_record(key, anchor.id, missing_session)])
                receipts = [sign_record(key, anchor.id, event) for event in (touch, gap)]
                self.assertEqual(import_verifications(connection, key, receipts)["verified"], 2)
                self.assertEqual(import_verifications(connection, key, receipts)["verified"], 0)

            revised, = triage(db, now=now)["runs"]
            with database(db) as connection:
                report = get_run(connection, revised)
                self.assertEqual(report["anchor_id"], anchor.id)
                self.assertEqual(report["recommendation"]["decision"], "review")
                self.assertEqual(report["decoy_evidence"]["touch_count"], 1)
                self.assertEqual(report["decoy_evidence"]["open_gaps"][0]["event_id"], gap.id)
                aramis = next(item for item in report["dumas"] if item["specialist"] == "Aramis")
                self.assertEqual(aramis["decoy_evidence_ids"], [touch.id, gap.id])
            self.assertEqual(triage(db, now=now)["runs"], [])
            with database(db) as connection:
                self.assertEqual(get_run(connection, revised)["decoy_evidence"]["open_gaps"][0]["event_id"], gap.id)
                import_verifications(connection, key, [sign_record(key, anchor.id, recovered)])
            latest, = triage(db, now=now)["runs"]
            with database(db) as connection:
                report = get_run(connection, latest)
                self.assertEqual(report["decoy_evidence"]["open_gaps"], [])
                self.assertEqual(report["decoy_evidence"]["touch_count"], 1)
                self.assertEqual(report["recommendation"]["decision"], "review")
