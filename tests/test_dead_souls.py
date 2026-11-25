from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from arachne.dead_souls import import_touches, overview, register_decoy
from arachne.store import database


def touch(identifier, decoy="archive", action="probe", timestamp="2026-01-01T12:00:01Z"):
    return {"id": identifier, "decoy_id": decoy, "timestamp": timestamp,
            "sensor": "test-sensor", "action": action}


class DeadSoulsTests(unittest.TestCase):
    def test_burst_preserves_the_rare_signal_and_replay_does_not_inflate_counts(self):
        records = [touch("first", action="write_attempt"),
                   *(touch(f"probe-{index}", "service") for index in range(2_000))]
        with TemporaryDirectory() as folder:
            path = Path(folder) / "test.sqlite3"
            with database(path) as connection:
                register_decoy(connection, "archive", "file")
                register_decoy(connection, "service", "service")
                self.assertEqual(import_touches(connection, records), {"inserted": 2001, "duplicates": 0})
            with database(path) as connection:
                shifted = {**records[0], "timestamp": "2026-01-01T14:00:01+02:00"}
                self.assertEqual(import_touches(connection, [shifted, *records[1:]]),
                                 {"inserted": 0, "duplicates": 2001})
                report = overview(connection)
                self.assertEqual(report["windows"], [{"minute": "2026-01-01T12:00:00+00:00",
                                                      "touches": 2001, "important": 1, "decoys": 2}])
                self.assertEqual([record["action"] for record in report["important"]], ["write_attempt"])

    def test_rejected_batch_leaves_no_raw_events_or_summary(self):
        with TemporaryDirectory() as folder, database(Path(folder) / "test.sqlite3") as connection:
            register_decoy(connection, "archive", "file")
            import_touches(connection, [touch("existing")])
            before = overview(connection)
            for invalid in (touch("existing", action="read"), touch("unknown", decoy="missing")):
                with self.assertRaises(ValueError):
                    import_touches(connection, [touch("pending", action="credential_use"), invalid])
                self.assertEqual(overview(connection), before)
            self.assertEqual(import_touches(connection, [touch("pending")])["inserted"], 1)
