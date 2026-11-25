from dataclasses import replace
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from arachne.audit_files import import_audit_files
from arachne.dead_souls import case_evidence, register_decoy
from arachne.events import journal_session
from arachne.provenance import VerificationKey
from arachne.store import database, ingest
from test_offline import sample


class AuditFileTests(unittest.TestCase):
    def test_concurrent_logins_remain_separate_and_burst_counts_distinct_files(self):
        machine, boot = "a" * 32, "b" * 32
        anchor, _ = sample("change-confirmed")
        def login(number):
            _, session = journal_session({"_MACHINE_ID": machine, "_BOOT_ID": boot, "_AUDIT_SESSION": str(number)})
            return replace(anchor, id=f"login-{number}", source="systemd-journal",
                           machine_id=machine, session_key=session)

        first, second = login(25), login(26)
        at = int(datetime.fromisoformat(first.timestamp).astimezone(timezone.utc).timestamp()) + 2

        def audit(number, session, path, flags):
            return (
                f'type=SYSCALL msg=audit({at}.010:{number}): arch=c000003e syscall=257 '
                f'success=yes a2={flags} pid=2000 ses={session} key="arachne"\n'
                f'type=PATH msg=audit({at}.010:{number}): item=0 name="{path}" nametype=NORMAL\n'
            )

        rows = (audit(1, 25, "/tmp/decoy", "1") + audit(2, 26, "/tmp/elsewhere", "0")
                + audit(3, 25, "/tmp/other", "1") + audit(4, 25, "/tmp/other", "2")
                + audit(5, 4294967295, "/tmp/decoy", "0"))
        key = VerificationKey("sensor-a", "decoy-monitor", anchor.host, b"a" * 32)
        with TemporaryDirectory() as folder, database(Path(folder) / "cases.sqlite3") as db:
            ingest(db, [first, second])
            register_decoy(db, "decoy", "file")
            result = import_audit_files(db, StringIO(rows), key, machine, boot, "arachne", {"/tmp/decoy": "decoy"}, 2)
            self.assertEqual((result["inserted"], result["new_verified"], result["unattributed"]), (2, 1, 1))
            self.assertEqual(result["write_open_bursts"][0]["distinct_write_opens"], 2)
            self.assertEqual(case_evidence(db, first.id)["important_count"], 1)
            self.assertEqual(case_evidence(db, second.id)["touch_count"], 0)
