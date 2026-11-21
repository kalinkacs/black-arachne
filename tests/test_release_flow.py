from datetime import datetime
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_offline import sample


class ReleaseFlowTests(unittest.TestCase):
    def test_offline_cli_import_triage_monitor_and_authenticated_recheck(self):
        anchor, records = sample("change-confirmed")
        verification = next(item for item in records if item.kind == "change_verified")
        context = next(item for item in records if item.kind == "deployment")
        activity = next(item for item in records if item.kind == "privileged_activity")
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            command = [sys.executable, "-m", "arachne", "--db", str(root / "evidence.sqlite3")]

            def run(*args, code=0, data=None, parse=True):
                result = subprocess.run([*command, *map(str, args)], text=True, input=data, capture_output=True)
                self.assertEqual(result.returncode, code, result.stderr or result.stdout)
                return json.loads(result.stdout) if parse else result.stdout

            def jd(*rows):
                return "\n".join(json.dumps(row) for row in rows)

            run("import-journal", data=jd(
                {"_HOSTNAME": anchor.host, "_EXE": "/usr/sbin/sshd", "SYSLOG_IDENTIFIER": "sshd",
                 "MESSAGE": f"Accepted publickey for {anchor.actor} from 192.0.2.1 port 1234 ssh2",
                 "__REALTIME_TIMESTAMP": str(int(datetime.fromisoformat(anchor.timestamp).timestamp() * 1_000_000)),
                 "__CURSOR": "release-ssh-cursor"},
                {"_HOSTNAME": anchor.host, "_EXE": "/usr/bin/sudo", "SYSLOG_IDENTIFIER": "sudo",
                 "MESSAGE": f"{anchor.actor} : TTY=pts/0 ; COMMAND=/usr/bin/true",
                 "__REALTIME_TIMESTAMP": str(int(datetime.fromisoformat(activity.timestamp).timestamp() * 1_000_000)),
                 "__CURSOR": "release-sudo-cursor"},
            ))
            login, = run("anchors")
            run("import-events", data=jd(context.__dict__, verification.__dict__))
            draft = run("investigate", login["host"], login["id"], "--offline")
            self.assertEqual(draft["recommendation"]["decision"], "review")
            self.assertEqual(draft["provenance"]["unverified"], [verification.id])
            self.assertEqual(run("triage", "--offline")["investigated"], 1)

            key = root / "changes.key.json"
            run("create-verifier", key, "--id", "release-test", "--source", verification.source, "--host", anchor.host)
            plain = root / "record.jsonl"
            plain.write_text(jd(verification.__dict__))
            signed = root / "signed.jsonl"
            signed.write_text(run("sign-verifications", plain, "--key", key, "--anchor", login["id"], parse=False))
            self.assertEqual(run("import-verifications", signed, "--key", key)["verified"], 1)
            self.assertEqual(run("triage", "--offline")["investigated"], 1)
            self.assertEqual(run("triage", "--offline")["investigated"], 0)

            monitored = root / "directory"
            monitored.mkdir()
            marker = monitored / "configuration"
            marker.write_text("original contents")
            baseline = run("integrity-baseline", monitored, "--name", "Test data")
            marker.write_text("changed contents")
            self.assertEqual(run("integrity-check", baseline["id"], code=2)["findings"][0]["change"], "content")
            self.assertEqual(run("integrity-check", baseline["id"])["findings"], [])
            self.assertEqual(run("status")["authenticated_records"], 1)
