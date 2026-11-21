import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from arachne.integrity import baseline_catalog, establish, observe, recent_findings, scheduled_checks
from arachne.store import database

LIMITS = {"max_files": 20, "max_bytes": 1000, "total_bytes": 10_000}


class IntegrityTests(unittest.TestCase):
    def test_real_disk_changes_are_recorded_once_and_restoration_is_visible(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "watch"
            root.mkdir()
            db = Path(directory) / "observer.sqlite3"
            (root / "content").write_text("old")
            (root / "permissions").write_text("unchanged")
            (root / "removed").write_text("save this baseline")
            (root / "subdir").mkdir()
            (root / "subdir" / "type").write_text("baseline")

            base = establish(db, root, "Local files", LIMITS)
            self.assertEqual(base["files"], 4)
            (root / "content").write_text("new")
            (root / "added").write_text("additional")
            os.chmod(root / "permissions", 0o400)
            (root / "removed").unlink()
            (root / "subdir" / "type").unlink()
            (root / "subdir" / "type").symlink_to(root, target_is_directory=True)

            first = scheduled_checks(db)
            self.assertEqual(first, [{"baseline_id": base["id"], "complete": True, "findings": 5, "reason": None}])
            self.assertEqual(observe(db, base["id"])["findings"], [])
            with database(db) as connection:
                findings = {change["path"]: change for change in recent_findings(connection)}
                self.assertTrue(baseline_catalog(connection)[0]["complete"])
            self.assertEqual({path: item["change"] for path, item in findings.items()},
                             {"added": "added", "content": "content", "permissions": "permissions",
                              "removed": "removed", "subdir/type": "type"})
            self.assertEqual(findings["content"]["observed"]["sha256"], hashlib.sha256(b"new").hexdigest())
            self.assertIsNone(findings["subdir/type"]["observed"]["sha256"])

            (root / "content").write_text("old")
            restored = observe(db, base["id"])["findings"]
            self.assertEqual([(item["path"], item["change"]) for item in restored], [("content", "restored")])

    def test_incomplete_scan_does_not_guess_deletions_or_replace_last_complete_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "watch"
            root.mkdir()
            db = Path(directory) / "observer.sqlite3"
            (root / "first").write_text("old")
            base = establish(db, root, "Small snapshot", {**LIMITS, "max_files": 1})
            (root / "first").write_text("changed")
            (root / "last").touch()
            blocked = observe(db, base["id"])
            self.assertEqual(blocked["findings"], [])
            self.assertFalse(blocked["complete"])
            with database(db) as connection:
                self.assertEqual(recent_findings(connection), [])
                self.assertFalse(baseline_catalog(connection)[0]["complete"])
            (root / "last").unlink()
            changes = observe(db, base["id"])["findings"]
            self.assertEqual([(item["path"], item["change"]) for item in changes], [("first", "content")])

    def test_changed_or_unavailable_root_reports_health_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "watch"
            root.mkdir()
            db = Path(directory) / "observer.sqlite3"
            (root / "first").write_text("a")
            base = establish(db, root, "Bound root", LIMITS)
            root.rename(Path(directory) / "another")
            self.assertFalse(observe(db, base["id"])["complete"])
            root.mkdir()
            (root / "other").write_text("b")
            replaced = observe(db, base["id"])
            self.assertIn("no longer matches", replaced["reason"])
            self.assertEqual(replaced["findings"], [])
