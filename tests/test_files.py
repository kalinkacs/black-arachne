import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from arachne.files import load_indicators, scan


class FileScannerTests(unittest.TestCase):
    def test_finds_indicator_without_following_links_or_reading_special_files(self):
        payload = b"harmless test marker"
        digest = hashlib.sha256(payload).hexdigest()
        indicators = load_indicators(io.StringIO(json.dumps({"sha256": digest, "label": "test-marker"})))
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "root"
            root.mkdir()
            external = Path(folder) / "external"
            external.mkdir()
            (external / "external-marker").write_bytes(payload)
            (root / "link-dir").symlink_to(external)
            (root / "link-file").symlink_to(external / "external-marker")
            (root / "indicator").write_bytes(payload)
            (root / "ordinary").write_bytes(b"other")
            (root / "large").write_bytes(b"z" * 80)
            os.mkfifo(root / "pipe")
            result = scan(root, indicators, max_bytes=40)
            self.assertEqual([match["path"] for match in result["matched"]], ["indicator"])
            self.assertEqual(result["counts"]["non_regular"], 2)
            self.assertEqual(result["counts"]["too_large"], 1)
            self.assertEqual(result["counts"]["scanned"], 2)

    def test_limit_and_invalid_indicator_file_are_explicit(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            load_indicators(io.StringIO('{"sha256":"invalid","label":"test"}'))
        with tempfile.TemporaryDirectory() as folder:
            for name in ("first", "second"):
                (Path(folder) / name).write_text("sample")
            result = scan(folder, {}, max_files=1)
            self.assertTrue(result["limit_reached"])
            self.assertEqual(result["counts"]["scanned"], 1)
