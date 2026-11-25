import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from arachne.quarantine import isolate, restore


class QuarantineTests(unittest.TestCase):
    def test_quarantine_preserves_file_and_restores_without_overwriting(self):
        payload = b"harmless quarantine control"
        digest = hashlib.sha256(payload).hexdigest()
        with TemporaryDirectory() as folder:
            root = Path(folder)
            vault = root / "vault"
            vault.mkdir(mode=0o700)
            file = root / "sample"
            file.write_bytes(payload)
            file.chmod(0o640)
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                isolate(vault, file, "0" * 64, "control")
            self.assertEqual(file.read_bytes(), payload)
            original_inode = file.stat().st_ino
            receipt = isolate(vault, file, digest, "control")
            self.assertFalse(file.exists())
            file.write_bytes(b"operator file")
            with self.assertRaises(FileExistsError):
                restore(vault, receipt["id"])
            self.assertEqual(file.read_bytes(), b"operator file")
            file.unlink()
            self.assertEqual(restore(vault, receipt["id"])["state"], "restored")
            self.assertEqual(file.read_bytes(), payload)
            self.assertEqual(file.stat().st_ino, original_inode)
            self.assertEqual(file.stat().st_mode & 0o777, 0o640)
            self.assertEqual(restore(vault, receipt["id"])["state"], "at_original_path")
