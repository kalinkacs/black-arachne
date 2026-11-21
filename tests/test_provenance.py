from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch

from arachne.operations import operational_review, triage
from arachne.provenance import authenticate, create_key, load_key, sign_record
from arachne.store import database, episode, get_run, import_verifications, ingest
from test_offline import sample


class ProvenanceTests(unittest.TestCase):
    def test_tamper_scope_and_key_file_permissions(self):
        anchor, events = sample("change-confirmed")
        verification = next(item for item in events if item.kind == "change_verified")
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "changes.key.json"
            summary = create_key(key_path, "change-key", "change-management", anchor.host)
            self.assertNotIn("secret", summary)
            self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                create_key(key_path, "new-key", "change-management", anchor.host)
            key = load_key(key_path)
            envelope = sign_record(key, anchor.id, verification)
            self.assertEqual(authenticate(key, envelope), (verification, anchor.id))
            with self.assertRaisesRegex(ValueError, "authentication failed"):
                authenticate(key, {**envelope, "anchor_id": "another-login"})
            with self.assertRaisesRegex(ValueError, "scope"):
                sign_record(key, anchor.id, replace(verification, host="other"))
            os.chmod(key_path, 0o644)
            with self.assertRaisesRegex(ValueError, "private"):
                load_key(key_path)

    def test_unsigned_claim_does_not_close_and_signed_claim_stays_bound_to_one_login(self):
        anchor, events = sample("change-confirmed")
        verification = next(item for item in events if item.kind == "change_verified")
        other = replace(anchor, id="second-overlapping-login")
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "changes.key.json"
            create_key(key_path, "official-changes", "change-management", anchor.host)
            key = load_key(key_path)
            envelope = sign_record(key, anchor.id, verification)
            with database(Path(directory) / "records.sqlite3") as connection:
                ingest(connection, [*events, other])
                unsigned = operational_review(connection, anchor, events, None)
                self.assertEqual(unsigned["recommendation"]["decision"], "review")
                self.assertEqual(unsigned["provenance"]["unverified"], [verification.id])
                self.assertEqual(import_verifications(connection, key, [envelope]), {"verified": 1})
                self.assertEqual(import_verifications(connection, key, [envelope]), {"verified": 0})
                signed = operational_review(connection, anchor, episode(connection, anchor.host, anchor.id)[1], None)
                self.assertEqual(signed["recommendation"]["decision"], "close")
                self.assertEqual(signed["provenance"]["verified"], {verification.id: "official-changes"})
                overlapping = operational_review(connection, other, episode(connection, other.host, other.id)[1], None)
                self.assertEqual(overlapping["recommendation"]["decision"], "review")
                separately_signed = sign_record(key, other.id, verification)
                with self.assertRaisesRegex(ValueError, "Conflicting"):
                    import_verifications(connection, key, [separately_signed])

    def test_mixed_import_rolls_back_if_binding_fails(self):
        anchor, events = sample("change-confirmed")
        verification = next(item for item in events if item.kind == "change_verified")
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "changes.key.json"
            create_key(key_path, "change-key", "change-management", anchor.host)
            key = load_key(key_path)
            good = sign_record(key, anchor.id, verification)
            wrong_account = sign_record(key, anchor.id, replace(verification, id="wrong-account", actor="other"))
            db = Path(directory) / "records.sqlite3"
            with database(db) as connection:
                ingest(connection, [anchor])
            with self.assertRaisesRegex(ValueError, "host and account"):
                with database(db) as connection:
                    import_verifications(connection, key, [good, wrong_account])
            with database(db) as connection:
                self.assertEqual(connection.execute("SELECT count(*) FROM verified_evidence").fetchone()[0], 0)
                self.assertEqual(connection.execute("SELECT count(*) FROM events").fetchone()[0], 1)


    def test_late_authenticated_record_creates_a_new_snapshot_once(self):
        anchor, events = sample("change-confirmed")
        native = replace(anchor, source="systemd-journal")
        verification = next(item for item in events if item.kind == "change_verified")
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "changes.key.json"
            create_key(key_path, "change-key", verification.source, native.host)
            key = load_key(key_path)
            db = Path(directory) / "records.sqlite3"
            with database(db) as connection:
                ingest(connection, [native, *(event for event in events if event.id != native.id)])
            now = datetime(2026, 1, 1, 13, tzinfo=timezone.utc)
            prior, = triage(db, now=now)["runs"]
            with database(db) as connection:
                import_verifications(connection, key, [sign_record(key, native.id, verification)])
            current, = triage(db, now=now)["runs"]
            self.assertEqual(triage(db, now=now)["investigated"], 0)
            with database(db) as connection:
                self.assertEqual(get_run(connection, prior)["recommendation"]["decision"], "review")
                self.assertEqual(get_run(connection, current)["recommendation"]["decision"], "close")


    def test_receipt_inserted_during_a_review_is_observed_by_the_next_run(self):
        anchor, events = sample("change-confirmed")
        native = replace(anchor, source="systemd-journal")
        verification = next(item for item in events if item.kind == "change_verified")
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            key_path = directory / "changes.key.json"
            create_key(key_path, "change-key", verification.source, native.host)
            key = load_key(key_path)
            db = directory / "records.sqlite3"
            with database(db) as connection:
                ingest(connection, [native, *(event for event in events if event.id != native.id)])
            envelope = sign_record(key, native.id, verification)

            def import_while_reviewing(connection, live_anchor, observations, model):
                with database(db) as writer:
                    import_verifications(writer, key, [envelope])
                return operational_review(connection, live_anchor, observations, model)

            now = datetime(2026, 1, 1, 13, tzinfo=timezone.utc)
            with patch("arachne.operations.operational_review", import_while_reviewing):
                original, = triage(db, now=now)["runs"]
            updated, = triage(db, now=now)["runs"]
            with database(db) as connection:
                self.assertEqual(get_run(connection, original)["recommendation"]["decision"], "review")
                self.assertEqual(get_run(connection, updated)["recommendation"]["decision"], "close")
