from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from arachne.agents import model_review
from arachne.lab import scenarios
from arachne.operations import collect, triage
from arachne.reasoning import investigate, role_investigation
from arachne.store import confirmed_history, confirm_outcome, database, ingest, save_run
from test_arachne import journal


class RolesTests(unittest.TestCase):
    def test_role_visibility_equal_checks_and_policy(self):
        _, _, events = next(scenarios())
        anchor = events[1]
        calls = []

        def pretend_model(role, model, event, visible, memory, check=None):
            calls.append((role, check, [event.kind for event in visible]))
            cited = {"evidence_ids": [anchor.id], "engine": model}
            if role == "red_forecast":
                return {**cited, "check": "change_record", "prediction": "close", "hypothesis": "Check the declaration."}
            if role == "independent_check":
                return {**cited, "check": "conflicting_activity", "reason": "Review timing."}
            return {**cited, "decision": "close", "legitimate": "Normal deploy.",
                    "security": "Unverified ownership.", "reason": "Consider a declaration."}

        with patch("arachne.reasoning.model_review", pretend_model):
            run = role_investigation(anchor, events, "fake")
            self.assertTrue(run["prediction_matched"])
            self.assertEqual(run["recommendation"]["decision"], "close")
            self.assertEqual([role for role, _, _ in calls],
                             ["red_forecast", "blue_initial", "independent_check", "blue_reassessment", "blue_reassessment"])
            self.assertTrue(all("change_verified" not in kinds for _, _, kinds in calls[:-1]))
            self.assertIn("change_verified", calls[-1][2])
            run = role_investigation(anchor, events[:-1], "fake")
            self.assertEqual(run["assisted"]["decision"], "close")
            self.assertEqual(run["recommendation"]["decision"], "review")

    def test_model_schema_checks_allow_list_and_cited_evidence(self):
        _, _, events = next(scenarios())
        anchor = events[1]
        fake = {"check": "unknown", "prediction": "close", "hypothesis": "Review.", "evidence_ids": ["E1"]}
        with patch("arachne.agents.request_result", return_value=fake) as request:
            with self.assertRaisesRegex(ValueError, "invalid check"):
                model_review("red_forecast", "fake", anchor, events[:-1])
            fake["check"] = "change_record"
            fake["evidence_ids"] = ["unknown"]
            with self.assertRaisesRegex(ValueError, "evidence validation"):
                model_review("red_forecast", "fake", anchor, events[:-1])
            data = request.call_args.args[-1]
            self.assertNotIn(anchor.host, json.dumps(data))
            self.assertNotIn(anchor.actor, json.dumps(data))

    def test_confirmed_memory_skips_synthetic_same_episode_and_unrelated_host(self):
        _, _, events = next(scenarios())
        anchor = events[1]
        with tempfile.TemporaryDirectory() as folder:
            with database(Path(folder) / "test.sqlite3") as connection:
                report = investigate(anchor, events)
                synthetic = save_run(connection, {**report, "scenario": "fixture"})
                with self.assertRaisesRegex(ValueError, "Synthetic"):
                    confirm_outcome(connection, synthetic["id"], "review", "No change ticket")
                actual = save_run(connection, report)
                confirm_outcome(connection, actual["id"], "review", "Text stays local")
                self.assertEqual(confirmed_history(connection, anchor, events), [])
                later = [replace(event, id=event.id + "-new") for event in events]
                self.assertEqual(confirmed_history(connection, later[1], later),
                                 [{"initial": "close", "verified": "review", "check": "change_record"}])
                other = [replace(event, host="other") for event in later]
                self.assertEqual(confirmed_history(connection, other[1], other), [])


class OperationsTests(unittest.TestCase):
    def test_collect_checkpoint_and_failed_import_rollback(self):
        accepted = journal("Accepted publickey for operator from 192.0.2.1 port 1 ssh2", "sshd", "a", 0)
        activity = journal("operator : TTY=pts/0 ; COMMAND=/usr/bin/true", "sudo", "b", 1)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "test.sqlite3"
            with database(path) as connection:
                self.assertEqual(collect(connection, "today", lambda since, cursor: [accepted])["inserted"], 1)

            def failing(since, cursor):
                self.assertEqual(cursor, "a")
                yield activity
                raise ValueError("read error")

            with self.assertRaisesRegex(ValueError, "read error"):
                with database(path) as connection:
                    collect(connection, "today", failing)

            with database(path) as connection:
                self.assertEqual(connection.execute("SELECT count(*) FROM events").fetchone()[0], 1)
                self.assertEqual(connection.execute("SELECT cursor FROM collector_state").fetchone()[0], "a")

    def test_triage_waits_for_evidence_and_does_not_duplicate(self):
        _, _, events = next(scenarios())
        anchor = events[1]
        live = [replace(event, source="systemd-journal") for event in events if event.kind == "ssh_login"]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "test.sqlite3"
            with database(path) as connection:
                ingest(connection, live)
            self.assertEqual(triage(path, now=datetime.fromisoformat(anchor.timestamp))["investigated"], 0)
            ready = datetime(2026, 1, 1, 13, tzinfo=timezone.utc)
            self.assertEqual(triage(path, now=ready)["investigated"], 1)
            self.assertEqual(triage(path, now=ready)["investigated"], 0)


class EvaluationTests(unittest.TestCase):
    def test_labels_stay_outside_investigation_and_paired_regressions_are_counted(self):
        import io

        from arachne.evaluation import evaluate
        from arachne.events import records

        def fixture():
            for name, decision, events in scenarios():
                anchor = next(event for event in events if event.kind == "ssh_login")
                yield json.dumps({"id": name, "family": "closed-group", "expected": decision,
                                  "anchor_id": anchor.id, "events": records(events)})

        original = "\n".join(fixture())
        first = evaluate(io.StringIO(original))
        tampered = evaluate(io.StringIO(original.replace('"expected": "escalate"', '"expected": "review"')))
        self.assertEqual(first["total"], 5)
        self.assertEqual(first["paired"], {"red_only_correct": 1, "standard_only_correct": 1})
        self.assertNotEqual(first["metrics"], tampered["metrics"])
