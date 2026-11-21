from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from arachne.evaluation import parse_case
from arachne.learning import check_model, decision_model, hypothesis_model
from arachne.mimicry import mimic
from arachne.operations import triage
from arachne.store import confirm_outcome, confirmed_history, database, ingest, save_run, status_snapshot, verify_audit

DATA = Path(__file__).resolve().parents[1] / "arachne" / "data" / "trial.jsonl"


def sample(name):
    row = next(item for item in map(json.loads, DATA.read_text().splitlines()) if item["id"] == name)
    return parse_case(row)


class LocalModelTests(unittest.TestCase):
    def test_probabilities_move_and_checks_use_distinct_episode_votes(self):
        history = [{"initial": "review"}] * 4
        decision, distribution = decision_model("close", history)
        self.assertEqual(decision, "review")
        self.assertAlmostEqual(sum(distribution.values()), 1, delta=0.002)
        comparison = {"check": "identity_record", "decision": "escalate", "state": "disputes"}
        example = {"initial": "review", "verified": "escalate", "comparisons": [comparison, comparison]}
        choice, evidence = check_model("change_record", ("change_record", "identity_record"), [example, example])
        self.assertEqual(choice, "change_record")
        self.assertEqual(evidence["identity_record"]["observations"], 2)
        choice, _ = check_model("change_record", ("change_record", "identity_record"), [example] * 3)
        self.assertEqual(choice, "identity_record")

    def test_blue_learns_only_repeated_operator_verified_expectations(self):
        expectation = lambda: {"security": {"expectations": {"identity_record": "unknown"}},
                               "legitimate": {"expectations": {"identity_record": "supports"}}}
        red_flag = {"verified": "escalate", "comparisons": [{"check": "identity_record", "state": "disputes"}]}
        self.assertEqual(hypothesis_model(expectation(), [red_flag] * 2)["security"]["expectations"]["identity_record"], "unknown")
        calibrated = hypothesis_model(expectation(), [red_flag] * 3)
        self.assertEqual(calibrated["security"]["expectations"]["identity_record"], "disputes")
        self.assertEqual(calibrated["legitimate"]["expectations"]["identity_record"], "supports")

    def test_memory_only_records_once_per_anchor_and_uses_newer_snapshot(self):
        anchor, events = sample("change-confirmed")
        with tempfile.TemporaryDirectory() as folder:
            with database(Path(folder) / "case.sqlite3") as connection:
                report = mimic(anchor, events)
                first = save_run(connection, report)
                confirm_outcome(connection, first["id"], "review", "Insufficient records")
                second = save_run(connection, report)
                confirm_outcome(connection, second["id"], "close", "Verified by operator")
                new_anchor = replace(anchor, id="different")
                new_events = [new_anchor if event.id == anchor.id else event for event in events]
                history = confirmed_history(connection, new_anchor, new_events)
                self.assertEqual(len(history), 1)
                self.assertEqual(history[0]["verified"], "close")
                self.assertEqual(history[0]["comparisons"][0]["state"], "supports")


class OperationalFlowTests(unittest.TestCase):
    def test_audit_detects_modified_decision_and_deleted_tail(self):
        anchor, events = sample("identity-disputed")
        with tempfile.TemporaryDirectory() as folder:
            with database(Path(folder) / "case.sqlite3") as connection:
                report = save_run(connection, mimic(anchor, events))
                confirm_outcome(connection, report["id"], "escalate", "Account issue independently confirmed")
                audit = verify_audit(connection)
                self.assertTrue(audit["valid"])
                self.assertEqual(audit["checked"], 1)
                self.assertEqual(status_snapshot(connection)["confirmed"], 1)
                connection.execute("UPDATE outcomes SET note='altered' WHERE run_id=?", (report["id"],))
                self.assertFalse(verify_audit(connection)["valid"])
                connection.execute("DELETE FROM decision_audit")
                self.assertFalse(verify_audit(connection)["valid"])

    def test_oversized_window_is_visible_and_does_not_stop_other_hosts(self):
        anchor, _ = sample("change-confirmed")
        live = replace(anchor, source="systemd-journal")
        other = replace(live, host="separate-host", id="other-ssh")
        many = [replace(live, id=f"noise-{seq}", kind="privileged_activity") for seq in range(1000)]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "case.sqlite3"
            with database(path) as connection:
                ingest(connection, [live, other, *many])
            now = datetime(2026, 1, 1, 13, tzinfo=timezone.utc)
            result = triage(path, now=now)
            self.assertEqual(result["excluded"], [live.id])
            self.assertEqual(result["investigated"], 1)
            self.assertEqual(triage(path, now=now)["excluded"], [])
            with database(path) as connection:
                self.assertEqual(status_snapshot(connection)["excluded_anchors"], 1)
