from io import StringIO
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from arachne.measurement import PROFILE_FIELDS
from arachne.role_runtime import RoleFailure, RoleProcess
from arachne.signal_experiment import model_proposals, run_signal_experiment


DATA = Path(__file__).resolve().parents[1] / "arachne" / "data"
DISCOVERY = DATA / "signal-discovery.jsonl"
HOLDOUT = DATA / "signal-holdout.jsonl"


class SignalExperimentTests(unittest.TestCase):
    def test_role_exchange_builds_a_measurement_unseen_in_calibration(self):
        discovery = DISCOVERY.read_text(encoding="utf-8")
        self.assertNotIn("identity_change_session", discovery)
        report = run_signal_experiment(StringIO(discovery), StringIO(HOLDOUT.read_text(encoding="utf-8")))
        witness = next(example for example in report["examples"]
                       if example["close_case"] == "lab-operator-on-approved-change-close")
        self.assertEqual(witness["selected"]["role_switch"], "identity_change_session")
        self.assertEqual(witness["results"]["role_switch"], "distinguished")
        self.assertEqual(witness["results"]["single_agent"], "unresolved")
        self.assertEqual(report["readings_per_pair_per_variant"], 1)
        self.assertEqual(report["holdout_pairs"], 8)
        self.assertEqual(report["holdout"]["role_switch"], {"distinguished": 4, "reversed": 1, "unresolved": 3})
        self.assertEqual(report["holdout"]["single_agent"]["distinguished"], 5)
        self.assertTrue(all(sum(metrics.values()) == report["holdout_pairs"] for metrics in report["holdout"].values()))

    def test_external_planner_receives_neither_case_metadata_nor_measurements(self):
        calls = []

        def provider(model, role, schema, instructions, payload):
            self.assertEqual(model, "test-model")
            self.assertEqual(role, "evidence_proposal")
            self.assertEqual(set(schema), {"primary", "secondary"})
            self.assertLessEqual(set(payload), {"profile", "perspective", "previous_proposal", "borrowed_proposal"})
            self.assertEqual(set(payload["profile"]), PROFILE_FIELDS)
            self.assertTrue(all(type(value) is bool for value in payload["profile"].values()))
            calls.append(payload)
            default = "change" if payload["perspective"] == "legitimate" else "identity"
            return {"primary": payload.get("borrowed_proposal", default), "secondary": None}

        data = HOLDOUT.read_text(encoding="utf-8")
        changed = []
        for line in data.splitlines():
            row = json.loads(line)
            row["signals"] = {key: "conflict" for key in row["signals"]}
            changed.append(json.dumps(row))
        with patch("arachne.signal_experiment.request_result", side_effect=provider):
            before = run_signal_experiment(StringIO(DISCOVERY.read_text(encoding="utf-8")), StringIO(data), "test-model")
            first_calls = list(calls)
            calls.clear()
            after = run_signal_experiment(StringIO(DISCOVERY.read_text(encoding="utf-8")),
                                          StringIO("\n".join(changed)), "test-model")
        self.assertEqual(first_calls, calls)
        self.assertTrue(any("borrowed_proposal" in call for call in calls))
        self.assertEqual(before["plans_sha256_before_scoring"], after["plans_sha256_before_scoring"])
        self.assertEqual(before["plans"], after["plans"])

    def test_model_cannot_replace_an_assigned_premise_after_switching(self):
        def ignores_borrowed_premise(*args):
            payload = args[-1]
            primary = "change" if payload["perspective"] == "legitimate" else "identity"
            if "borrowed_proposal" in payload:
                primary = payload["previous_proposal"]
            return {"primary": primary, "secondary": None}

        with patch("arachne.signal_experiment.request_result", side_effect=ignores_borrowed_premise):
            with self.assertRaisesRegex(ValueError, "assigned perspective"):
                model_proposals(dict.fromkeys(PROFILE_FIELDS, False), "test-model")

    def test_worker_rejects_unfrozen_or_repeated_proposals(self):
        with RoleProcess("red") as red:
            with self.assertRaises(RoleFailure):
                red.call("signal_reframe", {"peer": {"primary": "identity", "secondary": None}})
        with RoleProcess("blue") as blue:
            blue.call("signal_initial", {"profile": dict.fromkeys(PROFILE_FIELDS, False)})
            blue.call("signal_reframe", {"peer": {"primary": "privilege", "secondary": None}})
            with self.assertRaises(RoleFailure):
                blue.call("signal_reframe", {"peer": {"primary": "change", "secondary": None}})
