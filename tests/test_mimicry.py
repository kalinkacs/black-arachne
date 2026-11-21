import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from arachne.agents import MIMIC_EXPECTATIONS
from arachne.evaluation import evaluate, parse_case
from arachne.mimicry import mimic

DATA = Path(__file__).resolve().parents[1] / "arachne" / "data" / "trial.jsonl"


def cases():
    return {row["id"]: row for row in map(json.loads, DATA.read_text().splitlines())}


class MimicryTests(unittest.TestCase):
    def run_case(self, name, **options):
        return mimic(*parse_case(cases()[name]), **options)

    def test_hidden_evidence_changes_verification_but_not_either_initial_view(self):
        positive = self.run_case("change-confirmed")
        negative = self.run_case("change-disputed")
        self.assertEqual(positive["forecast"], negative["forecast"])
        self.assertEqual(positive["mimicry"]["hypotheses"], negative["mimicry"]["hypotheses"])
        self.assertEqual(positive["blue"]["decision"], negative["blue"]["decision"])
        self.assertEqual(positive["assisted"]["decision"], "close")
        self.assertEqual(negative["assisted"]["decision"], "escalate")
        self.assertEqual(negative["mimicry"]["hypothesis_matches"], {"legitimate": False, "security": True})

    def test_operational_policy_preserves_authoritative_risk_seen_outside_selected_check(self):
        run = self.run_case("change-confirmed-and-identity-disputed")
        self.assertEqual(run["mimicry"]["assisted_observation"]["check"], "change_record")
        self.assertEqual(run["assisted"]["decision"], "close")
        self.assertEqual(run["recommendation"]["decision"], "escalate")
        self.assertTrue(any("identity_disputed" in ref for ref in run["recommendation"]["evidence_ids"]))

    def test_wrong_host_source_and_time_do_not_corroborate_change(self):
        for name in ("other-host-change", "untrusted-change", "previous-change"):
            with self.subTest(name=name):
                run = self.run_case(name)
                self.assertEqual(run["mimicry"]["assisted_observation"]["state"], "unknown")
                self.assertEqual(run["recommendation"]["decision"], "review")

    def test_prior_operator_outcome_can_change_check_without_erasing_new_evidence(self):
        experience = {"initial": "close", "verified": "escalate", "check": "identity_record",
                      "comparisons": [{"check": "identity_record", "decision": "escalate", "state": "disputes"}]}
        isolated = self.run_case("identity-dispute-with-declaration", history=[experience])
        self.assertEqual(isolated["forecast"]["check"], "change_record")
        run = self.run_case("identity-dispute-with-declaration", history=[experience] * 3)
        self.assertEqual(run["forecast"]["check"], "identity_record")
        self.assertEqual(run["assisted"]["decision"], "escalate")

    def test_equal_red_and_control_inputs_and_no_blind_evidence_in_model_requests(self):
        def provider(model, role, properties, instructions, payload):
            if role == "mimic_forecast":
                return {"prediction": "close", "check": "change_record", "hypothesis": "Claim looks plausible",
                        "disconfirmation": "Blue keeps the case open."}
            if role == "mimic_control":
                return {"check": "identity_record", "reason": "Check independent authorization."}
            return {"decision": "close", "legitimate": "Expected change.", "security": "Unverified account use.",
                    "reason": "Visible change claim.", "evidence_ids": ["E0"],
                    **{key: "supports" if key.startswith("legitimate_") else "disputes"
                       for key in MIMIC_EXPECTATIONS}}

        with patch("arachne.agents.request_result", side_effect=provider) as requests:
            run = self.run_case("change-disputed", model="mock-model")
        calls = requests.call_args_list
        self.assertEqual([call.args[1] for call in calls], ["mimic_forecast", "mimic_control", "mimic_blue"])
        self.assertEqual(calls[0].args[-1], calls[1].args[-1])
        self.assertEqual(set(calls[0].args[-1]), {"checks", "profile", "confirmed_history"})
        self.assertEqual(set(calls[2].args[-1]["events"][0]), {"handle", "kind", "is_anchor", "offset_seconds"})
        self.assertNotIn("change_disputed", str(calls[2].args[-1]))
        self.assertTrue(run["prediction_matched"])
        self.assertEqual(run["mimicry"]["checks_per_branch"], 1)
        self.assertEqual(run["recommendation"]["decision"], "escalate")

    def test_trial_counts_improvements_and_leaves_partially_supported_cases_open(self):
        trial = evaluate(io.StringIO(DATA.read_text()), analyze=mimic)
        self.assertEqual(trial["total"], 18)
        self.assertEqual(trial["metrics"]["assisted"], {"correct": 16, "missed_escalations": 2, "false_escalations": 0})
        self.assertEqual(trial["paired"]["red_only_correct"], 2)
        self.assertEqual(trial["paired"]["standard_only_correct"], 0)
