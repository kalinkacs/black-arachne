from dataclasses import replace
from functools import partial
import io
import json
import unittest
from unittest.mock import patch

from arachne.evaluation import evaluate
from arachne.mimicry import mimic
from arachne.role_runtime import RoleFailure, RoleProcess
from test_offline import DATA, sample


class CrossExaminationTests(unittest.TestCase):
    def test_switches_commit_before_verification_and_are_blind_to_its_content(self):
        anchor, events = sample("change-confirmed-and-identity-disputed")
        alternatives = [replace(event, kind="identity_verified") if event.kind == "identity_disputed" else event
                        for event in events]
        packets = []

        class ObservedWorker(RoleProcess):
            def call(self, phase, payload):
                packets.append((self.role, phase, payload))
                return super().call(phase, payload)

        with patch("arachne.mimicry.RoleProcess", ObservedWorker):
            first = mimic(anchor, events, cross_examine=True)["cross_examination"]
            first_packets, packets = packets, []
            second = mimic(anchor, alternatives, cross_examine=True)["cross_examination"]

        before_reveal = [phase for _, phase, _ in first_packets[:7]]
        self.assertEqual(before_reveal, ["forecast", "select", "assess", "commit", "commit", "switch", "switch"])
        self.assertEqual(first_packets[:7], packets[:7])
        self.assertEqual(first["with_swap"]["commitments"], second["with_swap"]["commitments"])
        self.assertEqual(first["with_swap"]["decision"], "escalate")
        self.assertEqual(second["with_swap"]["decision"], "review")

    def test_diagnostic_variant_leaves_the_operational_recommendation_alone(self):
        anchor, events = sample("change-confirmed-and-identity-disputed")
        ordinary = mimic(anchor, events)
        experiment = mimic(anchor, events, cross_examine=True)
        self.assertNotIn("cross_examination", ordinary)
        self.assertEqual(experiment["recommendation"], ordinary["recommendation"])
        without_swap, with_swap = (experiment["cross_examination"][name]
                                   for name in ("without_swap", "with_swap"))
        self.assertEqual(without_swap["decision"], "close")
        self.assertEqual(without_swap["observation"]["check"], "change_record")
        self.assertEqual(with_swap["decision"], "escalate")
        self.assertEqual(with_swap["observation"]["check"], "identity_record")

    def test_worker_rejects_a_switch_after_disclosing_a_result(self):
        with RoleProcess("blue") as blue:
            blue.call("assess", {
                "observations": [{"id": "E0", "kind": "ssh_login", "timestamp": 0}], "anchor": "E0", "history": [],
            })
            blue.call("commit", {})
            blue.call("reconsider", {"observation": {"check": "identity_record", "state": "unknown", "evidence_ids": []}})
            with self.assertRaises(RoleFailure):
                blue.call("switch", {"peer": {"check": "identity_record", "expected_state": "disputes"}})

    def test_paired_report_counts_both_gains_and_losses_at_equal_budget(self):
        ids = {"change-confirmed-and-identity-disputed", "change-confirmed"}
        rows = [line for line in DATA.read_text().splitlines() if json.loads(line)["id"] in ids]
        report = evaluate(io.StringIO("\n".join(rows)), analyze=partial(mimic, cross_examine=True))
        self.assertEqual(report["checks_per_variant"]["without_swap"], 1)
        self.assertEqual(report["checks_per_variant"]["with_swap"], 1)
        self.assertEqual(report["role_swap"], {"changed_checks": 2, "changed_decisions": 2,
                                               "only_with_swap_correct": 1, "only_without_swap_correct": 1})
        self.assertEqual(report["metrics"]["without_swap"]["false_closures"], 1)
        self.assertEqual(report["metrics"]["with_swap"]["false_closures"], 0)
