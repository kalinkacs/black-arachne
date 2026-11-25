from dataclasses import replace
from threading import Barrier
import unittest

from arachne.dumas import review
from arachne.events import observation_profile
from arachne.mimicry import check_observations, operational_policy
from arachne.role_runtime import RoleFailure
from test_offline import sample


class DumasTests(unittest.TestCase):
    def test_three_specialists_run_concurrently_with_separate_evidence(self):
        anchor, events = sample("change-confirmed")
        identity = replace(anchor, id="identity", kind="identity_disputed", source="identity-management")
        events = [*events, identity]
        barrier = Barrier(3, timeout=3)
        expected = {
            "change_record": {"deployment", "change_verified"},
            "identity_record": {"identity_disputed"},
            "activity_record": {"privileged_activity"},
        }

        def inspect(check, login, evidence, profile):
            barrier.wait()
            self.assertEqual({event.kind for event in evidence}, expected[check])
            return check_observations(check, login, evidence, profile)

        findings = review(anchor, events, observation_profile(anchor, events), inspect)
        self.assertEqual(findings["identity_record"]["evidence_ids"], [identity.id])
        initial = {"decision": "review", "evidence_ids": [anchor.id]}
        assisted = {"decision": "close", "evidence_ids": [anchor.id]}
        result = operational_policy(anchor, events, observation_profile(anchor, events), initial,
                                    assisted, checks=findings)
        self.assertEqual(result["decision"], "escalate")

    def test_an_incomplete_specialist_blocks_closure(self):
        anchor, events = sample("change-confirmed")
        profile = observation_profile(anchor, events)

        def inspect(check, login, evidence, flags):
            if check == "activity_record":
                raise RoleFailure("unavailable")
            return check_observations(check, login, evidence, flags)

        findings = review(anchor, events, profile, inspect)
        self.assertFalse(findings["activity_record"]["available"])
        finding = {"decision": "close", "evidence_ids": [anchor.id]}
        self.assertEqual(operational_policy(anchor, events, profile, finding, finding,
                                            checks=findings)["decision"], "review")
