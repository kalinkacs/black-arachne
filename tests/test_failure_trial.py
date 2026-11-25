import unittest

from arachne.failure_trial import compare_profile


class FailureTrialTests(unittest.TestCase):
    def test_restart_budget_is_equal_and_peer_continues_after_replacement_loss(self):
        profile = {"declared_change": True, "prior_failures": False, "privileged_activity": True,
                   "repeated_privilege_denials": False}

        def choose(choices):
            return choices[0]

        for paired in (False, True):
            clean = compare_profile(profile, choose, failures=0, paired=paired)
            single = compare_profile(profile, choose, failures=1, paired=paired)
            self.assertEqual(clean[:2], single[:2])
            self.assertEqual(single[2], 1)
        solo = compare_profile(profile, choose, failures=2, paired=False)
        pair = compare_profile(profile, choose, failures=2, paired=True)
        self.assertEqual(solo[1:], ("first_commitment", 2))
        self.assertEqual(pair[1:], ("peer_handoff", 2))
