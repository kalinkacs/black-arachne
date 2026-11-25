import unittest

from arachne.rotation_trial import SOURCES, rotate


class RotationTrialTests(unittest.TestCase):
    def test_every_team_reviews_and_a_peer_takes_over_after_two_process_losses(self):
        profile = {"declared_change": True, "prior_failures": False, "privileged_activity": True,
                   "repeated_privilege_denials": False}
        normal, rounds, _ = rotate(profile, list(SOURCES))
        restarted, trace, stops = rotate(profile, list(SOURCES), interrupted_role="red", interrupted_round=2)
        self.assertEqual(restarted, normal)
        self.assertEqual(stops, 2)
        for team in ("A", "B", "C"):
            self.assertEqual(
                {role for entry in rounds for role, assigned in entry["teams"].items() if assigned == team},
                {"red", "blue", "control"},
            )
        self.assertEqual(trace[1]["handoffs"], [{"from": "B", "to": "A", "role": "red"}])
