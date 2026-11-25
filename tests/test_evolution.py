from pathlib import Path
import unittest

from arachne.evolution import Strategy, descendants, evolve_signals

DATA = Path(__file__).resolve().parents[1] / "arachne" / "data"


class EvolutionTests(unittest.TestCase):
    def test_pair_exploration_is_bounded_and_keeps_parent_first(self):
        parent = Strategy(red_focus="identity")
        candidates = list(descendants(parent, explore_pairs=True))
        self.assertEqual(candidates[0], parent)
        self.assertEqual(len(candidates), len(set(candidates)))
        self.assertEqual(len(candidates), 18)

    def test_discovery_winner_cannot_advance_after_a_holdout_regression(self):
        with (DATA / "signal-discovery.jsonl").open() as discovery, (DATA / "signal-holdout.jsonl").open() as holdout:
            report = evolve_signals(discovery, holdout, 2)
        self.assertEqual(report["readings_per_pair_per_variant"], 1)
        self.assertEqual(report["holdout_pairs"], 8)
        self.assertEqual(len(report["plans_sha256_before_scoring"]), 64)
        self.assertGreater(report["holdout"]["winner"]["reversed"], 0)
        self.assertFalse(report["eligible_for_next_pilot"])
