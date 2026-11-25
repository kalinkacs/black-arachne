from io import StringIO
from pathlib import Path
import unittest
from unittest.mock import patch

from arachne.swarm import Handoff, benchmark_swarm, follow_up, workload

DATA = Path(__file__).resolve().parents[1] / "arachne" / "data" / "trial.jsonl"


class SwarmTests(unittest.TestCase):
    def test_double_interruption_is_handed_to_a_fresh_team(self):
        with DATA.open(encoding="utf-8") as stream:
            case = stream.readline()
        report = benchmark_swarm(StringIO(case), 1, [1], 1)
        result = report["configurations"][0]
        self.assertEqual(report["forced_interruptions"], 2)
        self.assertEqual(result["worker_failure_handoffs"], 1)
        self.assertEqual(result["before_handoffs"]["manual_review"], 1)
        self.assertEqual(result["after_handoffs"]["correct"], 1)

    def test_follow_up_cannot_attach_its_message_to_another_session(self):
        with DATA.open(encoding="utf-8") as stream:
            assignments, _ = workload(stream, 1)
        message = Handoff(assignments[0].anchor.id, ("identity-management",), "verification_feed_degraded", 1)
        with self.assertRaisesRegex(ValueError, "does not match"):
            follow_up(assignments[1], message)

    def test_partial_coverage_does_not_promote_a_review_to_closure(self):
        with DATA.open(encoding="utf-8") as stream:
            assignments, _ = workload(stream, 2)
        item = next(item for item in assignments if item.degraded and item.delayed)
        sources = tuple(event.source for event in item.delayed)
        message = Handoff(item.anchor.id, sources, "verification_feed_degraded", 2)
        with patch("arachne.swarm.inspect_case", return_value={"recommendation": {"decision": "close"}}):
            self.assertEqual(follow_up(item, message), ("review", True))
