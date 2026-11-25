"""Score the disposable Windows pilot from Security log metadata."""

from dataclasses import dataclass
import json
from pathlib import Path
import sys

from arachne.dumas import review

SPECIALTIES = {
    "activity": ("Aramis", {"file_write"}),
    "scope": ("Porthos", {"file_write"}),
    "approval": ("Athos", {"approval"}),
}


@dataclass(frozen=True)
class Observation:
    kind: str
    path: str


def run(cases):
    metrics = {name: {"correct": 0, "missed_escalations": 0, "false_escalations": 0}
               for name in ("volume_only", "single_agent", "dumas")}
    details = []
    for case in cases:
        observed = {item["path"] for item in case["writes"]}
        if observed != set(case["written_paths"]):
            raise ValueError(f"Native event coverage is incomplete for {case['id']}")
        approved = set(case["approval"])
        evidence = [*(Observation("file_write", path) for path in observed),
                    *(Observation("approval", path) for path in approved)]

        def inspect(check, _, items, profile):
            paths = {item.path for item in items}
            return {"paths": paths, "check": check}

        findings = review(None, evidence, {}, inspect, specialties=SPECIALTIES)
        threshold = case["threshold"]
        decisions = {
            "volume_only": len(observed) >= threshold,
            "single_agent": len(observed) >= threshold and bool(observed - approved),
            "dumas": len(findings["activity"]["paths"]) >= threshold
            and bool(findings["scope"]["paths"] - findings["approval"]["paths"]),
        }
        for variant, escalated in decisions.items():
            expected = case["expected_escalation"]
            metrics[variant]["correct"] += escalated == expected
            metrics[variant]["missed_escalations"] += expected and not escalated
            metrics[variant]["false_escalations"] += escalated and not expected
        details.append({"case": case["id"], "distinct_writes": len(observed), "decisions": decisions})
    return {"cases": details, "metrics": metrics,
            "independent_approval_reads_per_case": {"single_agent": 1, "dumas": 1}}


if __name__ == "__main__":
    cases = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8-sig"))
    print(json.dumps(run(cases), indent=2))
