"""Offline comparison of evidence sharing and centralized reconciliation."""

from collections import Counter
from itertools import combinations
import json


def proposal(batch, approvals):
    return "clear" if any(row["scope"] == batch["scope"] for row in approvals) else "review"


def hypotheses(batch, approvals, registry):
    """Enumerate observed links and require a scoped, independently recorded match."""
    candidates = []
    for approval in approvals:
        if approval["scope"] != batch["scope"]:
            continue
        for record in registry:
            if record["reference"] != approval["reference"]:
                continue
            shared = (batch.keys() & record.keys()) - {"id"}
            matches = sorted(key for key in shared if batch[key] == record[key])
            differences = sorted(shared - set(matches))
            candidates.append({
                "evidence": [batch["id"], approval["id"], record["id"]],
                "reference": record["reference"],
                "matches": matches,
                "differences": differences,
            })
    return candidates


def reconcile(candidates):
    if not candidates:
        return "review"
    supports = [not item["differences"] for item in candidates]
    if all(supports):
        return "clear"
    if not any(supports):
        return "escalate"
    return "review"


def staged(batch, approvals, registry):
    initial = proposal(batch, approvals)
    candidates = hypotheses(batch, approvals, registry)
    return {
        "initial": initial,
        "hypotheses": candidates,
        "decision": reconcile(candidates),
    }


def corpus():
    inputs, answers = [], {}
    # Counterbalance which attribute contradicts the first interpretation.
    fields = {"scope": "archive", "principal": "service-17", "artifact": "snapshot-8"}
    variations = [()] + [(key,) for key in fields if key != "scope"]
    variations += list(combinations(("principal", "artifact"), 2))
    for replica in range(3):
        for index, changed in enumerate(variations):
            case_id = f"{replica}-{index}"
            ref = f"change-{replica}-{index}"
            batch = {"id": "A1", **fields}
            approval = {"id": "B1", "scope": fields["scope"], "reference": ref}
            registry = {"id": "C1", "reference": ref, **fields}
            for key in changed:
                registry[key] = f"other-{replica}-{key}"
            unrelated = {**registry, "id": "C2", "reference": f"unrelated-{replica}", **fields}
            records = [registry, unrelated] if replica % 2 else [unrelated, registry]
            inputs.append((case_id, batch, [approval], records))
            answers[case_id] = "escalate" if changed else "clear"

    batch = {"id": "A1", **fields}
    approval = {"id": "B1", "scope": fields["scope"], "reference": "change-extra"}
    record = {"id": "C1", "reference": approval["reference"], **fields}
    inputs.extend([
        ("missing", batch, [approval], []),
        ("conflict", batch, [approval], [record, {**record, "id": "C2", "principal": "other"}]),
    ])
    answers.update(missing="review", conflict="review")
    return inputs, answers


def run():
    inputs, answers = corpus()
    observations = {}
    for case_id, batch, approvals, registry in inputs:
        swarm = staged(batch, approvals, registry)
        observations[case_id] = {
            "input": {"A": batch, "B": approvals, "C": registry},
            "trace": swarm,
            "decisions": {
                "approval_only": swarm["initial"],
                "pooled": reconcile(hypotheses(batch, approvals, registry)),
                "staged": swarm["decision"],
            },
        }
    totals = {name: Counter(correct=0, false_alerts=0, incorrect_clearances=0, reviews=0)
              for name in next(iter(observations.values()))["decisions"]}
    for case_id, observation in observations.items():
        expected = answers[case_id]
        for name, decision in observation["decisions"].items():
            counts = totals[name]
            counts["correct"] += decision == expected
            counts["false_alerts"] += decision == "escalate" and expected == "clear"
            counts["incorrect_clearances"] += decision == "clear" and expected == "escalate"
            counts["reviews"] += decision == "review"
    return {"totals": totals, "observations": observations, "answer_key": answers}


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
