"""Run and score local, read-only audit-consistency experiments."""

from collections import Counter
from contextlib import contextmanager
import json
from pathlib import Path
from random import Random
import subprocess
import sys


# The worker receives anonymous columns and labeled discovery examples.
# The generators and holdout scorer stay in this process.
TASKS = {
    "shared_limit": lambda x, y, z: x + y <= z,
    "balance": lambda x, y, z: x - y == z,
    "ordering": lambda x, y, z: x < z,
    "outside_grammar": lambda x, y, z: x * y == z,
}
WORKER = Path(__file__).with_name("solver.py")


def examples(task, fields, phase, count, seed):
    rng = Random(seed)
    comparison = TASKS[task]
    rows = []
    for index in range(count):
        expected = index % 2 == 0
        while True:
            x, y = rng.sample(range(1, 94) if phase != "holdout" else range(94, 190), 2)
            if phase != "initial" or (x < y) == expected:
                break
        if task == "shared_limit":
            z = x + y + (rng.randrange(0, 16) if expected else -rng.randrange(1, 16))
        elif task == "ordering":
            z = x + (rng.randrange(1, 16) if expected else -rng.randrange(0, 16))
        else:
            z = (x - y if task == "balance" else x * y)
            if not expected:
                z += rng.choice((-1, 1)) * rng.randrange(1, 16)
        assert comparison(x, y, z) == expected
        signal = (x, y, z)
        audit = {}
        for source, (field, nuisance) in enumerate(fields):
            if phase == "initial" and source == 2:
                continue
            first, second = (field, nuisance) if rng.randrange(2) else (nuisance, field)
            values = {field: signal[source], nuisance: rng.randrange(-300, 300)}
            audit.update((key, values[key]) for key in (first, second))
        rows.append({"id": f"{phase}-{index:02}", "audit": audit, "consistent": expected})
    rng.shuffle(rows)
    return rows


def project(rows, fields):
    return [{**case, "audit": {key: val for key, val in case["audit"].items() if key in fields}}
            for case in rows]


@contextmanager
def worker():
    with subprocess.Popen(
        [sys.executable, str(WORKER)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    ) as process:
        def call(phase, **data):
            process.stdin.write(json.dumps({"phase": phase, **data}) + "\n")
            process.stdin.flush()
            line = process.stdout.readline()
            if not line:
                raise RuntimeError(f"Worker exited during {phase}")
            return json.loads(line)

        try:
            yield call
        finally:
            process.stdin.close()


def evaluate(first, critic, reviewer, initial, discovery_ab, discovery, unseen, visible):
    original = first("discover", examples=initial)
    before = first("predict", rules=original["rules"], cases=project(unseen, visible))
    challenges = critic("challenge", rules=original["rules"], examples=discovery_ab)
    revised = reviewer("revise", original=original, challenges=challenges, examples=discovery)
    after = reviewer("predict", rules=revised["rules"], cases=unseen)
    return {"initial": original, "challenges": challenges, "revised": revised,
            "before": before, "after": after}


def score(predictions, labels):
    if predictions.keys() != labels.keys():
        raise ValueError("Worker predictions must cover the holdout exactly")
    counts = Counter(correct=0, false_alerts=0, incorrect_clearances=0, reviews=0)
    for case_id, prediction in predictions.items():
        expected = labels[case_id]
        counts["correct"] += prediction == expected
        counts["false_alerts"] += prediction == "escalate" and expected == "clear"
        counts["incorrect_clearances"] += prediction == "clear" and expected == "escalate"
        counts["reviews"] += prediction == "review"
    return counts


def run():
    report = {}
    for index, task in enumerate(TASKS):
        names = [f"field_{n}" for n in range(1, 7)]
        Random(110 + index).shuffle(names)
        fields = list(zip(names[::2], names[1::2]))
        initial, discovery, holdout = (
            examples(task, fields, phase, count, seed + index)
            for phase, count, seed in (("initial", 12, 201), ("discover", 40, 401), ("holdout", 48, 601))
        )
        visible = set(names[:4])
        discovery_ab = project(discovery, visible)
        unseen = [{key: row[key] for key in ("id", "audit")} for row in holdout]
        payload = (initial, discovery_ab, discovery, unseen, visible)
        with worker() as first, worker() as critic, worker() as reviewer:
            staged = evaluate(first, critic, reviewer, *payload)
        with worker() as central:
            pooled = evaluate(central, central, central, *payload)
        labels = {case["id"]: "clear" if case["consistent"] else "escalate" for case in holdout}
        report[task] = {
            "fields_by_source": dict(zip("ABC", fields)),
            "initial_examples": initial,
            "discovery_examples": discovery,
            "holdout_inputs": unseen,
            "holdout_answer_key": labels,
            "staged": staged,
            "pooled": pooled,
            "scores": {
                "initial": score(staged["before"], labels),
                "staged": score(staged["after"], labels),
                "pooled": score(pooled["after"], labels),
            },
        }
    return report


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
