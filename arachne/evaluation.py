"""Offline evaluation with labels hidden from all reasoning roles."""

from collections import defaultdict
from time import perf_counter

from .events import ANCHOR_KINDS, Event, read_records
from .reasoning import investigate

VARIANTS = ("blue", "standard_review", "assisted")
FULL_REFERENCE = "full_evidence_reference"


def parse_case(record):
    if not isinstance(record, dict) or set(record) != {"id", "family", "expected", "anchor_id", "events"}:
        raise ValueError("Each case must contain id, family, expected, anchor_id and events")
    for key in ("id", "family", "anchor_id"):
        if not isinstance(record[key], str) or not record[key].strip() or len(record[key]) > 200:
            raise ValueError(f"Invalid case {key}")
    if record["expected"] not in ("close", "review", "escalate"):
        raise ValueError("Expected decision must be close, review or escalate")
    if not isinstance(record["events"], list) or not 1 <= len(record["events"]) <= 1000:
        raise ValueError("A case must contain 1–1000 observations")
    observations = sorted(map(Event.parse, record["events"]), key=lambda event: (event.timestamp, event.id))
    if len({event.id for event in observations}) != len(observations):
        raise ValueError("Duplicate observation id within one case")
    anchor = next((event for event in observations if event.id == record["anchor_id"]), None)
    if not anchor or anchor.kind not in ANCHOR_KINDS:
        raise ValueError("Missing or invalid SSH anchor")
    return anchor, observations


def evaluate(stream, model=None, *, analyze=investigate, on_case=None):
    counts = {variant: defaultdict(int) for variant in VARIANTS}
    families = defaultdict(lambda: defaultdict(int))
    safety = defaultdict(int)
    role_swap = None
    forecast_cases = 0
    ids = set()
    start = perf_counter()
    for record in read_records(stream):
        anchor, events = parse_case(record)
        case_id = record["id"]
        if case_id in ids:
            raise ValueError(f"Duplicate case identifier: {case_id}")
        ids.add(case_id)
        report = analyze(anchor, events, model=model)
        expected = record["expected"]
        if on_case is not None:
            on_case({**report, "scenario": case_id, "label": expected})
        family = families[record["family"]]
        family["total"] += 1
        compared = {variant: report[variant] for variant in (*VARIANTS, FULL_REFERENCE) if variant in report}
        if "cross_examination" in report:
            arms = report["cross_examination"]
            compared.update(arms)
            if role_swap is None:
                role_swap = {"changed_checks": 0, "changed_decisions": 0,
                             "only_with_swap_correct": 0, "only_without_swap_correct": 0}
            original, switched = arms["without_swap"], arms["with_swap"]
            role_swap["changed_checks"] += int(original["observation"]["check"] != switched["observation"]["check"])
            role_swap["changed_decisions"] += int(original["decision"] != switched["decision"])
            original_correct, switched_correct = original["decision"] == expected, switched["decision"] == expected
            role_swap["only_with_swap_correct"] += int(switched_correct and not original_correct)
            role_swap["only_without_swap_correct"] += int(original_correct and not switched_correct)
        for variant, assessment in compared.items():
            if variant not in counts:
                counts[variant] = defaultdict(int)
            decision = assessment["decision"]
            counts[variant]["correct"] += int(expected == decision)
            counts[variant]["missed_escalations"] += int(expected == "escalate" and decision != expected)
            counts[variant]["false_escalations"] += int(expected != "escalate" and decision == "escalate")
            if variant in ("without_swap", "with_swap"):
                counts[variant]["false_closures"] += int(expected != "close" and decision == "close")
                matched = assessment["forecast_matched"]
                counts[variant]["forecasts_resolved"] += int(matched is not None)
                counts[variant]["forecasts_matched"] += int(matched is True)
            family[variant] += int(expected == decision)
        if "mimicry" in report:
            forecast_cases += 1
            safety["red_forecasts"] += int(report["prediction_matched"] is not None)
            safety["red_forecasts_matched"] += int(report["prediction_matched"] is True)
            safety["safety_policy_correct"] += int(expected == report["recommendation"]["decision"])
        standard_correct = expected == report["standard_review"]["decision"]
        assisted_correct = expected == report["assisted"]["decision"]
        safety["red_only_correct"] += int(assisted_correct and not standard_correct)
        safety["standard_only_correct"] += int(standard_correct and not assisted_correct)
    if not ids:
        raise ValueError("Evaluation input contains no cases")
    result = {"total": len(ids), "metrics": counts, "by_family": families, "paired": safety,
              "elapsed_seconds": round(perf_counter() - start, 3)}
    if forecast_cases:
        result["checks_per_variant"] = {"blue": 0, "standard_review": 1, "assisted": 1, FULL_REFERENCE: 3}
    if role_swap is not None:
        result["checks_per_variant"].update({"without_swap": 1, "with_swap": 1})
        result["role_swap"] = role_swap
    return result
