"""Search for a consistency check in the supplied audit observations."""

from itertools import combinations, permutations
import json
import operator
import sys


RELATIONS = {"==": operator.eq, "<=": operator.le, "<": operator.lt}
ARITHMETIC = {"+": operator.add, "-": operator.sub}


def value(term, row):
    if isinstance(term, str):
        return row[term]
    operation, left, right = term
    return ARITHMETIC[operation](row[left], row[right])


def consistent(rule, row):
    operation, left, right = rule
    return RELATIONS[operation](value(left, row), value(right, row))


def rules_by_cost(fields):
    direct = [("==", a, b) for a, b in combinations(fields, 2)]
    direct.extend((op, a, b) for a, b in permutations(fields, 2) for op in ("<=", "<"))
    arithmetic = []
    for operation, pairs in (("+", combinations(fields, 2)), ("-", permutations(fields, 2))):
        for left, right in pairs:
            for field in fields:
                if field in (left, right):
                    continue
                term = (operation, left, right)
                arithmetic.extend((op, term, field) for op in RELATIONS)
                arithmetic.extend((op, field, term) for op in ("<=", "<"))
    return direct, arithmetic


def discover(examples):
    fields = sorted(set.intersection(*(set(case["audit"]) for case in examples)))
    examined = 0
    for cost, rules in enumerate(rules_by_cost(fields), start=1):
        examined += len(rules)
        surviving = [
            rule for rule in rules
            if all(consistent(rule, case["audit"]) == case["consistent"] for case in examples)
        ]
        if surviving:
            return {"rules": surviving, "cost": cost, "candidates_examined": examined}
    return {"rules": [], "cost": None, "candidates_examined": examined}


def predict(rules, cases):
    predictions = {}
    for case in cases:
        votes = {consistent(rule, case["audit"]) for rule in rules}
        predictions[case["id"]] = {frozenset({True}): "clear",
                                   frozenset({False}): "escalate"}.get(frozenset(votes), "review")
    return predictions


def counterexamples(rules, cases):
    return [
        {"rule": rule, "contradictions": [
            case["id"] for case in cases if consistent(rule, case["audit"]) != case["consistent"]
        ]}
        for rule in rules
    ]


def revise(original, challenges, examples):
    verified = counterexamples(original["rules"], examples)
    if challenges != verified:
        raise ValueError("The critic's report does not match the discovery observations")
    if verified and not any(item["contradictions"] for item in verified):
        return {**original, "action": "retained", "candidates_examined": 0}
    return {**discover(examples), "action": "searched"}


def respond(message):
    phase = message["phase"]
    if phase == "discover":
        return discover(message["examples"])
    if phase == "challenge":
        return counterexamples(message["rules"], message["examples"])
    if phase == "revise":
        return revise(message["original"], message["challenges"], message["examples"])
    if phase == "predict":
        return predict(message["rules"], message["cases"])
    raise ValueError(f"Unexpected phase: {phase}")


if __name__ == "__main__":
    for line in sys.stdin:
        print(json.dumps(respond(json.loads(line))), flush=True)
