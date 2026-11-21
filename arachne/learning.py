"""Small offline models updated from operator-confirmed, comparable episodes."""

from collections import Counter

DECISIONS = ("close", "review", "escalate")
MAX_HISTORY = 5
MIN_OBSERVATIONS = 3


def decision_model(prior, history):
    votes = Counter({decision: 1 + 2 * (prior == decision) for decision in DECISIONS})
    for episode in history:
        if episode.get("initial") in DECISIONS:
            votes[episode["initial"]] += 1
    prediction = max(votes, key=lambda decision: (votes[decision], decision == prior))
    total = sum(votes.values())
    return prediction, {decision: round(votes[decision] / total, 3) for decision in DECISIONS}


def check_model(default, checks, history):
    outcomes = {check: [] for check in checks}
    for episode in history:
        verified = episode.get("verified")
        if verified not in DECISIONS:
            continue
        compared = {}
        for branch in episode.get("comparisons", ()):
            check = branch["check"]
            if check in outcomes:
                compared[check] = branch["decision"] == verified
        for check, correct in compared.items():
            outcomes[check].append(correct)
    calibrated = {
        check: {"successes": sum(results), "observations": len(results),
                "score": round((1 + sum(results)) / (2 + len(results)), 3)}
        for check, results in outcomes.items() if results
    }
    eligible = [
        check for check, result in calibrated.items()
        if result["observations"] >= MIN_OBSERVATIONS and result["score"] >= 0.75
    ]
    preferred = max(eligible, key=lambda check: (calibrated[check]["score"],
                                                 calibrated[check]["observations"], check == default)) if eligible else default
    return preferred, calibrated


def hypothesis_model(hypotheses, history):
    """Calibrate Blue's observation expectations for confirmed closure/escalation cases."""
    expected_outcome = {"legitimate": "close", "security": "escalate"}
    for perspective, hypothesis in hypotheses.items():
        for check in hypothesis["expectations"]:
            votes = Counter()
            for episode in history:
                if episode.get("verified") != expected_outcome[perspective]:
                    continue
                observed = next((branch["state"] for branch in episode.get("comparisons", ())
                                 if branch["check"] == check), None)
                if observed in {"supports", "disputes", "unknown"}:
                    votes[observed] += 1
            if votes:
                state, count = votes.most_common(1)[0]
                if count >= MIN_OBSERVATIONS and count > sum(votes.values()) / 2:
                    hypothesis["expectations"][check] = state
    return hypotheses
