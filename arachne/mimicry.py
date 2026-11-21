"""Defensive perspective modeling with blind predictions and bounded evidence disclosure."""

from .reasoning import blue, finding, relevant
from .events import records
from .learning import check_model, decision_model, hypothesis_model

CHECKS = {
    "change_record": {
        "source": "change-management",
        "positive": "change_verified",
        "negative": "change_disputed",
    },
    "identity_record": {
        "source": "identity-management",
        "positive": "identity_verified",
        "negative": "identity_disputed",
    },
    "activity_record": {"source": "systemd-journal"},
}
RESTRICTED_KINDS = {
    kind
    for check in CHECKS.values()
    for field, kind in check.items()
    if field in {"positive", "negative"}
}


def observation_profile(anchor, events):
    return {
        "declared_change": any(event.kind == "deployment" and event.timestamp <= anchor.timestamp for event in events),
        "prior_failures": sum(event.kind == "ssh_failure" and event.timestamp <= anchor.timestamp for event in events) >= 3,
        "privileged_activity": any(event.kind == "privileged_activity" and event.timestamp >= anchor.timestamp for event in events),
    }


def blue_hypotheses(profile):
    context = "a declared change" if profile["declared_change"] else "an operator's normal work"
    return {
        "legitimate": {
            "description": f"The SSH activity is consistent with {context}.",
            "expectations": {"change_record": "supports", "identity_record": "supports", "activity_record": "unknown"},
        },
        "security": {
            "description": "The session may involve unauthorized use of the account.",
            "expectations": {"change_record": "disputes", "identity_record": "disputes", "activity_record": "disputes"},
        },
    }


def red_forecast(profile, history=()):
    """Model the original Blue policy using only boolean properties of its view."""
    if profile["declared_change"] and profile["privileged_activity"]:
        predicted = "close"
        check = "change_record"
        reason = "Blue may confuse a declared change with evidence that this activity was authorized."
    elif profile["prior_failures"] and profile["privileged_activity"]:
        predicted = "escalate"
        check = "identity_record"
        reason = "Blue may escalate before it checks whether an independent source can explain the login."
    else:
        predicted = "review"
        check = "identity_record"
        reason = "An independently recorded account decision could resolve uncertainty in the Blue assessment."

    prior = predicted
    predicted, probabilities = decision_model(prior, history)
    if predicted != prior:
        reason += " The distribution of prior Blue decisions changes the forecast."
    learned_check, estimates = check_model(check, CHECKS, history)
    if learned_check != check:
        check = learned_check
        reason += " Multiple comparable, verified episodes support a different verification."
    return {
        "engine": "policy-model",
        "check": check,
        "prediction": predicted,
        "hypothesis": reason,
        "disconfirmation": f"The forecast fails if Blue's initial decision differs from {predicted}.",
        "evidence_ids": [],
        "visible_profile": dict(profile),
        "decision_distribution": probabilities,
        "check_history": estimates,
    }


def standard_choice(profile):
    """Fixed review procedure using the same catalogue and single-check budget as Red."""
    if profile["prior_failures"]:
        return "activity_record"
    if profile["declared_change"]:
        return "change_record"
    return "identity_record"


def check_observations(check, anchor, events, profile):
    if check == "activity_record":
        failures = [event for event in events if event.kind == "ssh_failure" and event.timestamp <= anchor.timestamp]
        privilege = [event for event in events if event.kind == "privileged_activity" and event.timestamp >= anchor.timestamp]
        status = "disputes" if profile["prior_failures"] and profile["privileged_activity"] else "unknown"
        return {"check": check, "state": status, "evidence_ids": [event.id for event in (*failures[:3], *privilege[:1])]}
    allowed = CHECKS[check]
    candidates = [
        event for event in events
        if event.source == allowed["source"] and event.kind in {allowed["positive"], allowed["negative"]}
    ]
    if check == "change_record":
        claims = [event for event in events if event.kind == "deployment" and event.timestamp <= anchor.timestamp]
        candidates = [event for event in candidates if claims and event.timestamp >= claims[-1].timestamp]
    else:
        candidates = [event for event in candidates if event.timestamp >= anchor.timestamp]
    states = {event.kind for event in candidates}
    if states == {allowed["positive"], allowed["negative"]}:
        state = "conflict"
    elif allowed["negative"] in states:
        state = "disputes"
    elif allowed["positive"] in states:
        state = "supports"
    else:
        state = "unknown"
    return {"check": check, "state": state, "evidence_ids": [event.id for event in candidates[:12]]}


def reconsider(initial, observed, anchor):
    ids = list(dict.fromkeys([anchor.id, *observed["evidence_ids"]]))
    state = observed["state"]
    evidence = {"evidence_ids": ids}
    if state == "disputes":
        return {**evidence, "decision": "escalate", "reason": "The additional observation raises a specific concern."}
    if state == "conflict":
        return {**evidence, "decision": "review", "reason": "Independent records disagree and require operator review."}
    if observed["check"] == "change_record" and state == "supports" and initial["decision"] != "escalate":
        return {**evidence, "decision": "close", "reason": "The independent change record supports the expected work."}
    if observed["check"] == "identity_record" and state == "supports" and initial["decision"] == "escalate":
        return {**evidence, "decision": "review", "reason": "The identity record supplies a competing explanation for the initial escalation."}
    if initial["decision"] == "close":
        return {**evidence, "decision": "review", "reason": "The available observation cannot corroborate closure."}
    return initial


def operational_policy(anchor, observations, profile, initial, assisted):
    """Apply local safeguards outside both one-check comparison branches."""
    independent = [
        check_observations(check, anchor, observations, profile)
        for check in ("change_record", "identity_record")
    ]
    for result in independent:
        if result["state"] == "disputes":
            return reconsider(initial, result, anchor)
    for result in independent:
        if result["state"] == "conflict":
            return reconsider(initial, result, anchor)
    if initial["decision"] == "escalate" and assisted["decision"] != "escalate":
        return finding("review", "Escalation was disputed. An operator must reconcile the evidence.", [anchor])
    return assisted


def mimic(anchor, events, history=(), model=None):
    """Freeze both perspectives before either branch receives any verification."""
    scoped = relevant(anchor, events)
    visible = [event for event in scoped if event.kind not in RESTRICTED_KINDS]
    profile = observation_profile(anchor, visible)
    challenger = red_forecast(profile, history)
    initial = blue(anchor, visible)
    hypotheses = hypothesis_model(blue_hypotheses(profile), history)
    standard = {"check": standard_choice(profile), "engine": "rules",
                "reason": "Inspect the highest-priority independent evidence from the visible profile."}
    if model:
        from .agents import model_review

        challenger = model_review("mimic_forecast", model, anchor, visible, history, profile=profile)
        standard = model_review("mimic_control", model, anchor, visible, history, profile=profile)
        assessment = model_review("mimic_blue", model, anchor, visible, history)
        initial = {key: assessment[key] for key in ("decision", "reason", "evidence_ids", "engine")}
        hypotheses = {
            perspective: {
                "description": assessment[perspective],
                "expectations": {check: assessment[f"{perspective}_{check}"] for check in CHECKS},
            }
            for perspective in ("legitimate", "security")
        }

    standard_choice_id = standard["check"]
    standard_result = check_observations(standard_choice_id, anchor, scoped, profile)
    selected = challenger["check"]
    assisted_result = standard_result if selected == standard_choice_id else check_observations(selected, anchor, scoped, profile)

    def score(result):
        return {role: model["expectations"][result["check"]] == result["state"]
                for role, model in hypotheses.items()} if result["state"] in {"supports", "disputes"} else {}

    ordinary_review = reconsider(initial, standard_result, anchor)
    assisted = reconsider(initial, assisted_result, anchor)
    advice = operational_policy(anchor, scoped, profile, initial, assisted)
    return {
        "engine_version": "0.4",
        "host": anchor.host,
        "anchor_id": anchor.id,
        "events": records(events),
        "forecast": challenger,
        "prediction_matched": challenger["prediction"] == initial["decision"] if challenger["prediction"] is not None else None,
        "blue": initial,
        "initial_hypotheses": {role: hypothesis["description"] for role, hypothesis in hypotheses.items()},
        "standard_review": ordinary_review,
        "assisted": assisted,
        "recommendation": advice,
        "history_used": list(history),
        "mimicry": {
            "hypotheses": hypotheses,
            "standard_reviewer": standard,
            "standard_observation": standard_result,
            "assisted_observation": assisted_result,
            "hypothesis_matches": score(assisted_result),
            "checks_per_branch": 1,
        },
    }
