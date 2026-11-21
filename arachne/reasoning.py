"""Deterministic defensive review with a blinded challenger and an optional model."""

from .agents import model_review
from .events import DENIAL_REVIEW_THRESHOLD, denied_attempts, episode_window, records

VERSION = "0.1"


def finding(decision, reason, evidence):
    return {"decision": decision, "reason": reason, "evidence_ids": [item.id for item in evidence]}


def relevant(anchor, events):
    lower, upper = episode_window(anchor)
    return [
        event for event in events
        if event.host == anchor.host and event.actor == anchor.actor and lower <= event.timestamp <= upper
    ]


def blue(anchor, observations):
    claims = [event for event in observations if event.kind == "deployment" and event.timestamp <= anchor.timestamp]
    failures = [event for event in observations if event.kind == "ssh_failure" and event.timestamp <= anchor.timestamp]
    privileged = [event for event in observations if event.kind == "privileged_activity" and event.timestamp >= anchor.timestamp]
    denials = denied_attempts(anchor, observations)
    if len(denials) >= DENIAL_REVIEW_THRESHOLD:
        return finding("review", "Repeated denied privilege requests require review.",
                       [anchor, *denials[:DENIAL_REVIEW_THRESHOLD]])
    if privileged and claims:
        return finding("close", "Blue accepted a declared change as a plausible explanation.", [anchor, claims[-1], privileged[0]])
    if len(failures) >= 3 and privileged:
        return finding("escalate", "Repeated SSH failures preceded privileged activity.", [anchor, *failures, privileged[0]])
    return finding("review", "The visible records are insufficient to resolve this login.", [anchor, *privileged[:1]])


def red(anchor, observations):
    declared = [event for event in observations if event.kind == "deployment" and event.timestamp <= anchor.timestamp]
    privileged = [event for event in observations if event.kind == "privileged_activity" and event.timestamp >= anchor.timestamp]
    if declared and privileged:
        return {
            "engine": "rules",
            "check": "change_record",
            "prediction": "close",
            "hypothesis": "Blue may close this case based on a declared change before checking independent confirmation.",
            "evidence_ids": [anchor.id, declared[-1].id, privileged[0].id],
        }
    return {
        "engine": "rules",
        "check": "conflicting_activity",
        "prediction": None,
        "hypothesis": "Verify whether independent privileged activity changes the assessment.",
        "evidence_ids": [anchor.id],
    }


def verify(anchor, observations, first, check):
    privileged = [event for event in observations if event.kind == "privileged_activity" and event.timestamp >= anchor.timestamp]
    if check == "change_record":
        confirmations = [event for event in observations if event.kind == "change_verified"
                         and event.source == "change-management"]
        if confirmations and first["decision"] == "close":
            return finding("close", "The designated independent change source corroborated the declared change.", [anchor, confirmations[0]])
        if first["decision"] == "close":
            return finding("review", "The declared change has no independent corroboration in the available window.", [anchor, *privileged[:1]])
    elif check == "conflicting_activity" and privileged and first["decision"] == "close":
        failures = [event for event in observations if event.kind == "ssh_failure" and event.timestamp <= anchor.timestamp]
        if len(failures) >= 3:
            return finding("escalate", "Independent review prioritizes the repeated failures and privileged activity.",
                           [anchor, *failures, privileged[0]])
    return first


def investigate(anchor, events, model=None):
    scoped = relevant(anchor, events)
    visible = [event for event in scoped if event.kind != "change_verified"]
    if model:
        return role_investigation(anchor, events, model)
    forecast = red(anchor, visible)
    initial = blue(anchor, visible)
    standard = verify(anchor, scoped, initial, "conflicting_activity")
    assisted = verify(anchor, scoped, initial, forecast["check"])
    prediction = forecast["prediction"]
    return {
        "engine_version": VERSION, "host": anchor.host, "anchor_id": anchor.id,
        "events": records(events), "forecast": forecast,
        "prediction_matched": prediction == initial["decision"] if prediction is not None else None,
        "blue": initial, "standard_review": standard, "assisted": assisted,
    }


def apply_policy(anchor, observations, recommendation):
    """Keep weakly supported conclusions open and preserve corroborated risk signals."""
    risk = verify(anchor, observations, {"decision": "close"}, "conflicting_activity")
    if risk["decision"] == "escalate":
        return risk
    if recommendation["decision"] == "close":
        claims = [event for event in observations if event.kind == "deployment" and event.timestamp <= anchor.timestamp]
        corroborated = any(
            event.kind == "change_verified" and event.source == "change-management"
            and claims and event.timestamp >= claims[-1].timestamp
            for event in observations
        )
        if not corroborated:
            return finding("review", "Closure requires independent corroboration of a declared change.", [anchor])
    return recommendation


def role_investigation(anchor, events, model, memory=()):
    """Blind Red to initial Blue output and expose the same catalogue to both reviewers."""
    scoped = relevant(anchor, events)
    visible = [event for event in scoped if event.kind != "change_verified"]
    forecast = model_review("red_forecast", model, anchor, visible, memory)
    initial = model_review("blue_initial", model, anchor, visible, memory)
    independent = model_review("independent_check", model, anchor, visible, memory)

    def reassess(check):
        disclosed = scoped if check == "change_record" else visible
        return model_review("blue_reassessment", model, anchor, disclosed, memory, check)

    standard = reassess(independent["check"])
    assisted = standard if independent["check"] == forecast["check"] else reassess(forecast["check"])
    return {
        "engine_version": "0.2", "host": anchor.host, "anchor_id": anchor.id,
        "events": records(events), "forecast": forecast, "independent_check": independent,
        "prediction_matched": forecast["prediction"] == initial["decision"] if forecast["prediction"] is not None else None,
        "blue": initial, "standard_review": standard, "assisted": assisted,
        "recommendation": apply_policy(anchor, scoped, assisted),
        "initial_hypotheses": {"legitimate": initial["legitimate"], "security": initial["security"]},
        "history_used": list(memory),
    }
