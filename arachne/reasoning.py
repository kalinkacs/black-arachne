"""Deterministic defensive review with a blinded challenger and an optional model."""

from datetime import datetime
import json
import os
import urllib.request

from .events import records

VERSION = "0.1"
CHECKS = ("change_record", "conflicting_activity")


def finding(decision, reason, evidence):
    return {"decision": decision, "reason": reason, "evidence_ids": [item.id for item in evidence]}


def relevant(anchor, events):
    return [event for event in events if event.host == anchor.host and event.actor == anchor.actor]


def blue(anchor, observations):
    claims = [event for event in observations if event.kind == "deployment" and event.timestamp <= anchor.timestamp]
    failures = [event for event in observations if event.kind == "ssh_failure" and event.timestamp <= anchor.timestamp]
    privileged = [event for event in observations if event.kind == "privileged_activity" and event.timestamp >= anchor.timestamp]
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


def model_red(anchor, observations, model):
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        raise ValueError("OPENAI_API_KEY is required with --model")
    properties = {
        "check": {"type": "string", "enum": list(CHECKS)},
        "prediction": {"type": ["string", "null"], "enum": ["close", "review", "escalate", None]},
        "hypothesis": {"type": "string"},
        "evidence_ids": {"type": "array", "items": {"type": "string"}},
    }
    # Only kinds, relative timing and local handles are sent to the provider.
    handles = {f"E{index}": event.id for index, event in enumerate(observations)}
    visible = [
        {"handle": handle, "kind": event.kind, "is_anchor": event.id == anchor.id,
         "offset_seconds": (datetime.fromisoformat(event.timestamp) - datetime.fromisoformat(anchor.timestamp)).total_seconds()}
        for handle, event in zip(handles, observations)
    ]
    request = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=json.dumps({
            "model": model,
            "messages": [
                {"role": "system", "content": (
                    "You review defensive Linux triage. Blue closes when a deployment claim precedes a login "
                    "and privileged activity follows; otherwise it escalates when >=3 failures precede the "
                    "login and privilege follows, and requests review in other cases. Predict Blue's decision "
                    "or abstain. Choose one read-only check: change_record verifies the declared change; "
                    "conflicting_activity reviews privileged activity. Cite local evidence handles. "
                    "Use only the evidence provided and describe a defensive hypothesis."
                )},
                {"role": "user", "content": json.dumps(visible)},
            ],
            "response_format": {"type": "json_schema", "json_schema": {
                "name": "defensive_review", "strict": True,
                "schema": {"type": "object", "properties": properties,
                           "required": list(properties), "additionalProperties": False},
            }},
            "max_completion_tokens": 1200,
        }).encode(),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        data = json.load(response)
    try:
        result = json.loads(data["choices"][0]["message"]["content"])
        references = result["evidence_ids"]
        if (
            set(result) != set(properties)
            or result["check"] not in CHECKS
            or result["prediction"] not in ("close", "review", "escalate", None)
            or not isinstance(result["hypothesis"], str)
            or not 0 < len(result["hypothesis"]) <= 600
            or not isinstance(references, list)
            or not 0 < len(references) <= 12
            or not all(isinstance(ref, str) and ref in handles for ref in references)
        ):
            raise ValueError("Model output did not pass evidence validation")
        result["evidence_ids"] = list(dict.fromkeys(handles[ref] for ref in references))
        return {**result, "engine": model}
    except (KeyError, TypeError, IndexError, json.JSONDecodeError) as error:
        raise ValueError("No usable structured model review was received") from error


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
    forecast = model_red(anchor, visible, model) if model else red(anchor, visible)
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
