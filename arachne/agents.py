"""Structured model calls for defensive decisions. Transport has no execution tools."""

from datetime import datetime
import json
import os
import urllib.request

DECISIONS = ("close", "review", "escalate")
CHECKS = ("change_record", "conflicting_activity")
EVIDENCE = {"type": "array", "items": {"type": "string"}}
DECISION = {"type": "string", "enum": list(DECISIONS)}
CHECK = {"type": "string", "enum": list(CHECKS)}
TEXT = {"type": "string"}

ROLES = {
    "blue_initial": (
        "You are Blue, a Linux defensive analyst. Assess the login using only visible evidence. "
        "Give a plausible legitimate explanation and a competing security explanation. "
        "Choose close, review, or escalate. Request review when evidence is insufficient.",
        {"decision": DECISION, "legitimate": TEXT, "security": TEXT, "reason": TEXT, "evidence_ids": EVIDENCE},
    ),
    "red_forecast": (
        "You are Red, a defensive reviewer predicting another analyst's decision from their evidence, "
        "without seeing their actual answer. Identify a potential defensive reasoning error. "
        "Choose one read-only verification from the catalogue. Use null if the decision is unpredictable.",
        {"prediction": {"type": ["string", "null"], "enum": [*DECISIONS, None]}, "check": CHECK,
         "hypothesis": TEXT, "evidence_ids": EVIDENCE},
    ),
    "independent_check": (
        "Independently pick one read-only verification that is most useful for a Linux defensive investigation. "
        "Use the evidence and give a short rationale.",
        {"check": CHECK, "reason": TEXT, "evidence_ids": EVIDENCE},
    ),
    "blue_reassessment": (
        "You are Blue, reassessing a Linux investigation with an additional observation. "
        "Explain the plausible legitimate and security interpretations, and give a defensive recommendation.",
        {"decision": DECISION, "legitimate": TEXT, "security": TEXT, "reason": TEXT, "evidence_ids": EVIDENCE},
    ),
}

CATALOGUE = {
    "change_record": "Reveal an independent change record if one is recorded.",
    "conflicting_activity": "Re-evaluate the timing of failed logins and subsequent privileged activity.",
}


def visible_records(anchor, observations):
    origin = datetime.fromisoformat(anchor.timestamp)
    return [
        {"handle": f"E{index}", "kind": event.kind, "is_anchor": event.id == anchor.id,
         "offset_seconds": (datetime.fromisoformat(event.timestamp) - origin).total_seconds()}
        for index, event in enumerate(observations)
    ]


def request_result(model, role, properties, instructions, payload):
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        raise ValueError("OPENAI_API_KEY is required for model-assisted review")
    request = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=json.dumps({
            "model": model,
            "messages": [{"role": "system", "content": instructions},
                         {"role": "user", "content": json.dumps(payload)}],
            "response_format": {"type": "json_schema", "json_schema": {
                "name": role, "strict": True,
                "schema": {"type": "object", "properties": properties, "required": list(properties),
                           "additionalProperties": False},
            }},
            "max_completion_tokens": 1800,
        }).encode(),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read(262_145)
    if len(raw) > 262_144:
        raise ValueError("Model response exceeds 256 KiB")
    try:
        return json.loads(json.loads(raw)["choices"][0]["message"]["content"])
    except (KeyError, TypeError, IndexError, ValueError) as error:
        raise ValueError("No usable structured model review was received") from error


def model_review(role, model, anchor, observations, memory=(), check=None):
    instructions, properties = ROLES[role]
    payload = {"events": visible_records(anchor, observations), "checks": CATALOGUE,
               "confirmed_history": list(memory), "completed_check": check}
    result = request_result(model, role, properties, instructions, payload)
    if not isinstance(result, dict) or set(result) != set(properties):
        raise ValueError("Invalid keys in model review")
    for key, schema in properties.items():
        value = result[key]
        if "enum" in schema and value not in schema["enum"]:
            raise ValueError(f"Model provided invalid {key}")
        if schema == TEXT and (not isinstance(value, str) or not value.strip() or len(value) > 600):
            raise ValueError(f"Model provided invalid {key}")
    handles = {f"E{index}": event.id for index, event in enumerate(observations)}
    refs = result["evidence_ids"]
    if (not isinstance(refs, list) or not 0 < len(refs) <= 12
            or not all(isinstance(ref, str) and ref in handles for ref in refs)):
        raise ValueError("Model output did not pass evidence validation")
    return {**result, "engine": model, "evidence_ids": list(dict.fromkeys(handles[ref] for ref in refs))}
