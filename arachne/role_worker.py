"""Private child-process entry point for offline defensive roles."""

from dataclasses import dataclass
import json
import sys

from .learning import hypothesis_model
from .measurement import ASSURANCES, PROFILE_FIELDS, checked_focus, local_focus
from .mimicry import (
    CHECKS, CROSS_CHECKS, RESTRICTED_KINDS, blue_hypotheses, checked_commitment,
    observation_profile, reconsider, red_forecast, standard_choice,
)
from .reasoning import blue
from .role_runtime import FORMAT, MAX_PACKET


@dataclass(frozen=True)
class Observation:
    id: str
    timestamp: int
    kind: str


PHASES = {
    "red": {"forecast", "compare", "commit", "switch", "signal_initial", "signal_reframe"},
    "blue": {"assess", "reconsider", "commit", "switch", "signal_initial", "signal_reframe"},
    "control": {"select"},
}
PROFILE_KEYS = {"declared_change", "prior_failures", "privileged_activity"}
OPTIONAL_PROFILE_KEYS = {"repeated_privilege_denials"}
DECISIONS = {"close", "review", "escalate"}
STATES = {"supports", "disputes", "unknown", "conflict"}


def plan_signal(role, phase, payload, state):
    if phase in state:
        raise ValueError("Evidence proposal is already frozen")
    perspective = "legitimate" if role == "blue" else "security"
    if phase == "signal_initial":
        profile = payload.get("profile")
        focus = payload.get("focus")
        if (not {"profile"} <= set(payload) <= {"profile", "focus"}
                or focus not in (*ASSURANCES, None)
                or not isinstance(profile, dict) or set(profile) != PROFILE_FIELDS
                or not all(type(value) is bool for value in profile.values())):
            raise ValueError("Invalid evidence planning profile")
        result = local_focus(profile, perspective) if focus is None else {"primary": focus, "secondary": None}
        state["signal_profile"] = profile
    else:
        if "signal_initial" not in state or set(payload) != {"peer"} or (payload["peer"] is None and role != "blue"):
            raise ValueError("Invalid evidence planning reframe")
        peer = payload["peer"]
        if peer is not None:
            peer = checked_focus(peer, first=True)["primary"]
            perspective = "security" if role == "blue" else "legitimate"
        result = local_focus(state["signal_profile"], perspective, own=state["signal_initial"]["primary"], peer=peer)
    state[phase] = result
    return result


def cross_examine(role, phase, payload, state):
    initial_phase, reveal_phase = ("forecast", "compare") if role == "red" else ("assess", "reconsider")
    if initial_phase not in state or phase in state or reveal_phase in state:
        raise ValueError("Commitments must follow assessment and precede additional evidence")
    if phase == "commit" and not payload:
        if role == "red":
            check = state["forecast"]["check"]
            if check not in CROSS_CHECKS:
                check = "identity_record"
            expected = "disputes"
        else:
            decision = state["assess"]["decision"]
            check = "change_record" if decision == "close" else "identity_record"
            expected = "disputes" if decision == "escalate" else "supports"
    elif phase == "switch" and set(payload) == {"peer"} and "commit" in state:
        peer = checked_commitment(payload["peer"])
        check = peer["check"]
        if role == "red":
            # Argue the case for legitimate work using the independent
            # source that Blue named before hearing the challenge.
            expected = "supports"
        else:
            # A valid change record addresses authorization. It leaves the
            # identity of the person using the account open to challenge.
            if check == "change_record":
                check = "identity_record"
            expected = "disputes"
    else:
        raise ValueError("Invalid role-switch request")
    state[phase] = True
    return {"check": check, "expected_state": expected}


def handle(role, phase, payload, state):
    if phase not in PHASES[role] or not isinstance(payload, dict):
        raise ValueError("Unsupported role phase")
    if phase in {"signal_initial", "signal_reframe"}:
        return plan_signal(role, phase, payload, state)
    if phase in {"commit", "switch"}:
        return cross_examine(role, phase, payload, state)
    if phase in {"forecast", "select"}:
        expected = {"profile", "history"}
        if (set(payload) != expected or not PROFILE_KEYS <= set(payload["profile"]) <= PROFILE_KEYS | OPTIONAL_PROFILE_KEYS
                or not all(type(value) is bool for value in payload["profile"].values())):
            raise ValueError("Invalid coarse profile")
        if phase in state:
            raise ValueError("The initial role decision is already frozen")
        if role == "red":
            state[phase] = red_forecast(payload["profile"], payload["history"])
            return state[phase]
        state[phase] = True
        return {"check": standard_choice(payload["profile"]), "engine": "rules",
                "reason": "Check the highest-priority independent evidence from the visible profile."}
    if phase == "assess":
        if set(payload) != {"observations", "anchor", "history"} or phase in state:
            raise ValueError("Invalid Blue projection or repeat assessment")
        events = [Observation(**event) for event in payload["observations"]]
        if any(event.kind in RESTRICTED_KINDS for event in events):
            raise ValueError("Undisclosed observation in initial role projection")
        anchor = next(event for event in events if event.id == payload["anchor"])
        profile = observation_profile(anchor, events)
        state["anchor"] = anchor
        state[phase] = blue(anchor, events)
        return {"initial": state[phase],
                "hypotheses": hypothesis_model(blue_hypotheses(profile), payload["history"])}
    if phase == "reconsider":
        if set(payload) != {"observation"} or "assess" not in state or state.get(phase, 0) >= 2:
            raise ValueError("Invalid reconsideration request")
        observation = payload["observation"]
        if observation["check"] not in CHECKS or observation["state"] not in STATES:
            raise ValueError("Unsupported observation")
        state[phase] = state.get(phase, 0) + 1
        return reconsider(state["assess"], observation, state["anchor"])
    if set(payload) != {"actual", "result", "observation"} or "forecast" not in state or phase in state:
        raise ValueError("Invalid Red comparison")
    if payload["actual"] not in DECISIONS or payload["result"] not in DECISIONS or payload["observation"] not in STATES:
        raise ValueError("Invalid comparison result")
    state[phase] = True
    predicted = state["forecast"]["prediction"]
    return {
        "prediction_matched": predicted == payload["actual"] if predicted is not None else None,
        "decision_changed": payload["actual"] != payload["result"],
        "verification_state": payload["observation"],
    }


def main():
    role = sys.argv[1]
    state = {}
    previous_sequence = 0
    while message := sys.stdin.buffer.readline(MAX_PACKET + 1):
        if len(message) > MAX_PACKET:
            raise ValueError("Role request exceeds packet budget")
        envelope = json.loads(message)
        if (set(envelope) != {"version", "phase", "sequence", "payload"}
                or envelope["version"] != FORMAT or envelope["sequence"] != previous_sequence + 1):
            raise ValueError("Invalid role envelope")
        previous_sequence = envelope["sequence"]
        result = handle(role, envelope["phase"], envelope["payload"], state)
        print(json.dumps({"version": FORMAT, "sequence": envelope["sequence"], "result": result},
                         ensure_ascii=False, allow_nan=False), flush=True)


if __name__ == "__main__":
    main()
