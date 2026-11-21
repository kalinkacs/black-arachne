"""Private child-process entry point for offline defensive roles."""

from dataclasses import dataclass
import json
import sys

from .learning import hypothesis_model
from .mimicry import CHECKS, RESTRICTED_KINDS, blue_hypotheses, observation_profile, reconsider, red_forecast, standard_choice
from .reasoning import blue
from .role_runtime import FORMAT, MAX_PACKET


@dataclass(frozen=True)
class Observation:
    id: str
    timestamp: int
    kind: str


PHASES = {
    "red": {"forecast", "compare"},
    "blue": {"assess", "reconsider"},
    "control": {"select"},
}
PROFILE_KEYS = {"declared_change", "prior_failures", "privileged_activity"}
OPTIONAL_PROFILE_KEYS = {"repeated_privilege_denials"}
DECISIONS = {"close", "review", "escalate"}
STATES = {"supports", "disputes", "unknown", "conflict"}


def handle(role, phase, payload, state):
    if phase not in PHASES[role] or not isinstance(payload, dict):
        raise ValueError("Unsupported role phase")
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
