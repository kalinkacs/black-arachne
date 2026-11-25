"""Defensive perspective modeling with blind predictions and bounded evidence disclosure."""

from datetime import datetime, timedelta

from .reasoning import finding, relevant
from .events import DENIAL_REVIEW_THRESHOLD, denied_attempts, observation_profile, records
from .learning import check_model, decision_model
from .provenance import VERIFICATION_KINDS
from .role_runtime import RoleFailure, RoleProcess
from .sessions import attributed_events

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
RESTRICTED_KINDS = VERIFICATION_KINDS
CROSS_CHECKS = ("change_record", "identity_record")


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
    """Choose a check on the evidence; model Blue only from observed behavior."""
    if profile.get("repeated_privilege_denials"):
        check = "identity_record"
        reason = "The independent identity decision may clarify repeated denied requests."
    elif profile["declared_change"] and profile["privileged_activity"]:
        check = "change_record"
        reason = "Confirm whether the declared change covers the observed activity."
    elif profile["prior_failures"] and profile["privileged_activity"]:
        check = "identity_record"
        reason = "An independent identity decision distinguishes account misuse from a legitimate recovery."
    else:
        check = "identity_record"
        reason = "An independent identity decision may resolve an ambiguous login."

    predicted, probabilities = decision_model(history)
    learned_check, estimates = check_model(check, CHECKS, history)
    if learned_check != check:
        check = learned_check
        reason += " Multiple comparable, verified episodes support a different verification."
    return {
        "engine": "observed-policy-model",
        "check": check,
        "prediction": predicted,
        "hypothesis": reason,
        "disconfirmation": (f"The forecast fails if Blue's initial decision differs from {predicted}."
                             if predicted else "There is not enough comparable history to predict Blue's decision."),
        "evidence_ids": [],
        "visible_profile": dict(profile),
        "decision_distribution": probabilities,
        "check_history": estimates,
    }


def standard_choice(profile):
    """Fixed review procedure using the same catalogue and single-check budget as Red."""
    if profile["prior_failures"] or profile.get("repeated_privilege_denials"):
        return "activity_record"
    if profile["declared_change"]:
        return "change_record"
    return "identity_record"


def check_observations(check, anchor, events, profile):
    if check == "activity_record":
        failures = [event for event in events if event.kind == "ssh_failure" and event.timestamp <= anchor.timestamp]
        privilege = [event for event in events if event.kind == "privileged_activity" and event.timestamp >= anchor.timestamp]
        status = "disputes" if profile["prior_failures"] and profile["privileged_activity"] else "unknown"
        denials = denied_attempts(anchor, events)[:DENIAL_REVIEW_THRESHOLD]
        return {"check": check, "state": status,
                "evidence_ids": [event.id for event in (*failures[:3], *privilege[:1], *denials)]}
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
    if profile["repeated_privilege_denials"] and assisted["decision"] == "close":
        return finding("review", "Repeated denied privilege requests need review before closure.",
                       [anchor, *denied_attempts(anchor, observations)[:DENIAL_REVIEW_THRESHOLD]])
    if initial["decision"] == "escalate" and assisted["decision"] != "escalate":
        return finding("review", "Escalation was disputed. An operator must reconcile the evidence.", [anchor])
    return assisted


def full_evidence_reference(anchor, observations, profile):
    """Reference using every check, independently of either model's selection."""
    checks = {check: check_observations(check, anchor, observations, profile) for check in CHECKS}
    for state, decision in (("disputes", "escalate"), ("conflict", "review")):
        for key in ("change_record", "identity_record"):
            if checks[key]["state"] == state:
                return {"decision": decision, "evidence_ids": checks[key]["evidence_ids"],
                        "reason": "The full-evidence rule prioritizes independent evidence."}
    if profile["repeated_privilege_denials"]:
        return finding("review", "The full-evidence rule found repeated denied privilege requests.",
                       [anchor, *denied_attempts(anchor, observations)[:DENIAL_REVIEW_THRESHOLD]])
    if checks["change_record"]["state"] == "supports" and profile["privileged_activity"]:
        return {"decision": "close", "evidence_ids": checks["change_record"]["evidence_ids"],
                "reason": "The full-evidence rule found corroborated maintenance."}
    if checks["activity_record"]["state"] == "disputes" and checks["identity_record"]["state"] != "supports":
        return {"decision": "escalate", "evidence_ids": checks["activity_record"]["evidence_ids"],
                "reason": "The full-evidence rule found repeated failures and privileged activity."}
    return finding("review", "The full-evidence rule needs further context.", [anchor])


def isolated_branches(anchor, scoped, visible, profile, history, *, cross_examine=False, worker_factory=None):
    """Send each role a separate minimized projection, then compare its responses."""
    handles = {event.id: f"E{index}" for index, event in enumerate(visible)}
    undisclosed = [event for event in scoped if event.id not in handles]
    handles.update({event.id: f"V{index}" for index, event in enumerate(undisclosed)})
    fallback = {handle: event_id for event_id, handle in handles.items()}
    anchor_handle = handles[anchor.id]
    origin = datetime.fromisoformat(anchor.timestamp)
    visible_events = [
        {"id": handles[event.id], "kind": event.kind,
         "timestamp": (datetime.fromisoformat(event.timestamp) - origin) // timedelta(microseconds=1)}
        for event in visible
    ]
    red_history = [
        {"initial": item["initial"], "verified": item["verified"], "comparisons": [
            {"check": branch["check"], "decision": branch["decision"]}
            for branch in item.get("comparisons", ())
        ]}
        for item in history
    ]
    blue_history = [
        {"verified": item["verified"], "comparisons": [
            {"check": branch["check"], "state": branch["state"]}
            for branch in item.get("comparisons", ())
        ]}
        for item in history
    ]
    trace = []

    def step(worker, phase, payload):
        already_recovered = worker.recovery_used
        result = worker.call_with_recovery(phase, payload)
        entry = {"role": worker.role, "phase": phase}
        if worker.recovery_used and not already_recovered:
            entry["replaced_worker"] = True
        trace.append(entry)
        return result

    def map_refs(result, mapping):
        try:
            return {**result, "evidence_ids": [mapping[ref] for ref in result["evidence_ids"]]}
        except (KeyError, TypeError) as error:
            raise RoleFailure("Blue returned an evidence reference outside the disclosed projection") from error

    def valid_decision(result):
        if result.get("decision") not in ("review", "close", "escalate"):
            raise RoleFailure("Blue returned an unsupported decision")
        return result

    coarse = {"profile": profile, "history": red_history}
    worker = worker_factory or RoleProcess
    with worker("red") as red, worker("blue") as blue, worker("control") as control:
        forecast = step(red, "forecast", coarse)
        standard = step(control, "select", coarse)
        assessed = step(blue, "assess", {"observations": visible_events, "anchor": anchor_handle, "history": blue_history})
        initial = valid_decision(assessed["initial"])
        initial_map = {item["id"]: fallback[item["id"]] for item in visible_events}
        initial_mapped = map_refs(initial, initial_map)
        if any(chosen not in tuple(CHECKS) for chosen in (forecast.get("check"), standard.get("check"))):
            raise RoleFailure("A role selected a check outside the catalogue")
        if forecast.get("prediction") not in ("review", "close", "escalate", None):
            raise RoleFailure("Red returned an unsupported prediction")
        commitments = None
        if cross_examine:
            red_plan = checked_commitment(step(red, "commit", {}))
            blue_plan = checked_commitment(step(blue, "commit", {}))
            commitments = {
                "without_swap": {"red": red_plan, "blue": blue_plan},
                "with_swap": {
                    "red": checked_commitment(step(red, "switch", {"peer": blue_plan})),
                    "blue": checked_commitment(step(blue, "switch", {"peer": red_plan})),
                },
            }
        standard_result, assisted_result = selected_observations(standard, forecast, anchor, scoped, profile)

        def review(observed):
            allowed = {**initial_map, **{handles[ref]: ref for ref in observed["evidence_ids"]}}
            projection = map_refs(observed, handles)
            decision = valid_decision(step(blue, "reconsider", {"observation": projection}))
            return map_refs(decision, allowed)

        ordinary_review = review(standard_result)
        assisted = ordinary_review if standard_result == assisted_result else review(assisted_result)
        feedback = step(red, "compare", {"actual": initial["decision"], "result": assisted["decision"],
                                         "observation": assisted_result["state"]})

    hypotheses = checked_hypotheses(assessed.get("hypotheses"))
    cross_exam = {}
    if commitments is not None:
        cross_exam = {"cross_examination": {
            branch: evaluate_commitments(plans, initial_mapped, anchor, scoped, profile)
            for branch, plans in commitments.items()
        }}
    return {"forecast": forecast, "initial": initial_mapped, "hypotheses": hypotheses,
            "standard": standard, "standard_result": standard_result, "assisted_result": assisted_result,
            "ordinary_review": ordinary_review, "assisted": assisted,
            "role_runtime": {"mode": "local-processes", "trace": trace, "red_feedback": feedback},
            **cross_exam}


def checked_commitment(value):
    if (not isinstance(value, dict) or set(value) != {"check", "expected_state"}
            or value["check"] not in CROSS_CHECKS or value["expected_state"] not in ("supports", "disputes")):
        raise RoleFailure("Invalid cross-examination commitment")
    return value


def evaluate_commitments(plans, initial, anchor, scoped, profile):
    # Both arms select against the same frozen Blue assessment. An initial
    # escalation needs a test that can support a benign explanation.
    preferred_state = "supports" if initial["decision"] == "escalate" else "disputes"
    role = next((role for role in ("blue", "red") if plans[role]["expected_state"] == preferred_state), "blue")
    selected = plans[role]
    observed = check_observations(selected["check"], anchor, scoped, profile)
    return {
        "commitments": plans, "selected_role": role, "observation": observed,
        "forecast_matched": (selected["expected_state"] == observed["state"]
                             if observed["state"] in ("supports", "disputes") else None),
        **reconsider(initial, observed, anchor),
    }


def checked_hypotheses(value):
    if not isinstance(value, dict) or set(value) != {"legitimate", "security"}:
        raise RoleFailure("Blue returned invalid hypotheses")
    for hypothesis in value.values():
        if not isinstance(hypothesis, dict) or set(hypothesis) != {"description", "expectations"}:
            raise RoleFailure("Blue returned invalid hypothesis fields")
        expectations = hypothesis["expectations"]
        if not isinstance(expectations, dict) or set(expectations) != set(CHECKS) or any(
            state not in ("supports", "disputes", "unknown") for state in expectations.values()
        ):
            raise RoleFailure("Blue returned invalid check expectations")
    return value


def selected_observations(standard, challenger, anchor, scoped, profile):
    standard_choice_id = standard["check"]
    ordinary = check_observations(standard_choice_id, anchor, scoped, profile)
    selected = challenger["check"]
    assisted = ordinary if selected == standard_choice_id else check_observations(selected, anchor, scoped, profile)
    return ordinary, assisted


def external_branches(anchor, scoped, visible, profile, history, model):
    from .agents import model_review

    forecast = model_review("mimic_forecast", model, anchor, visible, history, profile=profile)
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
    standard_result, assisted_result = selected_observations(standard, forecast, anchor, scoped, profile)
    return {"forecast": forecast, "initial": initial, "hypotheses": hypotheses, "standard": standard,
            "standard_result": standard_result, "assisted_result": assisted_result,
            "ordinary_review": reconsider(initial, standard_result, anchor),
            "assisted": reconsider(initial, assisted_result, anchor), "role_runtime": {"mode": "external-model"}}


def mimic(anchor, events, history=(), model=None, *, verified=None, session_scope=None, cross_examine=False, worker_factory=None):
    """Freeze both perspectives before either branch receives any verification."""
    if model and cross_examine:
        raise ValueError("Experimental role switching requires offline workers")
    scoped = relevant(anchor, events)
    provenance = None
    if verified is not None:
        provenance = {
            "verified": {event.id: verified[event.id] for event in scoped
                         if event.kind in RESTRICTED_KINDS and event.id in verified},
            "unverified": [event.id for event in scoped if event.kind in RESTRICTED_KINDS and event.id not in verified],
        }
        scoped = [event for event in scoped if event.kind not in RESTRICTED_KINDS or event.id in verified]
    if session_scope is not None:
        scoped = attributed_events(anchor, scoped, session_scope)
    visible = [event for event in scoped if event.kind not in RESTRICTED_KINDS]
    profile = observation_profile(anchor, visible)
    branches = (external_branches(anchor, scoped, visible, profile, history, model) if model
                else isolated_branches(anchor, scoped, visible, profile, history, cross_examine=cross_examine,
                                       worker_factory=worker_factory))
    challenger, initial = branches["forecast"], branches["initial"]
    hypotheses = branches["hypotheses"]
    observed = branches["assisted_result"]
    assisted = branches["assisted"]
    matches = {role: hypothesis["expectations"][observed["check"]] == observed["state"]
               for role, hypothesis in hypotheses.items()} if observed["state"] in {"supports", "disputes"} else {}
    recommendation = operational_policy(anchor, scoped, profile, initial, assisted)
    if session_scope is not None and recommendation["decision"] == "close" and not profile["privileged_activity"]:
        recommendation = finding("review", "Closure requires privilege activity attributed to the same SSH session.", [anchor])
    return {
        "engine_version": "0.7",
        "provenance": provenance,
        "session_attribution": session_scope,
        "host": anchor.host,
        "anchor_id": anchor.id,
        "events": records(events),
        "forecast": challenger,
        "prediction_matched": challenger["prediction"] == initial["decision"] if challenger["prediction"] is not None else None,
        "blue": initial,
        "initial_hypotheses": {role: hypothesis["description"] for role, hypothesis in hypotheses.items()},
        "standard_review": branches["ordinary_review"],
        "assisted": assisted,
        "recommendation": recommendation,
        "full_evidence_reference": full_evidence_reference(anchor, scoped, profile),
        "history_used": list(history),
        "role_runtime": branches["role_runtime"],
        **({"cross_examination": branches["cross_examination"]} if cross_examine else {}),
        "mimicry": {
            "hypotheses": hypotheses,
            "standard_reviewer": branches["standard"],
            "standard_observation": branches["standard_result"],
            "assisted_observation": observed,
            "hypothesis_matches": matches,
            "checks_per_branch": 1,
        },
    }
