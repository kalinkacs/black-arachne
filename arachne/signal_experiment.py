"""Compare independent and role-switched proposals on withheld evidence."""

from collections import Counter
from hashlib import sha256
from types import SimpleNamespace

from .agents import request_result
from .events import encode, observation_profile
from .measurement import ASSURANCES, MEASUREMENTS, checked_focus, measurement
from .observability import MAX_EXAMPLES, find_witnesses, read_episodes, read_holdout
from .role_runtime import RoleProcess


VARIANTS = ("fixed", "single_agent", "two_without_switch", "role_switch")
CATALOGUE = ("identity_record", "change_record", *(item.identifier for item in MEASUREMENTS.values()))
PROPOSAL_SCHEMA = {
    "primary": {"type": "string", "enum": list(ASSURANCES)},
    "secondary": {"type": ["string", "null"], "enum": [*ASSURANCES, None]},
}


def blind_profile(visible):
    events = [SimpleNamespace(timestamp=timestamp, kind=kind) for timestamp, kind, _ in visible]
    return tuple(sorted(observation_profile(SimpleNamespace(timestamp=0), events).items()))


def model_proposals(profile, model):
    def ask(perspective, own=None, peer=None):
        payload = {"profile": profile, "perspective": perspective}
        instructions = (
            "You are proposing a read-only defensive evidence requirement in an SSH lab. "
            "Choose identity, change authorization, or privilege authorization. A second assurance means "
            "an independently recorded binding between the two claims. Use only the four observable flags. "
            "Infer no actual result. "
        )
        if own is None:
            instructions += "Commit to one primary claim and return null for secondary."
        elif peer is None:
            payload["previous_proposal"] = own
            instructions += "Reconsider your own proposition from the same perspective. You may combine two assurances."
        else:
            payload.update(previous_proposal=own, borrowed_proposal=peer)
            instructions += (
                "Adopt the borrowed proposition as primary and argue from the assigned new perspective. "
                "Add a second assurance only if it would clarify what the borrowed claim leaves open."
            )
        answer = request_result(model, "evidence_proposal", PROPOSAL_SCHEMA, instructions, payload)
        return checked_focus(answer, first=own is None, adopted=peer)

    blue = ask("legitimate")
    red = ask("security")
    solo = ask("legitimate")
    return {
        "before": {"blue": blue, "red": red},
        "after": {"blue": ask("security", blue["primary"], red["primary"]),
                  "red": ask("legitimate", red["primary"], blue["primary"])},
        "solo": ask("legitimate", solo["primary"]),
    }


def switched_proposals(profile, red_focus=None, blue_focus=None):
    with RoleProcess("blue") as blue, RoleProcess("red") as red:
        first_blue = checked_focus(
            blue.call_with_recovery("signal_initial", {"profile": profile, "focus": blue_focus}), first=True
        )
        first_red = checked_focus(
            red.call_with_recovery("signal_initial", {"profile": profile, "focus": red_focus}), first=True
        )
        return {
            "before": {"blue": first_blue, "red": first_red},
            "after": {
                "blue": checked_focus(blue.call_with_recovery("signal_reframe", {"peer": first_red}),
                                      adopted=first_red["primary"]),
                "red": checked_focus(red.call_with_recovery("signal_reframe", {"peer": first_blue}),
                                     adopted=first_blue["primary"]),
            },
        }


def solo_proposal(profile):
    with RoleProcess("blue") as solo:
        checked_focus(solo.call_with_recovery("signal_initial", {"profile": profile}), first=True)
        return checked_focus(solo.call_with_recovery("signal_reframe", {"peer": None}))


def local_proposals(profile):
    return {**switched_proposals(profile), "solo": solo_proposal(profile)}


def result_state(witness, source):
    observed = (witness.close.states.get(source), witness.escalate.states.get(source))
    if observed == ("supports", "disputes"):
        return "distinguished"
    if observed == ("disputes", "supports"):
        return "reversed"
    return "unresolved"


def run_signal_experiment(discovery_stream, holdout_stream, model=None):
    discovery, _ = read_episodes(discovery_stream)
    unseen = read_holdout(holdout_stream, discovery)
    calibration = find_witnesses(discovery, CATALOGUE)
    if not calibration:
        raise ValueError("Discovery needs a pair of indistinguishable episodes with different outcomes")
    score = {source: Counter(result_state(pair, source) for pair in calibration) for source in CATALOGUE}

    def best(candidates):
        return max(candidates, key=lambda source: (score[source]["distinguished"], -score[source]["reversed"]))

    fixed = best(CATALOGUE)
    plans = {}
    # Plan on every distinct holdout profile before matching opposite labels.
    # Workers receive only these flags, even when a profile has no pair.
    for view in sorted({blind_profile(episode.visible) for episode in unseen}):
        profile = dict(view)
        proposals = model_proposals(profile, model) if model else local_proposals(profile)
        plans[view] = {
            "visible": profile,
            "proposals": proposals,
            "selected": {
                "fixed": fixed,
                "single_agent": measurement(proposals["solo"]).identifier,
                "two_without_switch": best([measurement(proposal).identifier
                                            for proposal in proposals["before"].values()]),
                "role_switch": best([measurement(proposal).identifier for proposal in proposals["after"].values()]),
            },
        }
    commitments = list(plans.values())
    digest = sha256(encode(commitments).encode()).hexdigest()
    witnesses = find_witnesses(unseen, CATALOGUE)
    if not witnesses:
        raise ValueError("Holdout needs a pair of indistinguishable episodes with different outcomes")

    results = {variant: Counter({"distinguished": 0, "reversed": 0, "unresolved": 0}) for variant in VARIANTS}
    paired = {variant: Counter({"role_switch_only": 0, "comparator_only": 0}) for variant in VARIANTS[:-1]}
    examples = []
    for witness in witnesses:
        plan = plans[blind_profile(witness.close.visible)]["selected"]
        states = {variant: result_state(witness, source) for variant, source in plan.items()}
        if len(examples) < MAX_EXAMPLES:
            examples.append({
                "close_case": witness.close.identifier,
                "escalate_case": witness.escalate.identifier,
                "selected": plan,
                "results": states,
            })
        for variant, state in states.items():
            results[variant][state] += 1
        switched = states["role_switch"] == "distinguished"
        for variant, counts in paired.items():
            other = states[variant] == "distinguished"
            counts["role_switch_only"] += switched and not other
            counts["comparator_only"] += other and not switched

    return {
        "backend": model or "local-processes",
        "readings_per_pair_per_variant": 1,
        "discovery_pairs": len(calibration),
        "holdout_pairs": len(witnesses),
        "requirements": {item.identifier: item.requirement for item in MEASUREMENTS.values()},
        "fixed_source_scored_on_discovery": fixed,
        "plans_sha256_before_scoring": digest,
        "plans": commitments,
        "holdout": results,
        "paired": paired,
        "examples": examples,
        "omitted_examples": len(witnesses) - len(examples),
    }
