"""Replay a three-team defensive rotation with a bounded pool of role workers."""

from contextlib import ExitStack
from itertools import cycle, product

from .evolution import merit, scores
from .measurement import MEASUREMENTS, checked_focus, measurement
from .observability import find_witnesses, read_episodes, read_holdout
from .role_runtime import RoleFailure, RoleProcess, RoleTransportFailure
from .signal_experiment import CATALOGUE, blind_profile, solo_proposal, switched_proposals

ROTATION = (
    {"red": "A", "blue": "B", "control": "C"},
    {"red": "B", "blue": "C", "control": "A"},
    {"red": "C", "blue": "A", "control": "B"},
)
SOURCES = tuple(item.identifier for item in MEASUREMENTS.values())


def rotate(profile, ranking, interrupted_role=None, interrupted_round=1, *, eligible=None):
    trace = []
    inherited = {}
    previous = None
    stopped = 0

    def start(worker, focus):
        return checked_focus(worker.call_with_recovery("signal_initial", {"profile": profile, "focus": focus}),
                             first=True)

    def reframe(worker, peer):
        return checked_focus(worker.call_with_recovery("signal_reframe", {"peer": peer}), adopted=peer["primary"])

    for number, teams in enumerate(ROTATION, 1):
        class InterruptedRole(RoleProcess):
            def _exchange(self, phase, payload, deadline):
                nonlocal stopped
                if number == interrupted_round and self.role == interrupted_role and phase == "signal_reframe" and stopped < 2:
                    self.process.kill()
                    self.process.wait(timeout=2)
                    stopped += 1
                return super()._exchange(phase, payload, deadline)

        with ExitStack() as stack:
            workers = {role: stack.enter_context(InterruptedRole(role)) for role in teams}
            frozen = {role: start(workers[role], inherited.get(role)) for role in ("red", "blue")}
            proposals, options = {}, {}
            handoffs = []

            def propose(role, worker, peer):
                proposals[role] = reframe(worker, peer)
                if eligible is not None:
                    options[role] = worker.call_with_recovery("signal_options", {})["sources"]

            for role, other in (("red", "blue"), ("blue", "red")):
                try:
                    propose(role, workers[role], frozen[other])
                except RoleTransportFailure:
                    workers[role].__exit__()
                    # The reviewer takes the vacant slot and repeats only the
                    # stopped role's frozen proposal before receiving peer data.
                    with RoleProcess(role) as replacement:
                        if start(replacement, inherited.get(role)) != frozen[role]:
                            raise RoleFailure("Handoff changed the frozen proposal")
                        propose(role, replacement, frozen[other])
                    handoffs.append({"from": teams[role], "to": teams["control"], "role": role})
            request = {"proposals": proposals, "ranking": ranking, "previous": previous}
            offered = {measurement(item).identifier for item in proposals.values()}
            allowed = offered
            if eligible is not None:
                request.update(eligible=eligible, options=options)
                allowed = set(eligible) if eligible else {None}
            result = workers["control"].call_with_recovery("signal_judge", request)
            if "source" not in result or result["source"] not in allowed:
                raise RoleFailure("Reviewer selected a source outside the allowed evidence catalogue")
            previous = result["source"]
            inherited = {role: proposal["primary"] for role, proposal in proposals.items()}
            entry = {"round": number, "teams": teams, "inherited": inherited,
                     "chosen_source": previous, "handoffs": handoffs}
            if eligible is not None:
                entry.update(options=options, outside_first_proposals=previous is not None and previous not in offered)
            trace.append(entry)
    return previous, trace, stopped


def run_rotation_trial(discovery_stream, holdout_stream):
    discovery, _ = read_episodes(discovery_stream)
    calibration = find_witnesses(discovery, CATALOGUE)
    if not calibration:
        raise ValueError("Discovery needs indistinguishable cases with opposite outcomes")
    views = {blind_profile(pair.close.visible) for pair in calibration}
    calibration_scores = {source: scores(calibration, dict.fromkeys(views, source)) for source in SOURCES}
    ranked = sorted(SOURCES, key=lambda source: merit(calibration_scores[source]), reverse=True)
    eligible = [source for source in ranked
                if calibration_scores[source]["distinguished"] and not calibration_scores[source]["reversed"]]
    holdout = read_holdout(holdout_stream, discovery)
    holdout_views = sorted({blind_profile(episode.visible) for episode in holdout})
    plans = {name: {} for name in ("solo", "pair", "rotation", "rotation_after_loss",
                                   "open_catalogue", "open_catalogue_after_loss")}
    representative = open_example = None
    outside = abstained = open_recovered = 0
    fault_cases = cycle(product(range(1, len(ROTATION) + 1), ("red", "blue")))
    handoffs = stops = unchanged = 0
    for view in holdout_views:
        profile = dict(view)
        plans["solo"][view] = measurement(solo_proposal(profile)).identifier
        pair = switched_proposals(profile)["after"]
        plans["pair"][view] = min((measurement(item).identifier for item in pair.values()), key=ranked.index)
        clean, _, _ = rotate(profile, ranked)
        round_number, role = next(fault_cases)
        recovered, trace, killed = rotate(profile, ranked, interrupted_role=role, interrupted_round=round_number)
        open_plan, _, _ = rotate(profile, ranked, eligible=eligible)
        open_after, open_trace, _ = rotate(profile, ranked, interrupted_role=role,
                                           interrupted_round=round_number, eligible=eligible)
        if representative is None:
            representative, open_example = trace, open_trace
        plans["open_catalogue"][view] = open_plan
        plans["open_catalogue_after_loss"][view] = open_after
        open_recovered += open_after == open_plan
        outside += open_trace[-1]["outside_first_proposals"]
        abstained += open_plan is None
        handoffs += sum(len(item["handoffs"]) for item in trace)
        stops += killed
        unchanged += recovered == clean
        plans["rotation"][view] = clean
        plans["rotation_after_loss"][view] = recovered

    witnesses = find_witnesses(holdout, CATALOGUE)
    if not witnesses:
        raise ValueError("Holdout needs indistinguishable cases with opposite outcomes")
    return {
        "profiles": len(holdout_views), "holdout_pairs": len(witnesses),
        "reads_per_pair_per_variant": 1, "max_simultaneous_workers": 3,
        "forced_worker_stops": stops, "cross_team_handoffs": handoffs,
        "unchanged_plans_after_handoff": unchanged,
        "holdout": {name: scores(witnesses, selected) for name, selected in plans.items()},
        "example_rotation": representative,
        "open_catalogue": {"size": len(SOURCES), "eligible": eligible, "profiles_outside_first_proposals": outside,
                           "profiles_with_no_selection": abstained, "unchanged_plans_after_handoff": open_recovered,
                           "example_rotation": open_example},
    }
