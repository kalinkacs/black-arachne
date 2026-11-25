"""Paired defensive replay under bounded process and evidence-source failures."""

from collections import Counter

from .evolution import merit, scores
from .measurement import checked_focus, measurement
from .observability import find_witnesses, read_episodes, read_holdout
from .role_runtime import RoleProcess, RoleTransportFailure
from .signal_experiment import CATALOGUE, blind_profile, result_state

SCENARIOS = (
    ("healthy", 0, ()),
    ("single_crash", 1, ()),
    ("replacement_crash", 2, ()),
    ("replacement_crash_and_source_delay", 2, ("identity_change_session",)),
)


def compare_profile(profile, best_source, *, failures, paired):
    stopped = 0

    class InterruptedBlue(RoleProcess):
        def _exchange(self, phase, payload, deadline):
            nonlocal stopped
            if phase == "signal_reframe" and stopped < failures:
                self.process.kill()
                self.process.wait(timeout=2)
                stopped += 1
            return super()._exchange(phase, payload, deadline)

    def initial(worker):
        return checked_focus(worker.call_with_recovery("signal_initial", {"profile": profile}), first=True)

    def finish(worker, target):
        response = worker.call_with_recovery("signal_reframe", {"peer": target})
        return checked_focus(response, adopted=target["primary"] if target else None)

    with InterruptedBlue("blue") as blue:
        own = initial(blue)
        if paired:
            with RoleProcess("red") as red:
                peer = initial(red)
                try:
                    blue_result = finish(blue, peer)
                except RoleTransportFailure:
                    proposals = [finish(red, own)]
                    method = "peer_handoff"
                else:
                    proposals = [blue_result, finish(red, own)]
                    method = "complete"
        else:
            try:
                proposals = [finish(blue, None)]
                method = "complete"
            except RoleTransportFailure:
                # The coordinator keeps the solo worker's committed first proposal.
                proposals = [own]
                method = "first_commitment"
    return best_source([measurement(item).identifier for item in proposals]), method, stopped


def run_failure_trial(discovery_stream, holdout_stream):
    discovery, _ = read_episodes(discovery_stream)
    calibration = find_witnesses(discovery, CATALOGUE)
    if not calibration:
        raise ValueError("Discovery needs indistinguishable cases with opposite outcomes")
    calibration_views = {blind_profile(pair.close.visible) for pair in calibration}
    ranking = {source: merit(scores(calibration, dict.fromkeys(calibration_views, source)))
               for source in CATALOGUE}

    def best_source(candidates):
        return max(candidates, key=ranking.__getitem__)

    holdout = read_holdout(holdout_stream, discovery)
    views = sorted({blind_profile(episode.visible) for episode in holdout})
    # Freeze all plans before the held-out witness outcomes are classified.
    plans = {}
    process_outcomes = {}
    for scenario, failures, delayed in SCENARIOS:
        plans[scenario] = {}
        process_outcomes[scenario] = {}
        for label, paired in (("solo", False), ("red_blue", True)):
            selections = {view: compare_profile(dict(view), best_source, failures=failures, paired=paired)
                          for view in views}
            plans[scenario][label] = {view: value[0] for view, value in selections.items()}
            process_outcomes[scenario][label] = {
                "forced_stops": sum(value[2] for value in selections.values()),
                "methods_by_profile": dict(Counter(value[1] for value in selections.values())),
                "delayed_sources": list(delayed),
            }
    witnesses = find_witnesses(holdout, CATALOGUE)
    if not witnesses:
        raise ValueError("Holdout needs indistinguishable cases with opposite outcomes")
    results = {}
    for scenario, _, delayed in SCENARIOS:
        results[scenario] = {}
        for label, selection in plans[scenario].items():
            counts = Counter({"distinguished": 0, "reversed": 0, "unresolved": 0})
            for pair in witnesses:
                source = selection[blind_profile(pair.close.visible)]
                counts["unresolved" if source in delayed else result_state(pair, source)] += 1
            results[scenario][label] = {**process_outcomes[scenario][label], "decisions": dict(counts)}
    return {"holdout_pairs": len(witnesses), "profiles": len(views), "reads_per_pair_per_variant": 1,
            "replacements_per_worker": 1, "scenarios": results}
