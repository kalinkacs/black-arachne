"""Offline selection of bounded, role-switched defensive evidence strategies."""

from collections import Counter
from dataclasses import asdict, dataclass, replace
from functools import lru_cache
from hashlib import sha256
from itertools import product

from .events import encode
from .measurement import ASSURANCES, measurement
from .observability import find_witnesses, read_episodes, read_holdout
from .signal_experiment import CATALOGUE, blind_profile, result_state, solo_proposal, switched_proposals


@dataclass(frozen=True)
class Strategy:
    red_focus: str | None = None
    blue_focus: str | None = None
    selector: str = "calibration"


def descendants(parent, *, explore_pairs=False):
    yield parent
    if explore_pairs:
        for red, blue in product((None, *ASSURANCES), repeat=2):
            if red != parent.red_focus and blue != parent.blue_focus:
                yield replace(parent, red_focus=red, blue_focus=blue)
    for focus in (None, *ASSURANCES):
        if focus != parent.red_focus:
            yield replace(parent, red_focus=focus)
        if focus != parent.blue_focus:
            yield replace(parent, blue_focus=focus)
    for selector in ("calibration", "red", "blue"):
        if selector != parent.selector:
            yield replace(parent, selector=selector)


def scores(witnesses, plan):
    counts = Counter({"distinguished": 0, "reversed": 0, "unresolved": 0})
    for witness in witnesses:
        source = plan[blind_profile(witness.close.visible)]
        counts[result_state(witness, source)] += 1
    return dict(counts)


def merit(counts):
    # An inverted conclusion is worse than deferring judgement.
    return -counts["reversed"], counts["distinguished"]


def evolve_signals(discovery_stream, holdout_stream, generations):
    if not 1 <= generations <= 5:
        raise ValueError("Expected 1–5 local selection generations")
    discovery, _ = read_episodes(discovery_stream)
    calibration = find_witnesses(discovery, CATALOGUE)
    if not calibration:
        raise ValueError("Discovery needs indistinguishable cases with opposite outcomes")

    calibration_views = sorted({blind_profile(pair.close.visible) for pair in calibration})
    source_scores = {
        source: merit(scores(calibration, dict.fromkeys(calibration_views, source)))
        for source in CATALOGUE
    }

    @lru_cache(maxsize=256)
    def proposals(view, red_focus, blue_focus):
        return switched_proposals(dict(view), red_focus, blue_focus)["after"]

    def plan(strategy, views):
        chosen = {}
        for view in views:
            roles = proposals(view, strategy.red_focus, strategy.blue_focus)
            sources = {role: measurement(focus).identifier for role, focus in roles.items()}
            chosen[view] = (
                max(sources.values(), key=source_scores.__getitem__)
                if strategy.selector == "calibration" else sources[strategy.selector]
            )
        return chosen

    champion = Strategy()
    rounds = []
    for generation in range(1, generations + 1):
        previous = champion
        candidates = [(strategy, scores(calibration, plan(strategy, calibration_views)))
                      for strategy in descendants(champion, explore_pairs=generation == 2)]
        # The parent is first and survives a tie.
        champion, result = max(candidates, key=lambda candidate: merit(candidate[1]))
        rounds.append({"generation": generation, "candidates": len(candidates),
                       "changed": champion != previous, "winner": asdict(champion), "discovery": result})
        if generation >= 2 and champion == previous:
            break

    unseen = read_holdout(holdout_stream, discovery)
    views = sorted({blind_profile(episode.visible) for episode in unseen})
    winner_plan = plan(champion, views)
    solo_plan = {view: measurement(solo_proposal(dict(view))).identifier for view in views}
    original_plan = plan(Strategy(), views)
    commitment = [{"visible": dict(view), "winner": winner_plan[view],
                   "solo": solo_plan[view], "original_pair": original_plan[view]} for view in views]
    digest = sha256(encode(commitment).encode()).hexdigest()
    witnesses = find_witnesses(unseen, CATALOGUE)
    if not witnesses:
        raise ValueError("Holdout needs indistinguishable cases with opposite outcomes")
    report = {name: scores(witnesses, selection) for name, selection in
              (("winner", winner_plan), ("solo", solo_plan), ("original_pair", original_plan))}
    winner, solo, original = report["winner"], report["solo"], report["original_pair"]
    advance = (winner["reversed"] == 0 and winner["distinguished"] > max(solo["distinguished"],
                                                                      original["distinguished"]))
    return {"readings_per_pair_per_variant": 1, "discovery_pairs": len(calibration),
            "holdout_pairs": len(witnesses), "generations": rounds, "winner": asdict(champion),
            "plans_sha256_before_scoring": digest, "holdout": report,
            "eligible_for_next_pilot": advance}
