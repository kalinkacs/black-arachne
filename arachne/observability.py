"""Find and replay defensive coverage gaps in reviewed, offline SSH episodes."""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from hashlib import sha256
from itertools import combinations, product
import re

from .evaluation import parse_case
from .events import encode, observation_profile, read_records
from .mimicry import CHECKS, CROSS_CHECKS, RESTRICTED_KINDS, check_observations
from .reasoning import relevant
from .sessions import attributed_events, attribution

MAX_CASES = 256
MAX_EXAMPLES = 50
MAX_NEW_SOURCES = 6
MAX_CHECKS = len(CROSS_CHECKS) + MAX_NEW_SOURCES
OPPOSITE_STATES = {"supports", "disputes"}
SIGNAL_STATES = OPPOSITE_STATES | {"unknown", "conflict"}
SOURCE_ID = re.compile(r"[a-z][a-z0-9_]{0,39}")


@dataclass(frozen=True)
class Episode:
    identifier: str
    family: str
    expected: str
    visible: tuple
    states: dict


@dataclass(frozen=True)
class Witness:
    projection_digest: str
    close: Episode
    escalate: Episode
    separators: tuple

    def covered(self, checks, required):
        return len(set(checks).intersection(self.separators)) >= required


def read_episodes(stream):
    episodes = {}
    extra_sources = set()
    for record in read_records(stream):
        if len(episodes) == MAX_CASES:
            raise ValueError(f"Observability analysis accepts at most {MAX_CASES} cases per dataset")
        if not isinstance(record, dict):
            raise ValueError("Expected a labeled episode object")
        case = dict(record)
        signals = case.pop("signals", {})
        if not isinstance(signals, dict) or len(signals) > MAX_NEW_SOURCES or any(
            not SOURCE_ID.fullmatch(source) or source in CHECKS or not isinstance(state, str) or state not in SIGNAL_STATES
            for source, state in signals.items()
        ):
            raise ValueError("Invalid experimental signal source or state")
        extra_sources.update(signals)
        if len(extra_sources) > MAX_NEW_SOURCES:
            raise ValueError(f"Observability analysis accepts at most {MAX_NEW_SOURCES} added sources per dataset")
        anchor, events = parse_case(case)
        identifier = case["id"]
        if identifier in episodes:
            raise ValueError(f"Duplicate case identifier: {identifier}")
        scoped = relevant(anchor, events)
        if anchor.session_key:
            # Offline fixtures supply their own verification records per case.
            # This projection does not certify the fixtures or their sources.
            fixtures = {event.id for event in scoped if event.kind in RESTRICTED_KINDS
                        and event.session_key in (None, anchor.session_key)}
            scoped = attributed_events(anchor, scoped, attribution(anchor, scoped, fixtures))
        visible = [event for event in scoped if event.kind not in RESTRICTED_KINDS
                   and event.kind != "privilege_denial_unverified"]
        origin = datetime.fromisoformat(anchor.timestamp)
        projection = tuple(sorted(
            ((datetime.fromisoformat(event.timestamp) - origin) // timedelta(microseconds=1),
             event.kind, event.id == anchor.id)
            for event in visible
        ))
        profile = observation_profile(anchor, visible)
        states = {check: check_observations(check, anchor, scoped, profile)["state"] for check in CROSS_CHECKS}
        episodes[identifier] = Episode(identifier, case["family"], case["expected"], projection, {**states, **signals})
    if not episodes:
        raise ValueError("Observability input contains no cases")
    return list(episodes.values()), (*CROSS_CHECKS, *sorted(extra_sources))


def find_witnesses(episodes, catalogue):
    groups = defaultdict(lambda: {"close": [], "escalate": []})
    for episode in sorted(episodes, key=lambda item: item.identifier):
        if episode.expected != "review":
            groups[episode.visible][episode.expected].append(episode)
    witnesses = []
    for projection, outcomes in sorted(groups.items()):
        digest = sha256(encode(projection).encode()).hexdigest()
        for close, escalate in product(outcomes["close"], outcomes["escalate"]):
            separators = tuple(check for check in catalogue
                               if {close.states.get(check), escalate.states.get(check)} == OPPOSITE_STATES)
            witnesses.append(Witness(digest, close, escalate, separators))
    return witnesses


def coverage(witnesses, checks, required):
    return sum(witness.covered(checks, required) for witness in witnesses)


def summarize(episodes, witnesses, checks, catalogue, required):
    covered = coverage(witnesses, checks, required)
    examples = []
    for witness in witnesses[:MAX_EXAMPLES]:
        examples.append({
            "projection_sha256": witness.projection_digest,
            "close": {"case": witness.close.identifier, "states": witness.close.states},
            "escalate": {"case": witness.escalate.identifier, "states": witness.escalate.states},
            "explicit_separators": witness.separators,
            "covered": witness.covered(checks, required),
        })
    return {
        "cases": len(episodes),
        "review_cases_excluded": sum(episode.expected == "review" for episode in episodes),
        "pairs": len(witnesses),
        "covered": covered,
        "uncovered": len(witnesses) - covered,
        "without_explicit_separator": sum(not witness.separators for witness in witnesses),
        "fixed_single_source": {check: coverage(witnesses, (check,), required) for check in catalogue},
        "covered_after_removing_source": {
            removed: coverage(witnesses, tuple(check for check in checks if check != removed), 1)
            for removed in checks
        },
        "examples": examples,
        "omitted_examples": len(witnesses) - len(examples),
    }


def audit_observability(stream, max_checks=len(CROSS_CHECKS), tolerate_missing=0, *, holdout=None):
    if not 0 <= max_checks <= MAX_CHECKS or tolerate_missing not in (0, 1):
        raise ValueError("Unsupported observability budget")
    episodes, catalogue = read_episodes(stream)
    witnesses = find_witnesses(episodes, catalogue)
    required = tolerate_missing + 1
    candidates = [checks for size in range(max_checks + 1) for checks in combinations(catalogue, size)]
    checks = min(candidates, key=lambda candidate: (-coverage(witnesses, candidate, required), len(candidate), candidate))
    report = {
        "projection": "ssh-event-kind-and-offset-v1",
        "max_checks": max_checks,
        "tolerate_missing": tolerate_missing,
        "candidate_sources": catalogue,
        "selected_checks": checks,
        "discovery": summarize(episodes, witnesses, checks, catalogue, required),
    }
    if holdout is not None:
        unseen, _ = read_episodes(holdout)
        if {episode.family for episode in unseen} & {episode.family for episode in episodes}:
            raise ValueError("Holdout and discovery families must be disjoint")
        if {episode.identifier for episode in unseen} & {episode.identifier for episode in episodes}:
            raise ValueError("Holdout and discovery case identifiers must be disjoint")
        report["holdout"] = summarize(unseen, find_witnesses(unseen, catalogue), checks, catalogue, required)
    return report
