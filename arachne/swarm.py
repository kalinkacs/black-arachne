"""Offline stress replay. Labels are retained by the scorer, outside the worker inputs."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from time import perf_counter

from .evaluation import parse_case
from .events import Event, read_records
from .mimicry import RESTRICTED_KINDS, mimic
from .role_runtime import RoleFailure, RoleProcess


@dataclass(frozen=True)
class Assignment:
    anchor: Event
    observations: tuple[Event, ...]
    delayed: tuple[Event, ...]
    degraded: bool
    interrupt_role: str | None
    interruptions: int


@dataclass(frozen=True)
class Handoff:
    anchor_id: str
    requested_sources: tuple[str, ...]
    reason: str
    priority: int


def workload(stream, copies):
    cases = [(row["expected"], *parse_case(row)) for row in read_records(stream)]
    if not cases:
        raise ValueError("Swarm trial input contains no cases")
    assignments, labels = [], {}
    for host_index in range(copies):
        host = f"replay-{host_index + 1:03}"
        for index, (expected, anchor, events) in enumerate(cases):
            prefix = f"{host}-{index}-"
            projection = tuple(replace(event, id=prefix + event.id, host=host) for event in events)
            login = next(event for event in projection if event.id == prefix + anchor.id)
            # One cohort sees all configured sources. Two see delayed records and
            # one loses the verification feed for the whole replay.
            cohort = (index + host_index) % 4
            withheld = tuple(event for event in projection if event.kind in RESTRICTED_KINDS)
            visible = projection if cohort == 0 else tuple(event for event in projection if event not in withheld)
            delayed = withheld if cohort in (1, 2) else ()
            clock = datetime.fromisoformat(login.timestamp)
            noise = tuple(
                replace(login, id=f"{prefix}noise-{n}", actor=f"unrelated-{n % 8}",
                        timestamp=(clock + timedelta(seconds=n + 1)).isoformat(timespec="microseconds"),
                        kind="privilege_denial_unverified")
                for n in range(32)
            )
            serial = len(assignments)
            interruption = ("blue", "red", "control")[(serial // 7) % 3] if serial % 7 == 0 else None
            assignments.append(Assignment(login, tuple(sorted((*visible, *noise), key=order)),
                                          delayed, cohort != 0, interruption,
                                          (2 if serial % 28 == 0 else 1) if interruption else 0))
            labels[login.id] = expected
    return assignments, labels


def order(event):
    return event.timestamp, event.id


def inspect_case(item, observations, *, inject_failure=False):
    remaining = item.interruptions if inject_failure else 0

    class ReplayWorker(RoleProcess):
        def _exchange(self, phase, payload, deadline):
            nonlocal remaining
            affected_phase = {"red": "compare", "blue": "reconsider", "control": "select"}
            if remaining and self.role == item.interrupt_role and phase == affected_phase.get(self.role):
                remaining -= 1
                self.process.kill()
                self.process.wait(timeout=2)
            return super()._exchange(phase, payload, deadline)

    try:
        return mimic(item.anchor, observations, worker_factory=ReplayWorker if remaining else None)
    except RoleFailure:
        return None


def initial_review(item):
    report = inspect_case(item, item.observations, inject_failure=True)
    if report is None:
        return "review", 0, Handoff(item.anchor.id, ("identity-management", "change-management"),
                                    "worker_interrupted", 3)
    decision = report["recommendation"]["decision"]
    replaced = sum(bool(row.get("replaced_worker")) for row in report["role_runtime"]["trace"])
    if decision != "review" or not item.degraded:
        return decision, replaced, None
    checks = report["mimicry"]
    needed = {
        observation["check"]
        for observation in (checks["standard_observation"], checks["assisted_observation"])
        if observation["state"] == "unknown"
    }
    mapping = {"identity_record": "identity-management", "change_record": "change-management"}
    sources = tuple(sorted({mapping[check] for check in needed if check in mapping}))
    if not sources:
        return decision, replaced, None
    risk = any(event.kind == "privileged_activity" and event.actor == item.anchor.actor
               for event in item.observations)
    return decision, replaced, Handoff(item.anchor.id, sources, "verification_feed_degraded", 2 if risk else 1)


def follow_up(item, message):
    if message.anchor_id != item.anchor.id:
        raise ValueError("Follow-up does not match its SSH session")
    evidence = tuple(event for event in item.delayed if event.source in message.requested_sources)
    if not evidence and message.reason != "worker_interrupted":
        return "review", False
    report = inspect_case(item, tuple(sorted((*item.observations, *evidence), key=order)))
    decision = report["recommendation"]["decision"] if report is not None else "review"
    # A reply to one evidence request does not restore missing coverage.
    if item.degraded and decision == "close":
        decision = "review"
    return decision, bool(evidence)


def score(decisions, labels):
    pairs = [(labels[anchor], decision) for anchor, decision in decisions.items()]
    return {
        "correct": sum(expected == decision for expected, decision in pairs),
        "missed_escalations": sum(expected == "escalate" and decision != expected for expected, decision in pairs),
        "false_escalations": sum(expected != "escalate" and decision == "escalate" for expected, decision in pairs),
        "false_closures": sum(expected != "close" and decision == "close" for expected, decision in pairs),
        "manual_review": sum(decision == "review" for _, decision in pairs),
    }


def run_configuration(assignments, labels, teams, budget):
    started = perf_counter()
    with ThreadPoolExecutor(max_workers=teams) as investigators:
        results = list(investigators.map(initial_review, assignments))
    preliminary = {item.anchor.id: decision for item, (decision, _, _) in zip(assignments, results)}
    queue = sorted(
        ((message, item) for item, (_, _, message) in zip(assignments, results) if message is not None),
        key=lambda pair: (-pair[0].priority, pair[0].anchor_id),
    )
    dispatched = queue[:budget]
    with ThreadPoolExecutor(max_workers=teams) as reviewers:
        checked = list(reviewers.map(lambda pair: follow_up(pair[1], pair[0]), dispatched))
    resolved = dict(preliminary)
    for (message, _), (decision, _) in zip(dispatched, checked):
        resolved[message.anchor_id] = decision
    return {
        "teams": teams,
        "role_process_limit": teams * 3,
        "elapsed_seconds": round(perf_counter() - started, 3),
        "replaced_workers": sum(replaced for _, replaced, _ in results),
        "handoffs": len(queue),
        "dispatched": len(dispatched),
        "deferred_handoffs": len(queue) - len(dispatched),
        "worker_failure_handoffs": sum(message.reason == "worker_interrupted" for message, _ in dispatched),
        "evidence_delivered": sum(delivered for _, delivered in checked),
        "changed_decisions": sum(resolved[key] != value for key, value in preliminary.items()),
        "before_handoffs": score(preliminary, labels),
        "after_handoffs": score(resolved, labels),
    }


def benchmark_swarm(stream, copies, team_sizes, budget):
    assignments, labels = workload(stream, copies)
    return {
        "hosts": copies,
        "incidents": len(assignments),
        "events": sum(len(item.observations) + len(item.delayed) for item in assignments),
        "expected_escalations": sum(expected == "escalate" for expected in labels.values()),
        "forced_interruptions": sum(item.interruptions for item in assignments),
        "follow_up_budget": budget,
        "configurations": [run_configuration(assignments, labels, teams, budget) for teams in team_sizes],
    }
