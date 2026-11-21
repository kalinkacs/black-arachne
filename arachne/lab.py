"""Inert synthetic fixtures with labels kept outside the reasoning path."""

from .events import Event
from .reasoning import investigate, role_investigation
from .store import episode, ingest, save_run


def fixture(name, kind, minute, source="simulation"):
    return Event.parse({
        "id": f"lab-{name}-{minute:02d}-{kind}", "host": f"lab-{name}",
        "kind": kind, "timestamp": f"2026-01-01T12:{minute:02d}:00Z",
        "actor": "operator", "source": source,
    })


def scenarios():
    for name, expected, kinds in (
        ("approved", "close", [("deployment", 9), ("ssh_login", 10), ("privileged_activity", 11), ("change_verified", 12)]),
        ("unverified", "review", [("deployment", 9), ("ssh_login", 10), ("privileged_activity", 11)]),
        ("repeated-failures", "escalate", [("ssh_failure", 6), ("ssh_failure", 7), ("ssh_failure", 8), ("ssh_login", 10), ("privileged_activity", 11)]),
        ("partial", "review", [("ssh_login", 10)]),
        ("misleading-change", "escalate", [("ssh_failure", 5), ("ssh_failure", 6), ("ssh_failure", 7), ("deployment", 8), ("ssh_login", 10), ("privileged_activity", 11)]),
    ):
        events = [
            fixture(name, kind, minute, "change-management" if kind == "change_verified" else "simulation")
            for kind, minute in kinds
        ]
        yield name, expected, events


def run_lab(connection, model=None):
    scores = {"blue": 0, "standard_review": 0, "assisted": 0}
    cases = []
    for name, expected, events in scenarios():
        ingest(connection, events)
        login = next(event for event in events if event.kind == "ssh_login")
        anchor, evidence = episode(connection, login.host, login.id)
        report = role_investigation(anchor, evidence, model) if model else investigate(anchor, evidence)
        for variant in scores:
            scores[variant] += int(report[variant]["decision"] == expected)
        run = save_run(connection, {**report, "label": expected, "scenario": name})
        cases.append(run["id"])
    return {"correct": scores, "total": len(cases), "runs": cases, "evaluation": "synthetic smoke cases"}
