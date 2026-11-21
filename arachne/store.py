"""SQLite persistence, idempotent ingestion and immutable run snapshots."""

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import sqlite3
from uuid import uuid4

from .events import Event, encode, episode_window, records

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY, host TEXT NOT NULL, timestamp TEXT NOT NULL, payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_by_host_time ON events(host, timestamp, id);
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY, created TEXT NOT NULL, payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS runs_by_time ON runs(created DESC, id);
CREATE TABLE IF NOT EXISTS outcomes (
    run_id TEXT PRIMARY KEY REFERENCES runs(id),
    decision TEXT NOT NULL CHECK(decision IN ('close', 'review', 'escalate')),
    note TEXT NOT NULL, created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS collector_state (
    name TEXT PRIMARY KEY, cursor TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS triaged (
    anchor_id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id)
);
"""


@contextmanager
def database(path):
    connection = sqlite3.connect(path, timeout=10)
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.executescript(SCHEMA)
        with connection:
            yield connection
    finally:
        connection.close()


def ingest(connection, events):
    inserted = 0
    for event in events:
        payload = encode(records([event])[0])
        result = connection.execute(
            "INSERT OR IGNORE INTO events VALUES (?, ?, ?, ?)",
            (event.id, event.host, event.timestamp, payload),
        )
        if result.rowcount:
            inserted += 1
        else:
            original, = connection.execute(
                "SELECT payload FROM events WHERE id = ?", (event.id,)
            ).fetchone()
            if original != payload:
                raise ValueError(f"Conflicting evidence id: {event.id}")
    return inserted


def episode(connection, host, anchor_id):
    row = connection.execute(
        "SELECT payload FROM events WHERE host = ? AND id = ?", (host, anchor_id)
    ).fetchone()
    if not row:
        raise ValueError("Anchor event is missing")
    anchor = Event.parse(json.loads(row[0]))
    if anchor.kind != "ssh_login":
        raise ValueError("The anchor must be an SSH login")
    lower, upper = episode_window(anchor)
    rows = connection.execute(
        """SELECT payload FROM events WHERE host = ? AND timestamp BETWEEN ? AND ?
           ORDER BY timestamp, id LIMIT 1001""",
        (host, lower, upper),
    ).fetchall()
    if len(rows) > 1000:
        raise ValueError("More than 1000 observations in the investigation window")
    return anchor, [Event.parse(json.loads(row[0])) for row in rows]


def save_run(connection, report):
    run = {**report, "id": uuid4().hex, "created": datetime.now(timezone.utc).isoformat()}
    connection.execute("INSERT INTO runs VALUES (?, ?, ?)", (run["id"], run["created"], encode(run)))
    return run


def list_runs(connection):
    rows = connection.execute("SELECT payload FROM runs ORDER BY created DESC, id LIMIT 100")
    return [json.loads(row[0]) for row in rows]


def get_run(connection, run_id):
    row = connection.execute("SELECT payload FROM runs WHERE id = ?", (run_id,)).fetchone()
    return json.loads(row[0]) if row else None


def confirm_outcome(connection, run_id, decision, note):
    if decision not in {"close", "review", "escalate"}:
        raise ValueError("Invalid verified decision")
    if not note.strip() or len(note) > 2000:
        raise ValueError("Provide a verification note of 1–2000 characters")
    report = get_run(connection, run_id)
    if not report:
        raise ValueError("Run does not exist")
    if "scenario" in report:
        raise ValueError("Synthetic outcomes are excluded from analyst memory")
    connection.execute(
        "INSERT INTO outcomes VALUES (?, ?, ?, ?)",
        (run_id, decision, note.strip(), datetime.now(timezone.utc).isoformat()),
    )


def evidence_profile(anchor, events):
    relevant = [event for event in events if event.host == anchor.host and event.actor == anchor.actor]
    return (
        any(event.kind == "deployment" and event.timestamp <= anchor.timestamp for event in relevant),
        sum(event.kind == "ssh_failure" and event.timestamp <= anchor.timestamp for event in relevant) >= 3,
        any(event.kind == "privileged_activity" and event.timestamp >= anchor.timestamp for event in relevant),
    )


def confirmed_history(connection, anchor, events):
    current = evidence_profile(anchor, events)
    rows = connection.execute(
        """SELECT r.payload, o.decision FROM outcomes o JOIN runs r ON r.id = o.run_id
           WHERE json_extract(r.payload, '$.host') = ?
           ORDER BY o.created DESC LIMIT 50""",
        (anchor.host,),
    )
    history = []
    seen = {anchor.id}
    for payload, expected in rows:
        run = json.loads(payload)
        if run["anchor_id"] in seen:
            continue
        past = [Event.parse(event) for event in run["events"]]
        prior_anchor = next(event for event in past if event.id == run["anchor_id"])
        if evidence_profile(prior_anchor, past) == current:
            seen.add(run["anchor_id"])
            history.append({"initial": run["blue"]["decision"], "verified": expected,
                            "check": run["forecast"]["check"]})
            if len(history) == 5:
                break
    return history
