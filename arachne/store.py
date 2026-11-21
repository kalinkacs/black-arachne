"""SQLite persistence, idempotent ingestion and immutable run snapshots."""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
import sqlite3
from uuid import uuid4

from .events import Event, encode, records

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY, host TEXT NOT NULL, timestamp TEXT NOT NULL, payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_by_host_time ON events(host, timestamp, id);
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY, created TEXT NOT NULL, payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS runs_by_time ON runs(created DESC, id);
"""


@contextmanager
def database(path):
    connection = sqlite3.connect(path, timeout=10)
    try:
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
    time = datetime.fromisoformat(anchor.timestamp)
    lower = (time - timedelta(minutes=10)).isoformat(timespec="microseconds")
    upper = (time + timedelta(minutes=15)).isoformat(timespec="microseconds")
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
