"""SQLite persistence, idempotent ingestion and immutable run snapshots."""

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import sqlite3
from uuid import uuid4

from .events import (
    ANCHOR_KINDS, POST_LOGIN_OBSERVATION, PRE_LOGIN_OBSERVATION, SESSION_ACTIVITY,
    Event, encode, episode_window, observation_profile, records,
)
from .learning import MAX_HISTORY
from .provenance import authenticate, check_binding
from .sessions import attributed_events

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY, host TEXT NOT NULL, timestamp TEXT NOT NULL, payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_by_host_time ON events(host, timestamp, id);
CREATE INDEX IF NOT EXISTS events_by_session ON events(host, json_extract(payload, '$.session_key'), timestamp)
WHERE json_extract(payload, '$.session_key') IS NOT NULL;
CREATE TABLE IF NOT EXISTS verified_evidence (
    event_id TEXT PRIMARY KEY REFERENCES events(id),
    anchor_id TEXT NOT NULL REFERENCES events(id),
    key_id TEXT NOT NULL,
    signature TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS verified_evidence_by_anchor ON verified_evidence(anchor_id);
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
CREATE TABLE IF NOT EXISTS triage_evidence_state (
    anchor_id TEXT PRIMARY KEY REFERENCES events(id), verification_count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS session_evidence_versions (
    anchor_id TEXT PRIMARY KEY REFERENCES events(id), revision INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS triage_session_state (
    anchor_id TEXT PRIMARY KEY REFERENCES events(id), revision INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS triage_issues (
    anchor_id TEXT PRIMARY KEY REFERENCES events(id), reason TEXT NOT NULL, created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS role_retries (
    anchor_id TEXT PRIMARY KEY REFERENCES events(id),
    attempts INTEGER NOT NULL, retry_after TEXT NOT NULL, reason TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS collector_health (
    name TEXT PRIMARY KEY, checked_at TEXT NOT NULL, inserted INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS integrity_baselines (
    id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, definition TEXT NOT NULL,
    current TEXT NOT NULL, revision INTEGER NOT NULL, last_checked TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS integrity_health (
    baseline_id TEXT PRIMARY KEY REFERENCES integrity_baselines(id),
    attempted TEXT NOT NULL, complete INTEGER NOT NULL, reason TEXT
);
CREATE TABLE IF NOT EXISTS integrity_findings (
    id TEXT PRIMARY KEY, baseline_id TEXT NOT NULL REFERENCES integrity_baselines(id),
    created TEXT NOT NULL, payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS integrity_findings_by_time ON integrity_findings(created DESC, id DESC);
CREATE TABLE IF NOT EXISTS decision_audit (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    payload TEXT NOT NULL,
    digest TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS audit_baseline (
    id INTEGER PRIMARY KEY CHECK(id=1), preexisting INTEGER NOT NULL
);
INSERT INTO audit_baseline SELECT 1, (SELECT count(*) FROM outcomes)
WHERE NOT EXISTS (SELECT 1 FROM audit_baseline WHERE id=1);
"""


class EvidenceWindowOverflow(ValueError):
    """The current candidate contains more observations than the allowed window quota."""


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
            advance_related_logins(connection, event)
        else:
            original, = connection.execute(
                "SELECT payload FROM events WHERE id = ?", (event.id,)
            ).fetchone()
            if original != payload:
                previous = Event.parse(json.loads(original))
                if journal_enrichment(previous, event):
                    connection.execute("UPDATE events SET payload=? WHERE id=?", (payload, event.id))
                    advance_related_logins(connection, event)
                else:
                    raise ValueError(f"Conflicting evidence id: {event.id}")
    return inserted


def advance_related_logins(connection, event):
    # If the anchor itself was enriched on replay, its existing analysis
    # might have been made without session attribution.
    if event.kind in ANCHOR_KINDS and event.source == "systemd-journal" and event.session_key:
        connection.execute(
            """INSERT INTO session_evidence_versions VALUES (?, 1)
               ON CONFLICT(anchor_id) DO UPDATE SET revision=revision+1""",
            (event.id,),
        )
        return
    if event.kind not in SESSION_ACTIVITY or not event.session_key:
        return
    at = datetime.fromisoformat(event.timestamp)
    after = (at - POST_LOGIN_OBSERVATION).isoformat(timespec="microseconds")
    before = (at + PRE_LOGIN_OBSERVATION).isoformat(timespec="microseconds")
    connection.execute(
        """INSERT INTO session_evidence_versions(anchor_id,revision)
           SELECT id, 1 FROM events WHERE host=? AND timestamp BETWEEN ? AND ?
               AND json_extract(payload,'$.session_key')=?
               AND json_extract(payload,'$.machine_id')=?
               AND json_extract(payload,'$.actor')=?
               AND json_extract(payload,'$.kind') IN ('ssh_login','ssh_session_open')
               AND json_extract(payload,'$.source')='systemd-journal'
           ON CONFLICT(anchor_id) DO UPDATE SET revision=revision+1""",
        (event.host, after, before, event.session_key, event.machine_id, event.actor),
    )


def journal_enrichment(previous, event):
    if event.source != "systemd-journal" or not event.machine_id:
        return False
    old, new = records((previous, event))
    # A repeat import may add new machine metadata to older journal records.
    # Previously observed facts are immutable.
    return old != new and all(new.get(key) == value for key, value in old.items())


def import_verifications(connection, key, envelopes):
    enrolled = 0
    for envelope in envelopes:
        event, anchor_id = authenticate(key, envelope)
        row = connection.execute("SELECT payload FROM events WHERE id=?", (anchor_id,)).fetchone()
        if not row:
            raise ValueError("Verification refers to an unknown login")
        check_binding(Event.parse(json.loads(row[0])), event)
        ingest(connection, (event,))
        receipt = (anchor_id, key.key_id, envelope["mac"])
        existing = connection.execute(
            "SELECT anchor_id, key_id, signature FROM verified_evidence WHERE event_id=?", (event.id,)
        ).fetchone()
        if existing is not None:
            if existing != receipt:
                raise ValueError("Conflicting authenticated evidence receipt")
            continue
        connection.execute("INSERT INTO verified_evidence VALUES (?, ?, ?, ?)", (event.id, *receipt))
        enrolled += 1
    return {"verified": enrolled}


def verifications_for(connection, anchor_id):
    rows = connection.execute("SELECT event_id, key_id FROM verified_evidence WHERE anchor_id=?", (anchor_id,))
    return dict(rows)


def episode(connection, host, anchor_id):
    row = connection.execute(
        "SELECT payload FROM events WHERE host = ? AND id = ?", (host, anchor_id)
    ).fetchone()
    if not row:
        raise ValueError("Anchor event is missing")
    anchor = Event.parse(json.loads(row[0]))
    if anchor.kind not in ANCHOR_KINDS:
        raise ValueError("The anchor must be an SSH login")
    lower, upper = episode_window(anchor)
    rows = connection.execute(
        """SELECT payload FROM events WHERE host = ? AND timestamp BETWEEN ? AND ?
           AND json_extract(payload, '$.actor')=?
           ORDER BY timestamp, id LIMIT 1001""",
        (host, lower, upper, anchor.actor),
    ).fetchall()
    if len(rows) > 1000:
        raise EvidenceWindowOverflow("More than 1000 observations in the investigation window")
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
    if decision not in ("close", "review", "escalate"):
        raise ValueError("Invalid verified decision")
    if not isinstance(note, str) or not note.strip() or len(note) > 2000:
        raise ValueError("Provide a verification note of 1–2000 characters")
    report = get_run(connection, run_id)
    if not report:
        raise ValueError("Run does not exist")
    if "scenario" in report:
        raise ValueError("Synthetic outcomes are excluded from analyst memory")
    record = {
        "run_id": run_id, "decision": decision, "note": note.strip(),
        "created": datetime.now(timezone.utc).isoformat(),
    }
    connection.execute(
        "INSERT INTO outcomes VALUES (?, ?, ?, ?)",
        (record["run_id"], record["decision"], record["note"], record["created"]),
    )
    previous = connection.execute(
        "SELECT digest FROM decision_audit ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    data = encode({**record, "previous": previous[0] if previous else None})
    connection.execute("INSERT INTO decision_audit(payload, digest) VALUES (?, ?)",
                       (data, hashlib.sha256(data.encode()).hexdigest()))
    return record


def get_outcome(connection, run_id):
    row = connection.execute("SELECT decision, note, created FROM outcomes WHERE run_id = ?", (run_id,)).fetchone()
    if row:
        return dict(zip(("decision", "note", "created"), row))
    return None


def verify_audit(connection):
    connection.execute("SAVEPOINT audit_snapshot")
    try:
        return _verify_audit_snapshot(connection)
    finally:
        connection.execute("RELEASE audit_snapshot")


def _verify_audit_snapshot(connection):
    previous = None
    count = 0
    for sequence, data, digest in connection.execute(
        "SELECT sequence, payload, digest FROM decision_audit ORDER BY sequence"
    ):
        if hashlib.sha256(data.encode()).hexdigest() != digest:
            return {"valid": False, "checked": count, "invalid_sequence": sequence}
        entry = json.loads(data)
        outcome = get_outcome(connection, entry["run_id"])
        expected = {key: entry[key] for key in ("decision", "note", "created")}
        if entry["previous"] != previous or outcome != expected:
            return {"valid": False, "checked": count, "invalid_sequence": sequence}
        previous = digest
        count += 1
    outcomes, = connection.execute("SELECT count(*) FROM outcomes").fetchone()
    legacy, = connection.execute("SELECT preexisting FROM audit_baseline WHERE id=1").fetchone()
    return {"valid": outcomes == legacy + count, "checked": count,
            "untracked_legacy_outcomes": legacy, "head": previous}


def status_snapshot(connection):
    checked = connection.execute(
        "SELECT checked_at, inserted FROM collector_health WHERE name = 'local_journal'"
    ).fetchone()
    return {
        "events": connection.execute("SELECT count(*) FROM events").fetchone()[0],
        "investigations": connection.execute(
            "SELECT count(*) FROM runs WHERE json_type(payload, '$.scenario') IS NULL"
        ).fetchone()[0],
        "confirmed": connection.execute("SELECT count(*) FROM outcomes").fetchone()[0],
        "authenticated_records": connection.execute("SELECT count(*) FROM verified_evidence").fetchone()[0],
        "excluded_anchors": connection.execute("SELECT count(*) FROM triage_issues").fetchone()[0],
        "pending_role_retries": connection.execute("SELECT count(*) FROM role_retries").fetchone()[0],
        "collector": {"checked_at": checked[0], "inserted": checked[1]} if checked else None,
    }


def evidence_profile(anchor, events):
    relevant = [event for event in events if event.host == anchor.host and event.actor == anchor.actor]
    return observation_profile(anchor, relevant)


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
        if prior_anchor.machine_id != anchor.machine_id:
            continue
        scope = run.get("session_attribution")
        if scope is not None:
            past = attributed_events(prior_anchor, past, scope)
        if evidence_profile(prior_anchor, past) == current:
            seen.add(run["anchor_id"])
            record = {"initial": run["blue"]["decision"], "verified": expected, "check": run["forecast"]["check"]}
            if "mimicry" in run:
                observations = run["mimicry"]
                record["comparisons"] = [
                    {"check": observations[key]["check"], "state": observations[key]["state"],
                     "decision": run[branch]["decision"]}
                    for key, branch in (("standard_observation", "standard_review"), ("assisted_observation", "assisted"))
                ]
            history.append(record)
            if len(history) == MAX_HISTORY:
                break
    return history
