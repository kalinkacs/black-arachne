"""Local, observation-only telemetry for operator-registered decoys."""

from datetime import datetime, timezone
import re

KINDS = ("account", "file", "service")
ACTIONS = ("probe", "read", "credential_use", "write_attempt")
MAX_BATCH = 50_000
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}")

SCHEMA = """
CREATE TABLE IF NOT EXISTS decoy_assets (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK(kind IN ('account', 'file', 'service'))
);
CREATE TABLE IF NOT EXISTS decoy_touches (
    id TEXT PRIMARY KEY,
    decoy_id TEXT NOT NULL REFERENCES decoy_assets(id),
    timestamp TEXT NOT NULL,
    minute TEXT NOT NULL,
    sensor TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('probe', 'read', 'credential_use', 'write_attempt'))
);
CREATE INDEX IF NOT EXISTS decoy_important_by_time ON decoy_touches(timestamp DESC, id DESC)
WHERE action IN ('credential_use', 'write_attempt');
CREATE TABLE IF NOT EXISTS decoy_minutes (
    minute TEXT PRIMARY KEY, touches INTEGER NOT NULL, important INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS decoy_minute_assets (
    minute TEXT NOT NULL REFERENCES decoy_minutes(minute),
    decoy_id TEXT NOT NULL REFERENCES decoy_assets(id),
    PRIMARY KEY(minute, decoy_id)
);
"""


def identifier(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError("Expected a decoy, sensor or event identifier of 1–96 ASCII characters")
    return value


def register_decoy(connection, decoy_id, kind):
    identifier(decoy_id)
    if kind not in KINDS:
        raise ValueError("Unsupported decoy kind")
    result = connection.execute("INSERT OR IGNORE INTO decoy_assets VALUES (?, ?)", (decoy_id, kind))
    if not result.rowcount:
        existing, = connection.execute("SELECT kind FROM decoy_assets WHERE id = ?", (decoy_id,)).fetchone()
        if existing != kind:
            raise ValueError("Decoy already registered with a different kind")
    return {"id": decoy_id, "kind": kind, "created": bool(result.rowcount)}


def normalize_touch(record):
    if not isinstance(record, dict) or set(record) != {"id", "decoy_id", "timestamp", "sensor", "action"}:
        raise ValueError("Decoy telemetry requires id, decoy_id, timestamp, sensor and action")
    action = record["action"]
    if action not in ACTIONS:
        raise ValueError("Unsupported decoy action")
    timestamp = record["timestamp"]
    if not isinstance(timestamp, str) or len(timestamp) > 64:
        raise ValueError("Invalid decoy event timestamp")
    observed = datetime.fromisoformat(timestamp)
    if observed.tzinfo is None:
        raise ValueError("Decoy event timestamp must include a timezone")
    utc = observed.astimezone(timezone.utc)
    return (
        identifier(record["id"]), identifier(record["decoy_id"]), utc.isoformat(timespec="microseconds"),
        utc.replace(second=0, microsecond=0).isoformat(timespec="seconds"), identifier(record["sensor"]), action,
    )


def import_touches(connection, records):
    inserted = duplicates = 0
    connection.execute("SAVEPOINT import_decoy_touches")
    try:
        summaries = {}
        assets = set()
        for number, record in enumerate(records, 1):
            if number > MAX_BATCH:
                raise ValueError(f"Import accepts at most {MAX_BATCH} decoy events per batch")
            row = normalize_touch(record)
            event_id, decoy_id, _, minute, _, action = row
            cursor = connection.execute(
                """INSERT INTO decoy_touches
                   SELECT ?, ?, ?, ?, ?, ? FROM decoy_assets WHERE id = ?
                   ON CONFLICT(id) DO NOTHING""", (*row, decoy_id),
            )
            if not cursor.rowcount:
                previous = connection.execute("SELECT * FROM decoy_touches WHERE id=?", (event_id,)).fetchone()
                if previous is None:
                    raise ValueError("Decoy event refers to an unregistered asset")
                if previous != row:
                    raise ValueError("Conflicting decoy event identifier")
                duplicates += 1
                continue
            inserted += 1
            counts = summaries.setdefault(minute, [0, 0])
            counts[0] += 1
            counts[1] += action in ("credential_use", "write_attempt")
            assets.add((minute, decoy_id))
        connection.executemany(
            """INSERT INTO decoy_minutes VALUES (?, ?, ?)
               ON CONFLICT(minute) DO UPDATE SET touches=touches+excluded.touches,
               important=important+excluded.important""",
            ((minute, *counts) for minute, counts in summaries.items()),
        )
        connection.executemany("INSERT OR IGNORE INTO decoy_minute_assets VALUES (?, ?)", assets)
    except BaseException:
        connection.execute("ROLLBACK TO import_decoy_touches")
        raise
    finally:
        connection.execute("RELEASE import_decoy_touches")
    return {"inserted": inserted, "duplicates": duplicates}


def overview(connection):
    windows = connection.execute(
        """SELECT minute, touches, important,
           (SELECT count(*) FROM decoy_minute_assets WHERE minute=m.minute) AS decoys
           FROM decoy_minutes m ORDER BY minute DESC LIMIT 60"""
    )
    important = connection.execute(
        """SELECT timestamp, decoy_id, action, sensor FROM decoy_touches
           WHERE action IN ('credential_use', 'write_attempt')
           ORDER BY timestamp DESC, id DESC LIMIT 30"""
    )
    return {
        "registered": connection.execute("SELECT count(*) FROM decoy_assets").fetchone()[0],
        "windows": [dict(zip(("minute", "touches", "important", "decoys"), row)) for row in windows],
        "important": [dict(zip(("timestamp", "decoy_id", "action", "sensor"), row)) for row in important],
    }
