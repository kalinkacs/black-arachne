"""Validated, minimal evidence records and Linux journal normalization."""

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json

KINDS = {
    "ssh_login", "ssh_failure", "privileged_activity", "deployment", "change_verified",
    "change_disputed", "identity_verified", "identity_disputed",
}
MAX_LINE = 65_536


@dataclass(frozen=True)
class Event:
    id: str
    timestamp: str
    host: str
    kind: str
    actor: str
    source: str

    @classmethod
    def parse(cls, record):
        if not isinstance(record, dict) or set(record) != set(cls.__dataclass_fields__):
            raise ValueError("Expected id, timestamp, host, kind, actor and source")
        for key, value in record.items():
            if not isinstance(value, str) or not value.strip() or len(value) > 256:
                raise ValueError(f"Invalid value for {key}")
            if any(ord(char) < 32 or ord(char) == 127 for char in value):
                raise ValueError(f"Control character in {key}")
        if record["kind"] not in KINDS:
            raise ValueError("Unsupported event kind")
        timestamp = datetime.fromisoformat(record["timestamp"])
        if timestamp.tzinfo is None:
            raise ValueError("Timestamp must include a timezone")
        return cls(**{**record, "timestamp": timestamp.astimezone(timezone.utc).isoformat(timespec="microseconds")})


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def read_records(stream):
    while line := stream.readline(MAX_LINE + 1):
        if len(line) > MAX_LINE:
            raise ValueError("Input line exceeds 64 KiB")
        if line.strip():
            yield json.loads(line)


def from_journal(record):
    message = record.get("MESSAGE")
    identifier = record.get("SYSLOG_IDENTIFIER")
    if not isinstance(message, str) or not isinstance(identifier, str):
        return None
    fields = message.split()
    kind, actor = None, None
    if identifier in {"sshd", "sshd-session"} and len(fields) >= 4:
        if fields[0] == "Accepted" and fields[2] == "for":
            kind, actor = "ssh_login", fields[3]
        elif fields[0] == "Failed" and fields[2] == "for":
            kind = "ssh_failure"
            actor = fields[5] if fields[3:5] == ["invalid", "user"] and len(fields) > 5 else fields[3]
    elif identifier == "sudo" and fields and "COMMAND=" in message and " : " in message:
        kind, actor = "privileged_activity", fields[0]
    if kind is None:
        return None
    cursor = record.get("__CURSOR")
    host = record.get("_HOSTNAME")
    micros = record.get("__REALTIME_TIMESTAMP")
    if not all(isinstance(value, str) and value for value in (cursor, host, micros)):
        return None
    try:
        seconds, remainder = divmod(int(micros), 1_000_000)
        timestamp = datetime.fromtimestamp(seconds, timezone.utc).replace(microsecond=remainder)
        return Event.parse({
            "id": hashlib.sha256(cursor.encode()).hexdigest(),
            "timestamp": timestamp.isoformat(),
            "host": host,
            "kind": kind,
            "actor": actor,
            "source": "systemd-journal",
        })
    except (OverflowError, OSError, ValueError):
        return None


def records(events):
    return [asdict(event) for event in events]


POST_LOGIN_OBSERVATION = timedelta(minutes=15)


def episode_window(anchor):
    timestamp = datetime.fromisoformat(anchor.timestamp)
    return (
        (timestamp - timedelta(minutes=10)).isoformat(timespec="microseconds"),
        (timestamp + POST_LOGIN_OBSERVATION).isoformat(timespec="microseconds"),
    )
