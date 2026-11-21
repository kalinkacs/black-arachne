"""Validated, minimal evidence records and Linux journal normalization."""

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re

ANCHOR_KINDS = {"ssh_login", "ssh_session_open"}
KINDS = ANCHOR_KINDS | {
    "ssh_failure", "privileged_activity", "deployment", "change_verified",
    "change_disputed", "identity_verified", "identity_disputed",
}
MAX_LINE = 65_536
NATIVE_EXECUTABLES = {
    "sshd": {"/usr/sbin/sshd", "/sbin/sshd"},
    "sshd-session": {"/usr/lib/openssh/sshd-session", "/usr/libexec/openssh/sshd-session",
                     "/usr/libexec/sshd-session", "/usr/sbin/sshd-session"},
    "sudo": {"/usr/bin/sudo", "/bin/sudo"},
}


@dataclass(frozen=True)
class Event:
    id: str
    timestamp: str
    host: str
    kind: str
    actor: str
    source: str
    machine_id: str | None = None
    session_key: str | None = None

    @classmethod
    def parse(cls, record):
        required = {"id", "timestamp", "host", "kind", "actor", "source"}
        if not isinstance(record, dict) or not required <= set(record) <= set(cls.__dataclass_fields__):
            raise ValueError("Expected id, timestamp, host, kind, actor and source")
        for key in required:
            value = record[key]
            if not isinstance(value, str) or not value.strip() or len(value) > 256:
                raise ValueError(f"Invalid value for {key}")
            if any(ord(char) < 32 or ord(char) == 127 for char in value):
                raise ValueError(f"Control character in {key}")
        machine, session = record.get("machine_id"), record.get("session_key")
        if machine is not None and (not isinstance(machine, str) or not hex_identifier(machine, 32)):
            raise ValueError("Invalid machine identifier")
        if session is not None and (machine is None or not isinstance(session, str) or not hex_identifier(session, 64)):
            raise ValueError("Invalid session key")
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


SSH_SESSION = re.compile(r"^Starting session: .+ for ([^\s]+) from \S+ port \d+ id \d+$")
PAM_LOGIN = re.compile(r"^pam_unix\(sshd(?:-session)?:session\): session opened for user ([^\s(]+)")


def hex_identifier(value, length):
    return len(value) == length and all(character in "abcdef0123456789" for character in value)


def journal_session(record):
    machine = record.get("_MACHINE_ID")
    if not isinstance(machine, str) or not hex_identifier(machine, 32):
        return None, None
    boot, audit = record.get("_BOOT_ID"), record.get("_AUDIT_SESSION")
    # -1 (u32 max) is Linux's unset audit-session sentinel.
    if (not isinstance(boot, str) or not hex_identifier(boot, 32) or not isinstance(audit, str)
            or not audit.isascii() or not audit.isdecimal() or len(audit) > 10 or not 0 < int(audit) < 4_294_967_295):
        return machine, None
    return machine, hashlib.sha256(f"{machine}:{boot}:{int(audit)}".encode()).hexdigest()


def from_journal(record, *, native=False):
    message = record.get("MESSAGE")
    identifier = record.get("SYSLOG_IDENTIFIER")
    if not isinstance(message, str) or not isinstance(identifier, str):
        return None
    if native and record.get("_EXE") not in tuple(NATIVE_EXECUTABLES.get(identifier, ())):
        return None
    fields = message.split()
    machine, session = journal_session(record)
    kind, actor = None, None
    if identifier in {"sshd", "sshd-session"} and len(fields) >= 4:
        session_open = PAM_LOGIN.match(message) or SSH_SESSION.fullmatch(message)
        if session_open and session:
            kind, actor = "ssh_session_open", session_open[1]
        elif fields[0] == "Accepted" and fields[2] == "for":
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
            "machine_id": machine,
            "session_key": session,
        })
    except (OverflowError, OSError, ValueError):
        return None


def records(events):
    return [{key: value for key, value in asdict(event).items() if value is not None} for event in events]


POST_LOGIN_OBSERVATION = timedelta(minutes=15)


def episode_window(anchor):
    timestamp = datetime.fromisoformat(anchor.timestamp)
    return (
        (timestamp - timedelta(minutes=10)).isoformat(timespec="microseconds"),
        (timestamp + POST_LOGIN_OBSERVATION).isoformat(timespec="microseconds"),
    )
