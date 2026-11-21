"""Validated, minimal evidence records and Linux journal normalization."""

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re

ANCHOR_KINDS = {"ssh_login", "ssh_session_open"}
KINDS = ANCHOR_KINDS | {
    "ssh_failure", "privileged_activity", "privilege_denied", "privilege_denial_unverified", "deployment", "change_verified",
    "change_disputed", "identity_verified", "identity_disputed",
}
SESSION_ACTIVITY = {"ssh_failure", "privileged_activity", "privilege_denied"}
DENIAL_REVIEW_THRESHOLD = 2
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


def sudo_denial(detail):
    decision = detail.casefold()
    return any(phrase in decision for phrase in (
        "not in sudoers", "not allowed to execute", "command not allowed", "authentication failure",
        "incorrect password attempt", "a password is required", "account validation failure",
    ))


def from_journal(record, *, native=False):
    message = record.get("MESSAGE")
    identifier = record.get("SYSLOG_IDENTIFIER")
    if not isinstance(message, str) or not isinstance(identifier, str):
        return None
    trusted_executable = record.get("_EXE") in tuple(NATIVE_EXECUTABLES.get(identifier, ()))
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
    elif identifier == "sudo" and fields and " : " in message:
        actor, _, content = message.partition(" : ")
        actor = actor.strip()
        first = content.split(";", 1)[0].strip()
        if first.startswith(("TTY=", "PWD=", "USER=", "COMMAND=")) and any(
            field.lstrip().startswith("COMMAND=") for field in content.split(";")
        ):
            kind = "privileged_activity"
        elif sudo_denial(first):
            kind = "privilege_denied"
    if kind is None:
        return None
    if native and not trusted_executable:
        if (kind != "privilege_denied" or record.get("_EXE") is not None
                or record.get("_COMM") != "sudo" or record.get("_TRANSPORT") != "syslog"):
            return None
        # The kernel process name can survive when no executable path is
        # available. Show this as incomplete telemetry, never as a case signal.
        kind = "privilege_denial_unverified"
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


class NativeJournalCoverage:
    """Count usable messages and missing executable provenance in an import."""

    def __init__(self):
        self.read = self.retained = self.missing_executable = 0

    def normalize(self, record):
        self.read += 1
        self.missing_executable += int(not isinstance(record.get("_EXE"), str))
        event = from_journal(record, native=True)
        self.retained += int(event is not None)
        return event

    def report(self):
        return {"read": self.read, "retained": self.retained, "missing_executable": self.missing_executable}


def records(events):
    return [{key: value for key, value in asdict(event).items() if value is not None} for event in events]


PRE_LOGIN_OBSERVATION = timedelta(minutes=10)
POST_LOGIN_OBSERVATION = timedelta(minutes=15)


def episode_window(anchor):
    timestamp = datetime.fromisoformat(anchor.timestamp)
    return (
        (timestamp - PRE_LOGIN_OBSERVATION).isoformat(timespec="microseconds"),
        (timestamp + POST_LOGIN_OBSERVATION).isoformat(timespec="microseconds"),
    )


def denied_attempts(anchor, events):
    return [event for event in events if event.kind == "privilege_denied" and event.timestamp >= anchor.timestamp]


def observation_profile(anchor, events):
    return {
        "declared_change": any(event.kind == "deployment" and event.timestamp <= anchor.timestamp for event in events),
        "prior_failures": sum(event.kind == "ssh_failure" and event.timestamp <= anchor.timestamp for event in events) >= 3,
        "privileged_activity": any(event.kind == "privileged_activity" and event.timestamp >= anchor.timestamp for event in events),
        "repeated_privilege_denials": len(denied_attempts(anchor, events)) >= DENIAL_REVIEW_THRESHOLD,
    }
