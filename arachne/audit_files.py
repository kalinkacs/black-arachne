"""Import bounded, trusted Linux Audit file-open exports for defensive observation."""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import json
import os
import re
import shlex

from .dead_souls import import_touches
from .events import Event, journal_session
from .provenance import sign_record
from .store import import_verifications

RECORD = re.compile(r"^(?:node=[^ ]+ )?type=(SYSCALL|PATH) msg=audit\((\d{1,12}(?:\.\d{1,6})?):(\d{1,20})\): (.*)$")
MAX_LINES = 100_000
# x86-64 and aarch64. openat2 uses a pointer instead of inline flags.
OPEN_FLAGS = {("c000003e", "2"): "a1", ("c000003e", "257"): "a2", ("c00000b7", "56"): "a2"}
MAX_LINE = 16_384


def audit_opens(stream, watch_key):
    groups = {}
    for index, line in enumerate(iter(lambda: stream.readline(MAX_LINE + 1), ""), 1):
        if index > MAX_LINES or len(line) > MAX_LINE:
            raise ValueError("Audit export exceeds the supported batch size")
        match = RECORD.fullmatch(line.rstrip("\n"))
        if not match:
            continue
        record_type, seconds, sequence, fields = match.groups()
        tokens = dict(part.split("=", 1) for part in shlex.split(fields.split("\x1d", 1)[0]) if "=" in part)
        group = groups.setdefault((seconds, sequence), {"paths": set()})
        if record_type == "SYSCALL":
            if "call" in group and group["call"] != tokens:
                raise ValueError("Conflicting Linux Audit syscall records")
            group["call"] = tokens
        elif tokens.get("nametype") in ("NORMAL", "CREATE"):
            name = tokens.get("name", "")
            if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", name):
                name = bytes.fromhex(name).decode("utf-8", errors="replace")
            if name.startswith("/") and len(name) <= 4096:
                group["paths"].add(name)
    for (seconds, sequence), group in groups.items():
        call = group.get("call", {})
        flags_key = OPEN_FLAGS.get((call.get("arch"), call.get("syscall")))
        if not flags_key or call.get("key") != watch_key or call.get("success") != "yes":
            continue
        flags = call.get(flags_key, "")
        pid = call.get("pid", "")
        if not re.fullmatch(r"[0-9a-fA-F]{1,16}", flags) or not re.fullmatch(r"[1-9][0-9]{0,9}", pid):
            continue
        flags = int(flags, 16)
        if flags & os.O_PATH:
            continue
        writable = (flags & os.O_ACCMODE) in (os.O_WRONLY, os.O_RDWR)
        action = "write_attempt" if writable or flags & (os.O_TRUNC | os.O_CREAT) else "read"
        epoch_us = int(Decimal(seconds) * 1_000_000)
        try:
            timestamp = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=epoch_us)
        except OverflowError as error:
            raise ValueError("Audit timestamp is outside the supported range") from error
        for path in sorted(group["paths"]):
            yield sequence, timestamp, call.get("ses"), pid, path, action


def matching_login(connection, host, machine, session, timestamp):
    start = timestamp - timedelta(minutes=15)
    rows = connection.execute(
        """SELECT payload FROM events
           WHERE host=? AND timestamp BETWEEN ? AND ? AND json_extract(payload,'$.machine_id')=?
             AND json_extract(payload,'$.session_key')=? AND json_extract(payload,'$.source')='systemd-journal'
             AND json_extract(payload,'$.kind') IN ('ssh_login','ssh_session_open')
           ORDER BY timestamp, id LIMIT 33""",
        (host, start.isoformat(timespec="microseconds"), timestamp.isoformat(timespec="microseconds"), machine, session),
    ).fetchall()
    anchors = [Event.parse(json.loads(row[0])) for row in rows]
    if not anchors or len(anchors) > 32 or len({anchor.actor for anchor in anchors}) != 1:
        return None
    return anchors[0]


def import_audit_files(connection, stream, key, machine_id, boot_id, watch_key, decoys, threshold):
    machine, valid_boot = journal_session({"_MACHINE_ID": machine_id, "_BOOT_ID": boot_id, "_AUDIT_SESSION": "1"})
    if key.source != "decoy-monitor" or not machine or not valid_boot:
        raise ValueError("Expected a decoy-monitor key and explicit machine and boot identifiers")
    touches, observed, write_paths = [], [], defaultdict(set)
    for sequence, timestamp, audit_session, pid, path, action in audit_opens(stream, watch_key):
        _, session = journal_session({"_MACHINE_ID": machine_id, "_BOOT_ID": boot_id, "_AUDIT_SESSION": audit_session})
        at = timestamp.isoformat(timespec="microseconds")
        if action == "write_attempt":
            minute = timestamp.replace(second=0, microsecond=0).isoformat(timespec="seconds")
            write_paths[(session, pid, minute)].add(path)
        if path in decoys:
            digest = hashlib.sha256(f"{machine}:{boot_id}:{at}:{sequence}:{path}".encode()).hexdigest()
            event_id = f"audit-{digest}"
            touches.append({"id": event_id, "decoy_id": decoys[path], "timestamp": at,
                            "sensor": key.key_id, "action": action})
            observed.append((event_id, timestamp, session, decoys[path], action))
    receipts = []
    for event_id, timestamp, session, decoy_id, action in observed:
        anchor = matching_login(connection, key.host, machine, session, timestamp) if session else None
        if anchor:
            event = Event(event_id, timestamp.isoformat(timespec="microseconds"), key.host, "decoy_touch",
                          anchor.actor, key.source, machine, session, decoy_id, action)
            receipts.append(sign_record(key, anchor.id, event))
    counters = import_touches(connection, touches)
    signed = import_verifications(connection, key, receipts)
    bursts = [
        {"session_key": session, "pid": int(pid), "minute": minute, "distinct_write_opens": len(paths)}
        for (session, pid, minute), paths in write_paths.items() if len(paths) >= threshold
    ]
    bursts.sort(key=lambda item: (item["minute"], item["pid"], item["session_key"] or ""))
    return {**counters, "new_verified": signed["verified"], "matched_session": len(receipts),
            "unattributed": len(observed) - len(receipts), "write_open_bursts": bursts[:100],
            "total_write_open_bursts": len(bursts)}
