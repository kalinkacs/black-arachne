"""Observe Linux file changes against a known baseline, without modifying files."""

from datetime import datetime, timezone
import json
from pathlib import Path
from uuid import uuid4

from .events import encode
from .files import inventory


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def complete(report):
    return not report["limit_reached"] and not any(
        report["counts"][status] for status in ("changed", "unreadable", "too_large")
    )


def establish(path, root, name, limits):
    from .store import database

    if not name.strip() or len(name) > 80:
        raise ValueError("Baseline name must contain 1–80 characters")
    report, entries = inventory(Path(root), **limits)
    if not complete(report):
        raise ValueError("Snapshot was incomplete; choose a smaller, fully readable directory or raise the limits")
    baseline = {
        "id": uuid4().hex,
        "name": name.strip(),
        "root": report["root"],
        "created": timestamp(),
        "root_identity": report["root_identity"],
        "limits": limits,
        "reference": entries,
    }
    with database(path) as connection:
        connection.execute(
            "INSERT INTO integrity_baselines VALUES (?, ?, ?, ?, 0, ?)",
            (baseline["id"], baseline["name"], encode(baseline), encode(entries), baseline["created"]),
        )
    return {key: baseline[key] for key in ("id", "name", "created")} | {"files": len(entries)}


def transitions(reference, previous, current):
    changes = []
    for relative in sorted(previous.keys() | current.keys()):
        before, after = previous.get(relative), current.get(relative)
        if before == after:
            continue
        if after == reference.get(relative):
            kind = "restored"
        elif before is None:
            kind = "added"
        elif after is None:
            kind = "removed"
        elif before["kind"] != after["kind"]:
            kind = "type"
        elif before["sha256"] != after["sha256"]:
            kind = "content"
        else:
            kind = "permissions"
        changes.append({"path": relative, "change": kind, "previous": before, "observed": after})
    return changes


def record_health(connection, baseline_id, attempted, success, reason=None):
    connection.execute(
        """INSERT INTO integrity_health VALUES (?, ?, ?, ?) ON CONFLICT(baseline_id)
           DO UPDATE SET attempted=excluded.attempted, complete=excluded.complete, reason=excluded.reason""",
        (baseline_id, attempted, int(success), reason),
    )


def observe(path, baseline_id):
    from .store import database

    with database(path) as connection:
        row = connection.execute(
            "SELECT definition, current, revision FROM integrity_baselines WHERE id=?", (baseline_id,)
        ).fetchone()
    if row is None:
        raise ValueError("Unknown file integrity baseline")
    baseline, previous, revision = json.loads(row[0]), json.loads(row[1]), row[2]
    def incomplete(reason, report=None):
        with database(path) as connection:
            record_health(connection, baseline_id, timestamp(), False, reason)
        return {"baseline_id": baseline_id, "complete": False, "findings": [],
                "inventory": report, "reason": reason}

    try:
        report, current = inventory(baseline["root"], **baseline["limits"])
    except (OSError, ValueError) as error:
        return incomplete(str(error))
    if report["root_identity"] != baseline["root_identity"]:
        return incomplete("Monitored root no longer matches the baseline", report)
    if not complete(report):
        return incomplete("Inventory incomplete; last complete state preserved", report)

    result = {"baseline_id": baseline_id, "complete": True, "findings": [], "inventory": report}
    observed_at = timestamp()
    findings = [
        {**change, "id": uuid4().hex, "baseline_id": baseline_id, "baseline": baseline["name"], "created": observed_at}
        for change in transitions(baseline["reference"], previous, current)
    ]
    with database(path) as connection:
        updated = connection.execute(
            """UPDATE integrity_baselines SET current=?, revision=revision+1, last_checked=?
               WHERE id=? AND revision=?""",
            (encode(current), observed_at, baseline_id, revision),
        )
        if not updated.rowcount:
            # Another collection completed while this one was walking the files.
            return {**result, "complete": False, "reason": "Another scan committed first; run a fresh check"}
        connection.executemany("INSERT INTO integrity_findings VALUES (?, ?, ?, ?)",
                               [(item["id"], baseline_id, observed_at, encode(item)) for item in findings])
        record_health(connection, baseline_id, observed_at, True)
    return {**result, "findings": findings}


def baseline_catalog(connection):
    items = []
    for baseline_id, name, checked, attempted, success, reason in connection.execute(
        """SELECT b.id,b.name,b.last_checked,h.attempted,h.complete,h.reason FROM integrity_baselines b
           LEFT JOIN integrity_health h ON h.baseline_id=b.id ORDER BY b.name,b.id"""
    ):
        items.append({"id": baseline_id, "name": name, "last_checked": checked,
                      "latest_attempt": attempted, "complete": bool(success) if attempted else None,
                      "reason": reason})
    return items


def recent_findings(connection):
    return [json.loads(payload) for (payload,) in connection.execute(
        "SELECT payload FROM integrity_findings ORDER BY created DESC, id DESC LIMIT 100"
    )]


def scheduled_checks(path):
    from .store import database

    with database(path) as connection:
        ids = [item["id"] for item in baseline_catalog(connection)]
    summaries = []
    for baseline_id in ids:
        result = observe(path, baseline_id)
        summaries.append({"baseline_id": baseline_id, "complete": result["complete"],
                          "findings": len(result["findings"]), "reason": result.get("reason")})
    return summaries
