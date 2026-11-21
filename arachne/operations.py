"""Read-only collection and scheduled defensive triage for a single Linux deployment."""

from datetime import datetime, timedelta, timezone
import subprocess

from .events import POST_LOGIN_OBSERVATION, from_journal, read_records
from .mimicry import mimic
from .role_runtime import RoleFailure
from .sessions import attributed_events, attribution
from .store import (
    EvidenceWindowOverflow, confirmed_history, database, episode, ingest, save_run, verifications_for,
)

JOURNAL_IDENTIFIERS = ("sshd", "sshd-session", "sudo")


def journal_batch(since, cursor):
    command = ["journalctl", "--quiet", "--no-pager", "--output=json"]
    command.append(f"--after-cursor={cursor}" if cursor else f"--since={since}")
    command.extend(f"SYSLOG_IDENTIFIER={identifier}" for identifier in JOURNAL_IDENTIFIERS)
    with subprocess.Popen(command, stdout=subprocess.PIPE, text=True, encoding="utf-8") as process:
        try:
            yield from read_records(process.stdout)
        except BaseException:
            process.terminate()
            raise
        if process.wait() != 0:
            raise ValueError("journalctl failed; the import and checkpoint were not advanced")


def collect(connection, since, reader=journal_batch):
    state = connection.execute(
        "SELECT cursor FROM collector_state WHERE name = 'local_journal'"
    ).fetchone()
    cursor = state[0] if state else None
    last = cursor

    def normalize():
        nonlocal last
        for row in reader(since, cursor):
            if not isinstance(row, dict) or not isinstance(row.get("__CURSOR"), str) or not row["__CURSOR"]:
                raise ValueError("Journal record has no valid cursor")
            last = row["__CURSOR"]
            event = from_journal(row, native=True)
            if event:
                yield event

    inserted = ingest(connection, normalize())
    if last is not None:
        connection.execute(
            """INSERT INTO collector_state VALUES ('local_journal', ?)
               ON CONFLICT(name) DO UPDATE SET cursor = excluded.cursor""",
            (last,),
        )
    connection.execute(
        """INSERT INTO collector_health VALUES ('local_journal', ?, ?)
           ON CONFLICT(name) DO UPDATE SET checked_at=excluded.checked_at, inserted=excluded.inserted""",
        (datetime.now(timezone.utc).isoformat(), inserted),
    )
    return {"inserted": inserted, "checkpoint_advanced": last != cursor}


def operational_review(connection, anchor, events, model):
    verified = verifications_for(connection, anchor.id)
    scope = attribution(anchor, events, verified)
    history = confirmed_history(connection, anchor, attributed_events(anchor, events, scope))
    return mimic(anchor, events, history, model, verified=verified, session_scope=scope)


def triage(path, model=None, limit=20, now=None):
    now = now or datetime.now(timezone.utc)
    ready = (now - POST_LOGIN_OBSERVATION).isoformat(timespec="microseconds")
    current_time = now.isoformat(timespec="microseconds")
    with database(path) as connection:
        pending = connection.execute(
            """SELECT e.host, e.id FROM events e
               LEFT JOIN triaged t ON t.anchor_id=e.id
               LEFT JOIN triage_evidence_state s ON s.anchor_id=e.id
               WHERE e.timestamp <= ? AND
               (t.anchor_id IS NULL OR (
                   (SELECT count(*) FROM verified_evidence v WHERE v.anchor_id=e.id) > coalesce(s.verification_count,0)
               ))
               AND NOT EXISTS (SELECT 1 FROM triage_issues i WHERE i.anchor_id=e.id)
               AND NOT EXISTS (SELECT 1 FROM role_retries r WHERE r.anchor_id=e.id AND r.retry_after > ?)
               AND json_extract(e.payload, '$.kind') IN ('ssh_login','ssh_session_open')
               AND json_extract(e.payload, '$.source')='systemd-journal'
               AND (
                   json_extract(e.payload, '$.session_key') IS NULL
                   OR EXISTS (SELECT 1 FROM verified_evidence v WHERE v.anchor_id=e.id)
                   OR NOT EXISTS (
                       SELECT 1 FROM events a WHERE a.host=e.host
                       AND json_extract(a.payload,'$.session_key')=json_extract(e.payload,'$.session_key')
                       AND json_extract(a.payload,'$.machine_id')=json_extract(e.payload,'$.machine_id')
                       AND json_extract(a.payload,'$.actor')=json_extract(e.payload,'$.actor')
                       AND json_extract(a.payload,'$.source')='systemd-journal'
                       AND json_extract(a.payload,'$.kind') IN ('ssh_login','ssh_session_open')
                       AND (a.timestamp<e.timestamp OR (a.timestamp=e.timestamp AND a.id<e.id))
                   )
               )
               ORDER BY e.timestamp, e.id LIMIT ?""",
            (ready, current_time, limit),
        ).fetchall()

    saved = []
    excluded = []
    retries = []
    for host, anchor_id in pending:
        with database(path) as connection:
            connection.execute("BEGIN")
            try:
                anchor, events = episode(connection, host, anchor_id)
            except EvidenceWindowOverflow as error:
                connection.rollback()
                connection.execute("INSERT OR IGNORE INTO triage_issues VALUES (?, ?, ?)",
                                   (anchor_id, str(error), datetime.now(timezone.utc).isoformat()))
                excluded.append(anchor_id)
                continue
            reviewed = len(verifications_for(connection, anchor_id))
            try:
                report = operational_review(connection, anchor, events, model)
            except RoleFailure as error:
                connection.rollback()
                connection.execute("BEGIN IMMEDIATE")
                if latest_revision(connection, anchor_id) >= reviewed:
                    continue
                row = connection.execute("SELECT attempts FROM role_retries WHERE anchor_id=?", (anchor_id,)).fetchone()
                attempts = 1 + (row[0] if row else 0)
                next_try = (now + timedelta(seconds=min(3600, 15 * 2 ** min(attempts, 8)))).isoformat(timespec="microseconds")
                connection.execute(
                    """INSERT INTO role_retries VALUES (?, ?, ?, ?)
                       ON CONFLICT(anchor_id) DO UPDATE SET
                       attempts=excluded.attempts, retry_after=excluded.retry_after, reason=excluded.reason""",
                    (anchor_id, attempts, next_try, str(error)),
                )
                retries.append(anchor_id)
                continue
            connection.commit()
            connection.execute("BEGIN IMMEDIATE")
            if latest_revision(connection, anchor_id) >= reviewed:
                continue
            run = save_run(connection, report)
            connection.execute(
                "INSERT INTO triaged VALUES (?, ?) ON CONFLICT(anchor_id) DO UPDATE SET run_id=excluded.run_id",
                (anchor_id, run["id"]),
            )
            connection.execute(
                """INSERT INTO triage_evidence_state VALUES (?, ?)
                   ON CONFLICT(anchor_id) DO UPDATE SET verification_count=excluded.verification_count""",
                (anchor_id, reviewed),
            )
            connection.execute("DELETE FROM role_retries WHERE anchor_id=?", (anchor_id,))
            saved.append(run["id"])
    return {"investigated": len(saved), "runs": saved, "excluded": excluded, "retrying": retries}


def latest_revision(connection, anchor_id):
    row = connection.execute(
        """SELECT coalesce(s.verification_count,0) FROM triaged t
           LEFT JOIN triage_evidence_state s ON s.anchor_id=t.anchor_id WHERE t.anchor_id=?""",
        (anchor_id,),
    ).fetchone()
    return row[0] if row else -1
