"""Read-only collection and scheduled defensive triage for a single Linux deployment."""

from datetime import datetime, timezone
import subprocess

from .events import POST_LOGIN_OBSERVATION, from_journal, read_records
from .mimicry import mimic
from .store import confirmed_history, database, episode, ingest, save_run

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
            event = from_journal(row)
            if event:
                yield event

    inserted = ingest(connection, normalize())
    if last is not None:
        connection.execute(
            """INSERT INTO collector_state VALUES ('local_journal', ?)
               ON CONFLICT(name) DO UPDATE SET cursor = excluded.cursor""",
            (last,),
        )
    return {"inserted": inserted, "checkpoint_advanced": last != cursor}


def operational_review(connection, anchor, events, model):
    history = confirmed_history(connection, anchor, events)
    return mimic(anchor, events, history, model)


def triage(path, model=None, limit=20, now=None):
    now = now or datetime.now(timezone.utc)
    ready = (now - POST_LOGIN_OBSERVATION).isoformat(timespec="microseconds")
    with database(path) as connection:
        pending = connection.execute(
            """SELECT e.host, e.id FROM events e LEFT JOIN triaged t ON t.anchor_id=e.id
               WHERE t.anchor_id IS NULL AND e.timestamp <= ?
               AND json_extract(e.payload, '$.kind')='ssh_login'
               AND json_extract(e.payload, '$.source')='systemd-journal'
               ORDER BY e.timestamp, e.id LIMIT ?""",
            (ready, limit),
        ).fetchall()

    saved = []
    for host, anchor_id in pending:
        with database(path) as connection:
            anchor, events = episode(connection, host, anchor_id)
            report = operational_review(connection, anchor, events, model)
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("SELECT 1 FROM triaged WHERE anchor_id = ?", (anchor_id,)).fetchone():
                continue
            run = save_run(connection, report)
            connection.execute("INSERT INTO triaged VALUES (?, ?)", (anchor_id, run["id"]))
            saved.append(run["id"])
    return {"investigated": len(saved), "runs": saved}
