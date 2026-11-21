"""Black Arachne command line."""

import argparse
from contextlib import nullcontext
import json
import os
import sqlite3
import sys
from urllib.error import HTTPError, URLError

from .evaluation import evaluate
from .events import Event, from_journal, read_records
from .files import load_indicators, scan
from .lab import run_lab
from .operations import collect, operational_review, triage
from .store import confirm_outcome, database, episode, ingest, save_run
from .web import serve


def positive_int(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("Must be positive")
    return number


def parser():
    app = argparse.ArgumentParser(prog="python -m arachne", description="Linux defensive investigation and review")
    app.add_argument("--db", default="arachne.sqlite3", help="SQLite evidence file")
    commands = app.add_subparsers(dest="command", required=True)
    for name in ("import-events", "import-journal"):
        command = commands.add_parser(name)
        command.add_argument("file", nargs="?", default="-", help="JSONL file or stdin")
    anchors = commands.add_parser("anchors", help="Print recent SSH login anchors")
    anchors.add_argument("--host")
    run = commands.add_parser("investigate", help="Create one immutable investigation snapshot")
    run.add_argument("host")
    run.add_argument("anchor")
    run.add_argument("--model", help="Optional OpenAI model with structured output support")
    collector = commands.add_parser("collect", help="Import local journal with a durable checkpoint")
    collector.add_argument("--since", default="30 minutes ago", help="Initial journal window")
    cycle = commands.add_parser("cycle", help="Collect local Linux events and investigate pending logins")
    cycle.add_argument("--since", default="30 minutes ago", help="Initial journal window")
    worker = commands.add_parser("triage", help="Investigate mature SSH events once")
    for command in (cycle, worker):
        command.add_argument("--model", default=os.environ.get("ARACHNE_MODEL"), help="Enable both model-assisted roles")
        command.add_argument("--limit", type=int, choices=range(1, 101), default=20, metavar="1..100")
    review = commands.add_parser("confirm-outcome", help="Record an operator-verified decision")
    review.add_argument("run_id")
    review.add_argument("decision", choices=("close", "review", "escalate"))
    review.add_argument("--note", required=True)
    demo = commands.add_parser("demo", help="Run and store synthetic smoke cases")
    demo.add_argument("--model")
    benchmark = commands.add_parser("evaluate", help="Compare reviewers on labeled JSONL episodes")
    benchmark.add_argument("file")
    benchmark.add_argument("--model")
    scanner = commands.add_parser("scan-files", help="Compare local file hashes with trusted SHA-256 indicators")
    scanner.add_argument("directory")
    scanner.add_argument("--indicators", required=True)
    scanner.add_argument("--max-files", type=positive_int, default=1000)
    scanner.add_argument("--max-file-mib", type=positive_int, default=32)
    scanner.add_argument("--max-total-mib", type=positive_int, default=256)
    dashboard = commands.add_parser("serve")
    dashboard.add_argument("--port", type=int, default=8765)
    return app


def main(argv=None):
    options = parser().parse_args(argv)
    try:
        if options.command == "scan-files":
            with open(options.indicators, encoding="utf-8") as stream:
                indicators = load_indicators(stream)
            result = scan(options.directory, indicators, max_files=options.max_files,
                          max_bytes=options.max_file_mib * 1024**2, total_bytes=options.max_total_mib * 1024**2)
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 2 if result["matched"] else 0
        if options.command == "evaluate":
            with open(options.file, encoding="utf-8") as stream:
                print(json.dumps(evaluate(stream, options.model), indent=2))
            return 0
        if options.command == "serve":
            serve(options.db, options.port)
            return 0
        if options.command in ("triage", "cycle"):
            collection = {}
            if options.command == "cycle":
                with database(options.db) as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    collection = collect(connection, options.since)
            print(json.dumps({**collection, **triage(options.db, options.model, options.limit)}, indent=2))
            return 0
        with database(options.db) as connection:
            if options.command in ("import-events", "import-journal"):
                normalize = Event.parse if options.command == "import-events" else from_journal
                stream = nullcontext(sys.stdin) if options.file == "-" else open(options.file, encoding="utf-8")
                with stream as source:
                    events = (normalize(record) for record in read_records(source) if isinstance(record, dict)
                              or options.command == "import-events")
                    result = {"inserted": ingest(connection, (event for event in events if event is not None))}
            elif options.command == "anchors":
                parameters = ("ssh_login",)
                sql = "SELECT payload FROM events WHERE json_extract(payload, '$.kind') = ?"
                if options.host:
                    sql += " AND host = ?"
                    parameters += (options.host,)
                sql += " ORDER BY timestamp DESC, id LIMIT 100"
                result = [json.loads(row[0]) for row in connection.execute(sql, parameters)]
            elif options.command == "investigate":
                anchor, events = episode(connection, options.host, options.anchor)
                result = save_run(connection, operational_review(connection, anchor, events, options.model))
            elif options.command == "collect":
                connection.execute("BEGIN IMMEDIATE")
                result = collect(connection, options.since)
            elif options.command == "confirm-outcome":
                confirm_outcome(connection, options.run_id, options.decision, options.note)
                result = {"confirmed": options.run_id}
            else:
                result = run_lab(connection, options.model)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except KeyboardInterrupt:
        return 0
    except HTTPError as error:
        print(f"Model provider returned HTTP {error.code}", file=sys.stderr)
    except URLError as error:
        print(f"Model provider unavailable: {error.reason}", file=sys.stderr)
    except (OSError, ValueError, sqlite3.Error) as error:
        print(f"Black Arachne: {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    os.umask(0o077)
    sys.exit(main())
