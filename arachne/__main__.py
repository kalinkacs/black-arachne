"""Black Arachne command line."""

import argparse
from contextlib import nullcontext
from functools import partial
import json
import os
from pathlib import Path
import sqlite3
import sys
from urllib.error import HTTPError, URLError

from . import __version__
from .evaluation import evaluate
from .events import Event, from_journal, read_records
from .files import FILE_LIMITS, load_indicators, scan
from .integrity import baseline_catalog, establish, observe, recent_findings, scheduled_checks
from .lab import run_lab
from .mimicry import mimic
from .operations import collect, operational_review, triage
from .pilot import since_cutoff, summary as pilot_summary
from .provenance import SOURCE_KINDS, create_key, load_key, sign_record
from .store import (
    confirm_outcome, database, episode, import_verifications, ingest, save_run, status_snapshot, verify_audit,
)
from .web import serve


def positive_int(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("Must be positive")
    return number


def model_options(command, default=None):
    backend = command.add_mutually_exclusive_group()
    backend.add_argument("--model", help="Enable an external model for both roles")
    backend.add_argument("--offline", dest="model", action="store_const", const=None,
                         help="Use local role processes even if ARACHNE_MODEL is set")
    command.set_defaults(model=default)


def parser():
    app = argparse.ArgumentParser(prog="python -m arachne", description="Linux defensive investigation and review")
    app.add_argument("--version", action="version", version=f"Black Arachne {__version__}")
    app.add_argument("--db", default="arachne.sqlite3", help="SQLite evidence file")
    commands = app.add_subparsers(dest="command", required=True)
    for name in ("import-events", "import-journal"):
        command = commands.add_parser(name)
        command.add_argument("file", nargs="?", default="-", help="JSONL file or stdin")
        if name == "import-journal":
            command.add_argument("--native", action="store_true", help="Require trusted executable metadata on exported journal records")
    key = commands.add_parser("create-verifier", help="Create a scoped private key for an independent evidence source")
    key.add_argument("file")
    key.add_argument("--id", required=True)
    key.add_argument("--source", choices=SOURCE_KINDS, required=True)
    key.add_argument("--host", required=True)
    seal = commands.add_parser("sign-verifications", help="Sign normalized verification records for one SSH login")
    seal.add_argument("file")
    seal.add_argument("--key", required=True)
    seal.add_argument("--anchor", required=True)
    verified = commands.add_parser("import-verifications", help="Authenticate signed evidence and associate it with the login")
    verified.add_argument("file")
    verified.add_argument("--key", required=True)
    anchors = commands.add_parser("anchors", help="Print recent SSH login anchors")
    anchors.add_argument("--host")
    run = commands.add_parser("investigate", help="Create one immutable investigation snapshot")
    run.add_argument("host")
    run.add_argument("anchor")
    model_options(run)
    collector = commands.add_parser("collect", help="Import local journal with a durable checkpoint")
    collector.add_argument("--since", default="30 minutes ago", help="Initial journal window")
    cycle = commands.add_parser("cycle", help="Collect local Linux events and investigate pending logins")
    cycle.add_argument("--since", default="30 minutes ago", help="Initial journal window")
    worker = commands.add_parser("triage", help="Investigate mature SSH events once")
    for command in (cycle, worker):
        model_options(command, default=os.environ.get("ARACHNE_MODEL"))
        command.add_argument("--limit", type=int, choices=range(1, 101), default=20, metavar="1..100")
    review = commands.add_parser("confirm-outcome", help="Record an operator-verified decision")
    review.add_argument("run_id")
    review.add_argument("decision", choices=("close", "review", "escalate"))
    review.add_argument("--note", required=True)
    demo = commands.add_parser("demo", help="Run and store synthetic smoke cases")
    demo.add_argument("--model")
    benchmark = commands.add_parser("evaluate", help="Compare reviewers on labeled JSONL episodes")
    benchmark.add_argument("file")
    model_options(benchmark)
    trial = commands.add_parser("trial", help="Run the packaged perspective comparison and save its dossiers")
    model_options(trial)
    scanner = commands.add_parser("scan-files", help="Compare local file hashes with trusted SHA-256 indicators")
    scanner.add_argument("directory")
    scanner.add_argument("--indicators", required=True)
    scanner.add_argument("--max-files", type=positive_int, default=1000)
    scanner.add_argument("--max-file-mib", type=positive_int, default=32)
    scanner.add_argument("--max-total-mib", type=positive_int, default=256)
    baseline = commands.add_parser("integrity-baseline", help="Record a complete local file integrity baseline")
    baseline.add_argument("directory")
    baseline.add_argument("--name", required=True)
    baseline.add_argument("--max-files", type=positive_int, default=FILE_LIMITS["max_files"])
    baseline.add_argument("--max-file-mib", type=positive_int, default=FILE_LIMITS["max_bytes"] // 1024**2)
    baseline.add_argument("--max-total-mib", type=positive_int, default=FILE_LIMITS["total_bytes"] // 1024**2)
    integrity_check = commands.add_parser("integrity-check", help="Compare real files against a baseline")
    integrity_check.add_argument("baseline")
    commands.add_parser("integrity-list", help="List file baselines and findings")
    pilot = commands.add_parser("pilot-report", help="Export aggregate observation-mode pilot metrics as JSON")
    pilot.add_argument("--since", help="Only include telemetry and dossiers at or after this RFC3339 timestamp")
    commands.add_parser("status", help="Print local collection and triage status")
    commands.add_parser("verify-audit", help="Verify linkage and content of operator outcomes")
    dashboard = commands.add_parser("serve")
    dashboard.add_argument("--operator", action="store_true", help="Enable local confirmation forms")
    dashboard.add_argument("--port", type=int, default=8765)
    return app


def main(argv=None):
    options = parser().parse_args(argv)
    try:
        if options.command == "create-verifier":
            print(json.dumps(create_key(options.file, options.id, options.source, options.host), indent=2))
            return 0
        if options.command == "sign-verifications":
            key = load_key(options.key)
            with open(options.file, encoding="utf-8") as stream:
                for record in read_records(stream):
                    print(json.dumps(sign_record(key, options.anchor, Event.parse(record))))
            return 0
        if options.command == "scan-files":
            with open(options.indicators, encoding="utf-8") as stream:
                indicators = load_indicators(stream)
            result = scan(options.directory, indicators, max_files=options.max_files,
                          max_bytes=options.max_file_mib * 1024**2, total_bytes=options.max_total_mib * 1024**2)
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 2 if result["matched"] else 0
        if options.command == "integrity-baseline":
            limits = {"max_files": options.max_files, "max_bytes": options.max_file_mib * 1024**2,
                      "total_bytes": options.max_total_mib * 1024**2}
            print(json.dumps(establish(options.db, options.directory, options.name, limits), indent=2))
            return 0
        if options.command == "integrity-check":
            result = observe(options.db, options.baseline)
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return (2 if result["findings"] else 0) if result["complete"] else 3
        if options.command == "evaluate":
            with open(options.file, encoding="utf-8") as stream:
                print(json.dumps(evaluate(stream, options.model, analyze=mimic), indent=2))
            return 0
        if options.command == "serve":
            serve(options.db, options.port, options.operator)
            return 0
        if options.command in ("triage", "cycle"):
            collection = {}
            if options.command == "cycle":
                try:
                    with database(options.db) as connection:
                        connection.execute("BEGIN IMMEDIATE")
                        collection = collect(connection, options.since)
                except (OSError, ValueError) as error:
                    collection["journal_error"] = str(error)
                collection["integrity"] = scheduled_checks(options.db)
            print(json.dumps({**collection, **triage(options.db, options.model, options.limit)}, indent=2))
            failed_scan = any(not result["complete"] for result in collection.get("integrity", ()))
            return 1 if "journal_error" in collection or failed_scan else 0
        with database(options.db) as connection:
            if options.command in ("import-events", "import-journal"):
                normalize = Event.parse if options.command == "import-events" else partial(from_journal, native=options.native)
                stream = nullcontext(sys.stdin) if options.file == "-" else open(options.file, encoding="utf-8")
                with stream as source:
                    events = (normalize(record) for record in read_records(source) if isinstance(record, dict)
                              or options.command == "import-events")
                    result = {"inserted": ingest(connection, (event for event in events if event is not None))}
            elif options.command == "import-verifications":
                key = load_key(options.key)
                with open(options.file, encoding="utf-8") as stream:
                    result = import_verifications(connection, key, read_records(stream))
            elif options.command == "anchors":
                parameters = ()
                sql = "SELECT payload FROM events WHERE json_extract(payload, '$.kind') IN ('ssh_login', 'ssh_session_open')"
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
            elif options.command == "integrity-list":
                result = {"baselines": baseline_catalog(connection), "findings": recent_findings(connection)}
            elif options.command == "pilot-report":
                result = pilot_summary(connection, since_cutoff(options.since))
            elif options.command in ("status", "verify-audit"):
                result = status_snapshot(connection) if options.command == "status" else verify_audit(connection)
            elif options.command == "trial":
                cases = Path(__file__).parent / "data" / "trial.jsonl"
                with cases.open(encoding="utf-8") as stream:
                    result = evaluate(stream, options.model, analyze=mimic,
                                      on_case=lambda report: save_run(connection, report))
            else:
                result = run_lab(connection, options.model)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 2 if options.command == "verify-audit" and not result["valid"] else 0
    except KeyboardInterrupt:
        return 0
    except HTTPError as error:
        print(f"Model provider returned HTTP {error.code}", file=sys.stderr)
    except URLError as error:
        print(f"Model provider unavailable: {error.reason}", file=sys.stderr)
    except (OSError, ValueError, sqlite3.Error) as error:
        print(f"Black Arachne: {error}", file=sys.stderr)
    return 1


def cli():
    os.umask(0o077)
    return main()


if __name__ == "__main__":
    sys.exit(cli())
