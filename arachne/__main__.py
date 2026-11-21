"""Black Arachne command line."""

import argparse
from contextlib import nullcontext
import json
import os
import sqlite3
import sys
from urllib.error import HTTPError, URLError

from .events import Event, from_journal, read_records
from .lab import run_lab
from .reasoning import investigate
from .store import database, episode, ingest, save_run
from .web import serve


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
    demo = commands.add_parser("demo", help="Run and store synthetic smoke cases")
    demo.add_argument("--model")
    dashboard = commands.add_parser("serve")
    dashboard.add_argument("--port", type=int, default=8765)
    return app


def main(argv=None):
    options = parser().parse_args(argv)
    try:
        if options.command == "serve":
            serve(options.db, options.port)
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
                result = save_run(connection, investigate(anchor, events, options.model))
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
