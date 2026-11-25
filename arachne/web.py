"""Loopback-only dashboard with an explicitly enabled local operator console."""

import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import secrets
import sqlite3
from urllib.parse import urlsplit

from .dead_souls import overview
from .integrity import baseline_catalog, recent_findings
from .store import confirm_outcome, database, get_outcome, get_run, list_runs, status_snapshot

STATIC = Path(__file__).parent / "static"
ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}
RUN_URL = re.compile(r"/api/runs/([a-f0-9]{32})")
OUTCOME_URL = re.compile(r"/api/runs/([a-f0-9]{32})/outcome")
MAX_BODY = 12_000


def handler(path, operator=False):
    csrf_token = secrets.token_urlsafe(32) if operator else None

    class Handler(BaseHTTPRequestHandler):
        def respond(self, status, mime, data):
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(data)

        def send_json(self, status, value):
            self.respond(status, "application/json; charset=utf-8", json.dumps(value, ensure_ascii=False).encode())

        def local_host(self):
            return f"127.0.0.1:{self.server.server_port}"

        def do_GET(self):
            if self.headers.get("Host") != self.local_host():
                return self.send_json(403, {"error": "Use the localhost address shown at startup."})
            route = urlsplit(self.path).path
            if route in ASSETS:
                filename, mime = ASSETS[route]
                return self.respond(200, mime, (STATIC / filename).read_bytes())
            if route == "/api/session":
                return self.send_json(200, {"operator": operator, "csrf": csrf_token})
            if route == "/api/status":
                with database(path) as connection:
                    return self.send_json(200, status_snapshot(connection))
            if route == "/api/dead-souls":
                with database(path) as connection:
                    return self.send_json(200, overview(connection))
            if route == "/api/integrity":
                with database(path) as connection:
                    return self.send_json(200, {"baselines": baseline_catalog(connection), "findings": recent_findings(connection)})
            if route == "/api/runs":
                with database(path) as connection:
                    runs = list_runs(connection)
                keys = ("id", "created", "host", "scenario", "label", "blue", "assisted")
                return self.send_json(200, [{key: run.get(key) for key in keys} for run in runs])
            match = RUN_URL.fullmatch(route)
            if match:
                with database(path) as connection:
                    run = get_run(connection, match[1])
                    if run:
                        return self.send_json(200, {**run, "outcome": get_outcome(connection, match[1])})
            return self.send_json(404, {"error": "Not found"})

        def do_POST(self):
            route = urlsplit(self.path).path
            match = OUTCOME_URL.fullmatch(route)
            if not match:
                return self.send_json(404, {"error": "Not found"})
            if not operator:
                return self.send_json(403, {"error": "Operator mode is disabled"})
            supplied = self.headers.get("X-Arachne-Operator", "").encode()
            if (
                self.headers.get("Host") != self.local_host()
                or self.headers.get("Origin") != f"http://{self.local_host()}"
                or not hmac.compare_digest(supplied, csrf_token.encode())
            ):
                return self.send_json(403, {"error": "Local session verification failed"})
            if self.headers.get_content_type() != "application/json":
                return self.send_json(415, {"error": "Expected application/json"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return self.send_json(400, {"error": "Invalid Content-Length"})
            if not 0 < length <= MAX_BODY:
                return self.send_json(413, {"error": "Invalid outcome payload size"})
            try:
                data = json.loads(self.rfile.read(length))
                if not isinstance(data, dict) or set(data) != {"decision", "note"}:
                    raise ValueError("Provide decision and note")
                with database(path) as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    if get_run(connection, match[1]) is None:
                        return self.send_json(404, {"error": "Run does not exist"})
                    if get_outcome(connection, match[1]):
                        return self.send_json(409, {"error": "This outcome was already confirmed"})
                    outcome = confirm_outcome(connection, match[1], data["decision"], data["note"])
            except ValueError as error:
                return self.send_json(422, {"error": str(error)})
            except sqlite3.OperationalError:
                return self.send_json(503, {"error": "Database busy or unavailable"})
            return self.send_json(201, outcome)

    return Handler


def serve(path, port, operator=False):
    with database(path):
        pass
    with ThreadingHTTPServer(("127.0.0.1", port), handler(path, operator)) as server:
        print(f"Black Arachne · http://127.0.0.1:{server.server_port}", flush=True)
        server.serve_forever()
