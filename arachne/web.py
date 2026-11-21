"""Local read-only dashboard."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from .store import database, get_run, list_runs

STATIC = Path(__file__).parent / "static"
ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}


def handler(path):
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

        def do_GET(self):
            host = self.headers.get("Host", "")
            if host.split(":", 1)[0] != "127.0.0.1":
                return self.send_json(403, {"error": "Use the localhost address shown at startup."})
            route = urlsplit(self.path).path
            if route in ASSETS:
                filename, mime = ASSETS[route]
                return self.respond(200, mime, (STATIC / filename).read_bytes())
            if route == "/api/runs":
                with database(path) as connection:
                    runs = list_runs(connection)
                keys = ("id", "created", "host", "scenario", "label", "blue", "assisted")
                return self.send_json(200, [{key: run.get(key) for key in keys} for run in runs])
            match = re.fullmatch(r"/api/runs/([a-f0-9]{32})", route)
            if match:
                with database(path) as connection:
                    run = get_run(connection, match[1])
                if run:
                    return self.send_json(200, run)
            return self.send_json(404, {"error": "Not found"})

    return Handler


def serve(path, port):
    with database(path):
        pass
    with ThreadingHTTPServer(("127.0.0.1", port), handler(path)) as server:
        print(f"Black Arachne · http://127.0.0.1:{server.server_port}", flush=True)
        server.serve_forever()
