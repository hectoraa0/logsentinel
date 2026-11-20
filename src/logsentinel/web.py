"""Tiny read-only web dashboard built on the standard library.

Security notes (on purpose, because log data is attacker-controlled):
  * the browser renders alerts with textContent only, never innerHTML
  * strict Content-Security-Policy: scripts/styles only from this origin
  * static files come from a fixed whitelist, so path traversal is impossible
  * the API is read-only and the database is opened with mode=ro
"""

from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .models import SEVERITIES
from .storage import fetch_alerts, fetch_stats

_STATIC_DIR = Path(__file__).parent / "static"
_STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/static/app.js": ("app.js", "application/javascript; charset=utf-8"),
    "/static/style.css": ("style.css", "text/css; charset=utf-8"),
}

_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'; "
        "frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "LogSentinel"
    sys_version = ""  # do not advertise the Python version

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in _SECURITY_HEADERS.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: object) -> None:
        self._send(status, json.dumps(payload).encode(), "application/json")

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        url = urlparse(self.path)
        db_path: str = self.server.db_path  # type: ignore[attr-defined]

        if url.path in _STATIC_FILES:
            filename, ctype = _STATIC_FILES[url.path]
            self._send(HTTPStatus.OK, (_STATIC_DIR / filename).read_bytes(), ctype)
        elif url.path == "/healthz":
            self._json(HTTPStatus.OK, {"status": "ok"})
        elif url.path == "/api/stats":
            self._json(HTTPStatus.OK, fetch_stats(db_path))
        elif url.path == "/api/alerts":
            severity = parse_qs(url.query).get("severity", [None])[0]
            if severity is not None and severity not in SEVERITIES:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid severity"})
                return
            self._json(HTTPStatus.OK, fetch_alerts(db_path, severity))
        else:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        # One compact line per request on stderr (visible in `docker logs`).
        print(f"{self.address_string()} {format % args}", flush=True)


def make_server(db_path: str, host: str = "127.0.0.1", port: int = 8000) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), DashboardHandler)
    server.db_path = db_path  # type: ignore[attr-defined]
    return server
