#!/usr/bin/env python3
"""Scrapling fetch sidecar.

Speaks the solver JSON protocol the stealth library's HTTPSolver expects, so
the crawler can use Scrapling as an escalation tier:

    POST /v1/fetch
    {"url": "https://example.com", "method": "GET", "headers": {...},
     "timeout_ms": 30000, "wait_ms": 0, "solve": true}
    → 200 {"status": 200, "url": "https://example.com/", "html": "<html>…",
           "headers": {...}, "solver": "scrapling", "elapsed_ms": 1234}

Scrapling's StealthyFetcher is the interesting part: it spoofs the TLS
fingerprint and drives a real browser, so it answers walls that a plain
client cannot — the same class of wall the crawler's other tiers hit.

The server is deliberately stdlib-only. Scrapling's own dependency tree is
the whole environment; adding a web framework on top of it buys nothing.

Run it with Scrapling importable:

    uv run python server.py            # inside the scrapling image
    python server.py                   # any env with scrapling installed
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY_BYTES = 1 << 20
DEFAULT_TIMEOUT_MS = 30_000
MAX_TIMEOUT_MS = 180_000

# One fetcher for the whole process: the browser it drives is expensive, and
# a fresh one per request is how a sidecar falls over under load.
_fetcher = None
_fetcher_lock = threading.Lock()


def _get_fetcher():
    """Return the shared StealthyFetcher, creating it on first use."""
    global _fetcher
    if _fetcher is None:
        with _fetcher_lock:
            if _fetcher is None:
                from scrapling.fetchers import StealthyFetcher

                _fetcher = StealthyFetcher()
    return _fetcher


def _fetch(url: str, headers: dict, timeout_ms: int, wait_ms: int) -> tuple[int, str, str, dict]:
    """Fetch the URL and return (status, final_url, html, headers)."""
    fetcher = _get_fetcher()
    kwargs: dict = {"timeout": max(1, timeout_ms // 1000)}
    if wait_ms:
        kwargs["wait"] = wait_ms / 1000
    if headers:
        kwargs["headers"] = headers

    page = fetcher.fetch(url, **kwargs)
    status = int(getattr(page, "status", 200) or 200)
    final_url = str(getattr(page, "url", url) or url)
    html = getattr(page, "html_content", "") or ""
    if not isinstance(html, str):
        html = str(html)
    response_headers = getattr(page, "headers", {}) or {}
    if not isinstance(response_headers, dict):
        response_headers = {}
    return status, final_url, html, response_headers


class Handler(BaseHTTPRequestHandler):
    server_version = "brandbrain-scrapling-sidecar/1.0"

    def log_message(self, fmt, *args):  # noqa: A003 - stdlib hook
        sys.stderr.write("scrapling-sidecar: " + (fmt % args) + "\n")

    def _write_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 - stdlib hook
        if self.path.rstrip("/") in ("/health", ""):
            self._write_json(200, {"status": "ok", "solver": "scrapling"})
            return
        self._write_json(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802 - stdlib hook
        if self.path.rstrip("/") != "/v1/fetch":
            self._write_json(404, {"error": "not found"})
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._write_json(400, {"error": "invalid content length"})
            return
        if length <= 0 or length > MAX_BODY_BYTES:
            self._write_json(400, {"error": "invalid body length"})
            return

        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            self._write_json(400, {"error": f"invalid json: {exc}"})
            return

        url = str(payload.get("url") or "").strip()
        if not url:
            self._write_json(400, {"error": "url is required"})
            return

        timeout_ms = int(payload.get("timeout_ms") or DEFAULT_TIMEOUT_MS)
        timeout_ms = max(1, min(timeout_ms, MAX_TIMEOUT_MS))
        wait_ms = int(payload.get("wait_ms") or 0)
        headers = payload.get("headers") or {}
        if not isinstance(headers, dict):
            headers = {}

        started = time.time()
        try:
            status, final_url, html, response_headers = _fetch(url, headers, timeout_ms, wait_ms)
        except Exception as exc:  # noqa: BLE001 - the sidecar reports, it does not crash
            self._write_json(200, {"error": f"{type(exc).__name__}: {exc}"})
            return

        self._write_json(
            200,
            {
                "status": status,
                "url": final_url,
                "html": html,
                "headers": {str(k): str(v) for k, v in response_headers.items()},
                "solver": "scrapling",
                "elapsed_ms": int((time.time() - started) * 1000),
            },
        )


def main() -> None:
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    sys.stderr.write(f"scrapling-sidecar listening on :{port}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
