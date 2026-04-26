"""Python wrapper for the ``brwslab`` CLI — network fingerprint testing."""

from __future__ import annotations

from typing import Any

from ._base import CLIWrapper, FetchResult


class Brwslab(CLIWrapper):
    """Wrapper for the ``brwslab`` binary.

    Usage::

        from pybrwslab import Brwslab
        br = Brwslab()
        result = br.fetch("https://example.com", engine="chromium")
        print(result.body)
    """

    def __init__(self, binary_path: str | None = None) -> None:
        super().__init__("brwslab", binary_path)

    # ------------------------------------------------------------------
    # fetch
    # ------------------------------------------------------------------
    def fetch(
        self,
        url: str,
        *,
        engine: str = "native",
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str = "",
        proxy: str = "",
        timeout: str = "30s",
        follow_redirects: bool = True,
        session: str = "",
        output_format: str = "json",
    ) -> FetchResult:
        """Fetch a URL and return structured data.

        Args:
            url: Target URL.
            engine: One of ``native``, ``chromium``, ``firefox``, ``webkit``.
            method: HTTP method.
            headers: Extra HTTP headers.
            body: Request body.
            proxy: Proxy URL.
            timeout: Request timeout (e.g. ``"30s"``).
            follow_redirects: Whether to follow 3xx redirects.
            session: Existing session ID.
            output_format: ``json`` | ``pretty`` | ``raw``.
        """
        args = [
            "fetch", url,
            "--engine", engine,
            "--method", method,
            "--output", output_format,
            "--timeout", timeout,
        ]
        if proxy:
            args += ["--proxy", proxy]
        if body:
            args += ["--data", body]
        if session:
            args += ["--session", session]
        if headers:
            for k, v in headers.items():
                args += ["--header", f"{k}: {v}"]
        if not follow_redirects:
            args += ["--location=false"]

        data = self._run_json(*args)
        return FetchResult(
            status=data.get("status", 0),
            headers=data.get("headers", {}),
            body=data.get("body", ""),
            final_url=data.get("final_url", url),
            protocol=data.get("protocol", ""),
            timing_ms=data.get("timing", {}).get("Total", 0) if isinstance(data.get("timing"), dict) else None,
            trace=data.get("trace"),
        )

    # ------------------------------------------------------------------
    # fingerprint
    # ------------------------------------------------------------------
    def fingerprint(
        self,
        *,
        lab_url: str,
        engine: str = "native",
    ) -> dict[str, Any]:
        """Capture network fingerprint against a lab server.

        Args:
            lab_url: URL of a running ``labd`` instance.
            engine: Engine to fingerprint.
        """
        return self._run_json(
            "fingerprint",
            "--engine", engine,
            "--lab", lab_url,
        )

    # ------------------------------------------------------------------
    # diff
    # ------------------------------------------------------------------
    def diff(
        self,
        *,
        lab_url: str,
        engines: list[str] | None = None,
    ) -> dict[str, Any]:
        """Compare fingerprints across multiple engines.

        Args:
            lab_url: URL of a running ``labd`` instance.
            engines: List of engine names to compare (default ``["native", "chromium"]``).
        """
        engines = engines or ["native", "chromium"]
        args = ["diff", "--lab", lab_url]
        for eng in engines:
            args += ["--engine", eng]
        return self._run_json(*args)

    # ------------------------------------------------------------------
    # trace
    # ------------------------------------------------------------------
    def trace(
        self,
        url: str,
        *,
        engine: str = "native",
        timeout: str = "30s",
    ) -> dict[str, Any]:
        """Trace a request and return HAR-like data.

        Args:
            url: Target URL.
            engine: Engine to use.
            timeout: Request timeout.
        """
        return self._run_json(
            "trace", url,
            "--engine", engine,
            "--timeout", timeout,
        )

    # ------------------------------------------------------------------
    # engines
    # ------------------------------------------------------------------
    def list_engines(self) -> list[str]:
        """Return the list of available engines."""
        result = self._run("engines", check=False)
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip().startswith("-")]
        return [line.lstrip("- ").strip() for line in lines]

    # ------------------------------------------------------------------
    # session helpers
    # ------------------------------------------------------------------
    def session_new(self, name: str = "", engine: str = "chromium") -> str:
        """Create a new browser session and return its ID."""
        args = ["session", "new", "--engine", engine]
        if name:
            args += ["--name", name]
        result = self._run(*args)
        # Parse "Created session: <uuid>\nEngine: ..."
        for line in result.stdout.splitlines():
            if line.startswith("Created session:"):
                return line.split(":", 1)[1].strip()
        return ""

    def session_list(self) -> list[dict[str, str]]:
        """List all stored sessions."""
        result = self._run("session", "list", check=False)
        sessions: list[dict[str, str]] = []
        for line in result.stdout.splitlines()[1:]:
            parts = line.split(None, 3)
            if len(parts) >= 4:
                sessions.append({
                    "id": parts[0],
                    "name": parts[1],
                    "engine": parts[2],
                    "created": parts[3],
                })
        return sessions

    def session_delete(self, session_id: str) -> None:
        """Delete a session."""
        self._run("session", "delete", session_id)

    def session_export_cookies(self, session_id: str, output_path: str) -> None:
        """Export session cookies to a file."""
        self._run("session", "export-cookies", session_id, output_path)

    def session_import_cookies(self, session_id: str, input_path: str) -> None:
        """Import cookies into a session."""
        self._run("session", "import-cookies", session_id, input_path)
