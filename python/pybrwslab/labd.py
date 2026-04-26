"""Python wrapper for the ``labd`` CLI — fingerprint capture lab server."""

from __future__ import annotations

import json
import subprocess
from typing import Any

from ._base import CLIWrapper


class Labd(CLIWrapper):
    """Wrapper for the ``labd`` binary.

    Usage::

        from pybrwslab import Labd
        lab = Labd()
        proc = lab.start(http_port=8080, https_port=8443)
        # ... do work ...
        lab.stop(proc)
    """

    def __init__(self, binary_path: str | None = None) -> None:
        super().__init__("labd", binary_path)

    def start(
        self,
        *,
        http_port: int = 8080,
        https_port: int = 8443,
        proxy_port: int = 8081,
        tls_cert: str = "",
        tls_key: str = "",
        store_dir: str = "",
        chrome: bool = False,
        chrome_path: str = "",
        verbose: bool = False,
    ) -> subprocess.Popen[str]:
        """Start the lab server as a background process.

        Returns a :class:`subprocess.Popen` handle.  Call
        ``lab.stop(proc)`` when done.
        """
        args = [
            self._binary_path,
            "--http-port", str(http_port),
            "--https-port", str(https_port),
            "--proxy-port", str(proxy_port),
        ]
        if tls_cert:
            args += ["--tls-cert", tls_cert]
        if tls_key:
            args += ["--tls-key", tls_key]
        if store_dir:
            args += ["--store", store_dir]
        if chrome:
            args.append("--chrome")
        if chrome_path:
            args += ["--chrome-path", chrome_path]
        if verbose:
            args.append("-v")

        return subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    @staticmethod
    def stop(proc: subprocess.Popen[str]) -> tuple[str, str]:
        """Terminate a running lab server and capture remaining output."""
        proc.terminate()
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
        return stdout, stderr

    def capture_json(
        self,
        lab_url: str = "http://localhost:8080",
    ) -> dict[str, Any]:
        """Fetch the current fingerprint capture as JSON.

        This is a pure-HTTP helper; it does not require the ``labd``
        binary to be running locally.
        """
        import urllib.request

        with urllib.request.urlopen(f"{lab_url}/capture/json") as resp:
            return json.load(resp)

    def capture_yaml(
        self,
        lab_url: str = "http://localhost:8080",
    ) -> str:
        """Fetch the current fingerprint capture as YAML."""
        import urllib.request

        with urllib.request.urlopen(f"{lab_url}/capture/yaml") as resp:
            return resp.read().decode("utf-8")

    def health(self, lab_url: str = "http://localhost:8080") -> dict[str, Any]:
        """Check lab server health."""
        import urllib.request

        with urllib.request.urlopen(f"{lab_url}/health") as resp:
            return json.load(resp)
