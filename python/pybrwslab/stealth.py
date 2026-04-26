"""Python wrapper for the ``stealth`` CLI — spider / fetch / lab."""

from __future__ import annotations

import json
from typing import Any

from ._base import CLIWrapper, FetchResult


class Stealth(CLIWrapper):
    """Wrapper for the ``stealth`` binary.

    Usage::

        from pybrwslab import Stealth
        st = Stealth()
        result = st.fetch("https://example.com", engine="chromium-stealth")
        print(result.body)
    """

    def __init__(self, binary_path: str | None = None) -> None:
        super().__init__("stealth", binary_path)

    # ------------------------------------------------------------------
    # fetch
    # ------------------------------------------------------------------
    def fetch(
        self,
        url: str,
        *,
        engine: str = "native",
        json_output: bool = True,
    ) -> FetchResult | dict[str, Any]:
        """Fetch a URL with stealth and optional semantic extraction.

        Args:
            url: Target URL.
            engine: Engine name (e.g. ``native``, ``chromium-stealth``).
            json_output: Return parsed JSON when True, otherwise pretty text.
        """
        args = ["fetch", url, "-e", engine]
        if json_output:
            args.append("-j")

        result = self._run(*args)
        if not json_output:
            return FetchResult(
                status=0,
                headers={},
                body=result.stdout,
                final_url=url,
                protocol="",
            )

        data = json.loads(result.stdout)
        return FetchResult(
            status=0,
            headers={},
            body=result.stdout,
            final_url=url,
            protocol="",
        )

    # ------------------------------------------------------------------
    # crawl
    # ------------------------------------------------------------------
    def crawl(
        self,
        spider_name: str,
        *,
        engine: str = "native",
        depth: int = 5,
        concurrent: int = 16,
        timeout: str = "30s",
    ) -> str:
        """Run a spider crawl.

        Args:
            spider_name: Name of the spider to run.
            engine: Engine to use for requests.
            depth: Max crawl depth.
            concurrent: Max concurrent requests.
            timeout: Per-request timeout.
        """
        result = self._run(
            "crawl",
            "-s", spider_name,
            "-e", engine,
            "-d", str(depth),
            "-c", str(concurrent),
            "-t", timeout,
            check=False,
        )
        return result.stdout

    # ------------------------------------------------------------------
    # list
    # ------------------------------------------------------------------
    def list_spiders(self) -> list[str]:
        """Return available spider names."""
        result = self._run("list", check=False)
        spiders: list[str] = []
        in_spiders = False
        for line in result.stdout.splitlines():
            if "spiders" in line.lower():
                in_spiders = True
                continue
            if "engines" in line.lower():
                in_spiders = False
                continue
            if in_spiders and line.strip().startswith("-"):
                spiders.append(line.lstrip("- ").strip())
        return spiders

    def list_engines(self) -> list[str]:
        """Return available engine names."""
        result = self._run("list", check=False)
        engines: list[str] = []
        in_engines = False
        for line in result.stdout.splitlines():
            if "engines" in line.lower():
                in_engines = True
                continue
            if in_engines and line.strip().startswith("-"):
                engines.append(line.lstrip("- ").strip())
        return engines

    # ------------------------------------------------------------------
    # lab
    # ------------------------------------------------------------------
    def lab_start(
        self,
        *,
        http_port: int = 8080,
        https_port: int = 8443,
        proxy_port: int = 8081,
        proxy_mode: str = "mitm",
        chrome: bool = False,
        chrome_path: str = "",
        store_dir: str = "",
        verbose: bool = False,
    ) -> subprocess.Popen[str]:
        """Start the fingerprint capture lab server in the background.

        Returns a :class:`subprocess.Popen` handle.  The caller is
        responsible for terminating it (``proc.terminate()``).
        """
        import subprocess

        args = [
            self._binary_path, "lab",
            "--port", str(http_port),
            "--https-port", str(https_port),
            "--proxy-port", str(proxy_port),
            "--proxy-mode", proxy_mode,
        ]
        if chrome:
            args.append("--chrome")
        if chrome_path:
            args += ["--chrome-path", chrome_path]
        if store_dir:
            args += ["--store", store_dir]
        if verbose:
            args.append("-v")

        return subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    # ------------------------------------------------------------------
    # train
    # ------------------------------------------------------------------
    def train(
        self,
        urls: list[str],
        *,
        output_dir: str = "",
        proxy_port: int = 18081,
        chrome_path: str = "",
        page_wait: str = "5s",
        no_scroll: bool = False,
        verbose: bool = False,
    ) -> str:
        """Run an automated browser fingerprint training session.

        Args:
            urls: List of URLs to capture.
            output_dir: Directory to save training data.
            proxy_port: MITM proxy port for TLS capture.
            chrome_path: Path to Chrome executable.
            page_wait: Wait time after page load.
            no_scroll: Disable page scrolling.
            verbose: Verbose logging.
        """
        args = [
            "train",
            "--urls", ",".join(urls),
            "--proxy-port", str(proxy_port),
            "--page-wait", page_wait,
        ]
        if output_dir:
            args += ["--output", output_dir]
        if chrome_path:
            args += ["--chrome-path", chrome_path]
        if no_scroll:
            args.append("--no-scroll")
        if verbose:
            args.append("-v")

        result = self._run(*args, check=False)
        return result.stdout
