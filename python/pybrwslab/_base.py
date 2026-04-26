"""Base utilities for pybrwslab CLI wrappers."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any


class BrwslabError(Exception):
    """Raised when a CLI command fails."""

    def __init__(self, message: str, returncode: int | None = None, stderr: str = ""):
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


@dataclass
class FetchResult:
    """Result of a fetch operation."""

    status: int
    headers: dict[str, list[str]]
    body: str
    final_url: str
    protocol: str
    timing_ms: float | None = None
    trace: dict[str, Any] | None = None


class CLIWrapper:
    """Base wrapper for a Go CLI binary."""

    def __init__(self, binary_name: str, binary_path: str | None = None) -> None:
        self.binary_name = binary_name
        self._binary_path = binary_path or shutil.which(binary_name)
        if self._binary_path is None:
            raise BrwslabError(
                f"Binary '{binary_name}' not found in PATH. "
                f"Build the project with: go build -o build/{binary_name} ./cmd/{binary_name}"
            )

    def _run(
        self,
        *args: str,
        capture_json: bool = False,
        check: bool = True,
        input_data: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run the CLI with the given arguments."""
        cmd = [self._binary_path, *args]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            input=input_data,
            check=False,
        )
        if check and result.returncode != 0:
            raise BrwslabError(
                f"{' '.join(cmd)} failed: {result.stderr}",
                returncode=result.returncode,
                stderr=result.stderr,
            )
        return result

    def _run_json(self, *args: str, **kwargs: Any) -> Any:
        """Run the CLI and parse JSON output."""
        result = self._run(*args, capture_json=True, **kwargs)
        stdout = result.stdout.strip()
        if not stdout:
            return {}
        try:
            return json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise BrwslabError(f"Failed to parse JSON: {exc}\nOutput: {stdout[:500]}") from exc

    def version(self) -> str:
        """Return the binary version."""
        result = self._run("version", check=False)
        if result.returncode == 0:
            return result.stdout.strip()
        return "unknown"
