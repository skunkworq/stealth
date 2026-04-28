"""Python wrapper for the ``agent`` CLI — browser automation agent loop.

This wrapper talks to the Go ``agent`` binary via subprocess, managing a
persistent Chrome session across calls through a shared session directory.

Usage::

    from pybrwslab import Agent

    agent = Agent(session_dir="/tmp/agent-session")

    # Observe a page
    ctx = agent.observe("https://example.com", format="compact")
    print(ctx["formatted"])          # LLM-ready prompt
    print(ctx["action_space"][0])    # first available action

    # Semantic enrichment (no LLM required)
    ctx = agent.observe(
        "https://example.com",
        semantic=True,
        format="semantic",
    )
    print(ctx["snapshot"]["semantic_tree"])
    print(ctx["snapshot"]["meta"])

    # Execute an action by dict
    result = agent.execute({
        "type": "click",
        "id": "E1_click",
        "selector": "a#submit"
    })

    # One-shot step: observe + execute decision
    result = agent.step(
        "https://example.com",
        decision="click_E1",
        format="compact"
    )

    # Clean up
    agent.stop()
"""

from __future__ import annotations

import json
from typing import Any

from ._base import CLIWrapper


class Agent(CLIWrapper):
    """Wrapper for the ``agent`` binary.

    Manages a persistent browser session via ``--session-dir``. Chrome is
    started automatically on the first call and reused across subsequent
    calls for fast multi-step agent loops.
    """

    def __init__(
        self,
        session_dir: str = "/tmp/pybrwslab-agent-session",
        binary_path: str | None = None,
        chrome_path: str = "",
    ) -> None:
        super().__init__("agent", binary_path)
        self.session_dir = session_dir
        self.chrome_path = chrome_path

    def _base_args(self) -> list[str]:
        """Return flags shared by every command."""
        args = ["--session-dir", self.session_dir]
        if self.chrome_path:
            args += ["--chrome-path", self.chrome_path]
        return args

    # ------------------------------------------------------------------
    # observe
    # ------------------------------------------------------------------
    def observe(
        self,
        url: str,
        *,
        format: str = "compact",
        max_elements: int = 50,
        semantic: bool = False,
        semantic_llm: bool = False,
        describe_images: bool = False,
        representation: str = "dom",
    ) -> dict[str, Any]:
        """Navigate to *url* and capture the full page context.

        Returns a dict with keys:
        - ``snapshot`` — :class:`PageSnapshot` dict
        - ``action_space`` — :class:`ActionSpace` dict
        - ``formatted`` — LLM-ready prompt string
        - ``representation`` — "dom" or "semantic"
        """
        args = [
            "observe",
            *self._base_args(),
            "--url", url,
            "--format", format,
            "--max-elements", str(max_elements),
            "--representation", representation,
        ]
        if semantic:
            args.append("--semantic")
        if semantic_llm:
            args.append("--semantic-llm")
        if describe_images:
            args.append("--describe-images")
        return self._run_json(*args)

    # ------------------------------------------------------------------
    # execute
    # ------------------------------------------------------------------
    def execute(self, action: dict[str, Any]) -> dict[str, Any]:
        """Execute a single action in the current session.

        *action* is a dict with at least ``type`` and ``id`` keys.
        Additional keys (``selector``, ``text``, etc.) depend on the action type.

        Returns a dict with keys:
        - ``success`` — bool
        - ``action_id`` — str
        - ``new_url`` — str (if navigation occurred)
        - ``scroll_delta`` — float
        - ``error`` — str (empty if success)
        """
        args = [
            "execute",
            *self._base_args(),
            "--action", json.dumps(action),
        ]
        return self._run_json(*args)

    # ------------------------------------------------------------------
    # step
    # ------------------------------------------------------------------
    def step(
        self,
        url: str,
        *,
        decision: str = "",
        format: str = "compact",
        max_elements: int = 50,
        semantic: bool = False,
        semantic_llm: bool = False,
        describe_images: bool = False,
        representation: str = "dom",
    ) -> dict[str, Any]:
        """Observe *url* and optionally execute a decision.

        This is a convenience method that combines :meth:`observe` and
        :meth:`execute` in a single subprocess call.

        Returns a dict with keys:
        - ``observation`` — dict with ``snapshot``, ``action_space``, ``formatted``
        - ``result`` — execution result dict (or ``None`` if no decision)
        """
        args = [
            "step",
            *self._base_args(),
            "--url", url,
            "--format", format,
            "--max-elements", str(max_elements),
            "--representation", representation,
        ]
        if decision:
            args += ["--decision", decision]
        if semantic:
            args.append("--semantic")
        if semantic_llm:
            args.append("--semantic-llm")
        if describe_images:
            args.append("--describe-images")
        return self._run_json(*args)

    # ------------------------------------------------------------------
    # session management
    # ------------------------------------------------------------------
    def stop(self) -> dict[str, Any]:
        """Kill the Chrome process and clean up the session.

        Returns ``{"stopped": true}``.
        """
        args = ["session-stop", *self._base_args()]
        return self._run_json(*args)

    def __enter__(self) -> Agent:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()
