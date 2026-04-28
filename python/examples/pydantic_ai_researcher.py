"""
Pydantic AI Research Agent — Web Research via Stealth Browser Automation

This example shows how to combine Pydantic AI (agent framework) with
pybrwslab.Agent (browser automation) to build an autonomous web researcher.

The agent receives a research question, browses the web to find answers,
and returns a structured research report.

Usage::

    export OPENAI_API_KEY="sk-..."
    python pydantic_ai_researcher.py "What is the current price of NVIDIA stock?"

Requires::

    pip install pydantic-ai pybrwslab
    # And the Go agent binary in PATH:
    #   go build -o build/agent ./cmd/agent

"""

from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext

# pybrwslab must be importable (add project root to PYTHONPATH if needed)
from pybrwslab import Agent as BrowserAgent


# ---------------------------------------------------------------------------
# Structured output model
# ---------------------------------------------------------------------------

class ResearchReport(BaseModel):
    """Structured research report returned by the agent."""

    query: str = Field(description="The original research question")
    findings: list[str] = Field(
        default_factory=list,
        description="Key facts discovered during research",
    )
    sources: list[str] = Field(
        default_factory=list,
        description="URLs of pages visited",
    )
    answer: str = Field(
        description="A concise answer to the research question",
    )
    confidence: str = Field(
        description="Confidence level: high | medium | low",
        pattern="^(high|medium|low)$",
    )


# ---------------------------------------------------------------------------
# Agent dependencies (shared state)
# ---------------------------------------------------------------------------

@dataclass
class ResearchDeps:
    """Dependencies injected into every tool call.

    Holds the browser automation agent and accumulated research state.
    """

    browser: BrowserAgent
    visited_urls: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    max_steps: int = 20
    step_count: int = 0


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are an expert web researcher. Your goal is to find accurate, up-to-date
information on the web by browsing pages, reading content, and following links.

Rules:
1. Start by navigating to a search engine (Google, DuckDuckGo, Bing) or a
   relevant known URL.
2. Use the browser tools to observe pages, click links, scroll, and fill forms.
3. After each observation, the page context is shown to you. Use it to decide
   the next action.
4. Extract key facts and add them to your findings.
5. Track every URL you visit as a source.
6. If you don't find the answer after several attempts, state that clearly.
7. When you have enough information, call `finish_research` with your report.
8. Do NOT hallucinate. Only report facts you have seen on the web.

Available browser tools:
- navigate(url): Go to a URL and observe the page.
- search(query): Search the web for a query string.
- click(action_id): Click an interactive element by its action ID.
- type_text(action_id, text): Type text into an input field.
- scroll(direction): Scroll the page (down, up, bottom, top).
- go_back(): Go back to the previous page.
- observe(): Re-observe the current page without navigating.
- add_finding(fact): Record a fact you discovered.
- finish_research(...): Submit your final report and end the task.

Action IDs look like:
  click_E1      — click element E1
  type_E3       — type into element E3
  scroll_down   — scroll down the page
  nav_back      — go back
  navigate      — go to a URL
"""


# ---------------------------------------------------------------------------
# Agent definition
# ---------------------------------------------------------------------------

agent = Agent(
    model="openai:gpt-4o",  # or "anthropic:claude-3-5-sonnet-latest", etc.
    system_prompt=SYSTEM_PROMPT,
    result_type=ResearchReport,
    deps_type=ResearchDeps,
)


# ---------------------------------------------------------------------------
# Browser tools
# ---------------------------------------------------------------------------

@agent.tool
async def navigate(ctx: RunContext[ResearchDeps], url: str) -> str:
    """Navigate to *url* and return the formatted page context."""
    ctx.deps.step_count += 1
    if ctx.deps.step_count > ctx.deps.max_steps:
        return "ERROR: Maximum step limit reached. Please finish_research now."

    try:
        page = ctx.deps.browser.observe(url, format="compact")
    except Exception as exc:
        return f"ERROR navigating to {url}: {exc}"

    ctx.deps.visited_urls.append(page["snapshot"]["url"])

    # Return formatted context + action space summary
    lines = [
        f"=== NAVIGATED TO {page['snapshot']['url']} ===",
        page["formatted"],
        "",
        f"Available actions: {len(page['action_space']['element_actions'])} element, "
        f"{len(page['action_space']['scroll_actions'])} scroll, "
        f"{len(page['action_space']['nav_actions'])} nav",
    ]
    return "\n".join(lines)


@agent.tool
async def search(ctx: RunContext[ResearchDeps], query: str) -> str:
    """Search the web for *query* and return the results page context."""
    # DuckDuckGo HTML version (no JS required)
    search_url = (
        "https://html.duckduckgo.com/html/?q=" + query.replace(" ", "+")
    )
    return await navigate(ctx, search_url)


@agent.tool
async def click(ctx: RunContext[ResearchDeps], action_id: str) -> str:
    """Click an element by its action ID and return the updated page context."""
    ctx.deps.step_count += 1
    if ctx.deps.step_count > ctx.deps.max_steps:
        return "ERROR: Maximum step limit reached. Please finish_research now."

    try:
        result = ctx.deps.browser.step(
            "",  # URL unchanged
            decision=action_id,
            format="compact",
        )
    except Exception as exc:
        return f"ERROR clicking {action_id}: {exc}"

    obs = result.get("observation", {})
    res = result.get("result", {})

    lines = [
        f"=== CLICKED {action_id} ===",
        f"Success: {res.get('success', False)}",
    ]
    if res.get("new_url"):
        lines.append(f"New URL: {res['new_url']}")
        ctx.deps.visited_urls.append(res["new_url"])
    if res.get("error"):
        lines.append(f"Error: {res['error']}")

    lines.extend(["", "=== UPDATED PAGE ===", obs.get("formatted", "")])
    return "\n".join(lines)


@agent.tool
async def type_text(
    ctx: RunContext[ResearchDeps], action_id: str, text: str
) -> str:
    """Type *text* into the input field identified by *action_id*."""
    ctx.deps.step_count += 1

    # Re-observe to get current action space so we can inject the text parameter
    try:
        page = ctx.deps.browser.observe("", format="json")
    except Exception:
        page = {"action_space": {}}

    # Find the action and inject text
    action: dict[str, Any] | None = None
    for a in (
        page.get("action_space", {}).get("element_actions", [])
        + page.get("action_space", {}).get("other_actions", [])
    ):
        if a.get("id") == action_id:
            action = a
            break

    if action is None:
        return f"ERROR: Action {action_id} not found. Try observing first."

    action.setdefault("parameters", {})
    action["parameters"]["text"] = text

    try:
        result = ctx.deps.browser.execute(action)
    except Exception as exc:
        return f"ERROR typing into {action_id}: {exc}"

    return (
        f"=== TYPED INTO {action_id} ===\n"
        f"Success: {result.get('success', False)}\n"
        f"Error: {result.get('error', '')}"
    )


@agent.tool
async def scroll(ctx: RunContext[ResearchDeps], direction: str) -> str:
    """Scroll the page: direction is 'down', 'up', 'bottom', or 'top'."""
    ctx.deps.step_count += 1

    action_id = "scroll_down"
    if direction == "up":
        action_id = "scroll_up"
    elif direction == "bottom":
        action_id = "scroll_bottom"
    elif direction == "top":
        action_id = "scroll_top"

    try:
        result = ctx.deps.browser.step("", decision=action_id, format="compact")
    except Exception as exc:
        return f"ERROR scrolling {direction}: {exc}"

    obs = result.get("observation", {})
    return (
        f"=== SCROLLED {direction} ===\n"
        f"Success: {result.get('result', {}).get('success', False)}\n\n"
        f"{obs.get('formatted', '')}"
    )


@agent.tool
async def go_back(ctx: RunContext[ResearchDeps]) -> str:
    """Go back to the previous page in browser history."""
    ctx.deps.step_count += 1
    try:
        result = ctx.deps.browser.step("", decision="nav_back", format="compact")
    except Exception as exc:
        return f"ERROR going back: {exc}"

    obs = result.get("observation", {})
    return f"=== WENT BACK ===\n{obs.get('formatted', '')}"


@agent.tool
async def observe(ctx: RunContext[ResearchDeps]) -> str:
    """Re-observe the current page without navigating."""
    ctx.deps.step_count += 1
    try:
        page = ctx.deps.browser.observe("", format="compact")
    except Exception as exc:
        return f"ERROR observing: {exc}"

    return (
        f"=== CURRENT PAGE ===\n"
        f"URL: {page['snapshot']['url']}\n\n"
        f"{page['formatted']}"
    )


@agent.tool
async def add_finding(ctx: RunContext[ResearchDeps], fact: str) -> str:
    """Record a factual finding discovered during research."""
    ctx.deps.findings.append(fact)
    return f"Recorded finding #{len(ctx.deps.findings)}: {fact}"


@agent.tool
async def finish_research(
    ctx: RunContext[ResearchDeps],
    answer: str,
    confidence: str,
) -> ResearchReport:
    """Finish research and return the final report.

    Call this when you have gathered enough information to answer the question.
    """
    # Deduplicate sources
    unique_sources = list(dict.fromkeys(ctx.deps.visited_urls))

    return ResearchReport(
        query=ctx.prompt,  # type: ignore[attr-defined]
        findings=ctx.deps.findings,
        sources=unique_sources,
        answer=answer,
        confidence=confidence,
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def run_research(query: str) -> ResearchReport:
    """Run the research agent on *query* and return the report."""
    browser = BrowserAgent(session_dir="/tmp/pydantic-ai-research")

    deps = ResearchDeps(
        browser=browser,
        max_steps=25,
    )

    try:
        result = await agent.run(query, deps=deps)
    finally:
        browser.stop()

    return result.data


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pydantic_ai_researcher.py '<research question>'")
        print("Example: python pydantic_ai_researcher.py 'Current NVIDIA stock price'")
        sys.exit(1)

    query = " ".join(sys.argv[1:])
    report = asyncio.run(run_research(query))

    print("\n" + "=" * 70)
    print("RESEARCH REPORT")
    print("=" * 70)
    print(f"Query:     {report.query}")
    print(f"Confidence: {report.confidence}")
    print(f"\nAnswer:\n{report.answer}")
    print(f"\nFindings ({len(report.findings)}):")
    for i, finding in enumerate(report.findings, 1):
        print(f"  {i}. {finding}")
    print(f"\nSources ({len(report.sources)}):")
    for url in report.sources:
        print(f"  - {url}")
