"""Python wrapper for the ``semantic`` CLI — semantic web extraction."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from ._base import CLIWrapper


@dataclass
class CompressionStats:
    """Semantic compression statistics."""

    raw_html_bytes: int
    clean_html_bytes: int
    total_chunks: int
    chunks_cached: int
    chunks_llm_compressed: int
    compressed_tokens: int
    full_tree_tokens: int
    compression_ratio: float
    tokens_saved: int
    duration_ms: int


@dataclass
class SemanticNode:
    """A node in the semantic tree."""

    id: str
    summary: str
    tag: str
    token_count: int
    is_dynamic: bool
    children: list[SemanticNode]
    actions: list[dict[str, Any]]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SemanticNode:
        return cls(
            id=data.get("ID", ""),
            summary=data.get("Summary", ""),
            tag=data.get("Tag", ""),
            token_count=data.get("TokenCount", 0),
            is_dynamic=data.get("IsDynamic", False),
            children=[SemanticNode.from_dict(c) for c in data.get("Children", [])],
            actions=data.get("Actions", []),
        )


@dataclass
class SemanticTree:
    """Extracted semantic tree."""

    url: str
    title: str
    domain: str
    compressed_token_count: int
    full_token_count: int
    root_nodes: list[SemanticNode]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SemanticTree:
        return cls(
            url=data.get("URL", ""),
            title=data.get("Title", ""),
            domain=data.get("Domain", ""),
            compressed_token_count=data.get("CompressedTokenCount", 0),
            full_token_count=data.get("FullTokenCount", 0),
            root_nodes=[SemanticNode.from_dict(n) for n in data.get("RootNodes", [])],
        )


class Semantic(CLIWrapper):
    """Wrapper for the ``semantic`` binary.

    Usage::

        from pybrwslab import Semantic
        sem = Semantic()
        tree = sem.extract("https://example.com")
        print(tree.title)
    """

    def __init__(self, binary_path: str | None = None) -> None:
        super().__init__("semantic", binary_path)

    def extract(
        self,
        url: str,
        *,
        format: str = "json",
        engine: str = "native",
        stealth: bool = True,
        cache: str = "",
        no_cache: bool = False,
        api_key: str = "",
        compress_model: str = "openai/gpt-oss-120b",
        embed_model: str = "qwen/qwen3-embedding-8b",
        vision_model: str = "google/gemini-2.5-flash",
        timeout: str = "5m",
        initial_budget: int = 5000,
        max_budget: int = 128000,
        pretty: bool = True,
    ) -> SemanticTree | CompressionStats | str | dict[str, Any]:
        """Extract a semantic tree from a URL.

        Args:
            url: Target URL.
            format: ``tree`` | ``json`` | ``serialized`` | ``stats``.
            engine: Fetch engine.
            stealth: Enable stealth mode for fetching.
            cache: Cache database path.
            no_cache: Disable caching.
            api_key: OpenRouter API key (or set ``OPENROUTER_API_KEY``).
            compress_model: LLM model for compression.
            embed_model: Embedding model.
            vision_model: Vision model.
            timeout: Request timeout.
            initial_budget: Initial token budget per page.
            max_budget: Maximum token budget.
            pretty: Pretty-print JSON output.
        """
        args = [
            "--url", url,
            "--format", format,
            "--engine", engine,
            "--timeout", timeout,
            "--initial-budget", str(initial_budget),
            "--max-budget", str(max_budget),
            "--model", compress_model,
            "--embed-model", embed_model,
            "--vision-model", vision_model,
        ]
        if not stealth:
            args.append("--stealth=false")
        if cache:
            args += ["--cache", cache]
        if no_cache:
            args.append("--no-cache")
        if api_key:
            args += ["--api-key", api_key]
        if pretty:
            args.append("--pretty")
        else:
            args.append("--pretty=false")

        result = self._run(*args)
        stdout = result.stdout.strip()

        if format == "stats":
            data = json.loads(stdout)
            return CompressionStats(
                raw_html_bytes=data.get("raw_html_bytes", 0),
                clean_html_bytes=data.get("clean_html_bytes", 0),
                total_chunks=data.get("total_chunks", 0),
                chunks_cached=data.get("chunks_cached", 0),
                chunks_llm_compressed=data.get("chunks_llm_compressed", 0),
                compressed_tokens=data.get("compressed_tokens", 0),
                full_tree_tokens=data.get("full_tree_tokens", 0),
                compression_ratio=data.get("compression_ratio", 0.0),
                tokens_saved=data.get("tokens_saved", 0),
                duration_ms=data.get("duration_ms", 0),
            )

        if format == "json":
            data = json.loads(stdout)
            return SemanticTree.from_dict(data)

        # tree or serialized: return raw text
        return stdout

    def extract_text(
        self,
        url: str,
        *,
        engine: str = "native",
        stealth: bool = True,
    ) -> str:
        """Convenience method: extract serialized text suitable for LLM context."""
        return str(self.extract(url, format="serialized", engine=engine, stealth=stealth))

    def extract_stats(
        self,
        url: str,
        *,
        engine: str = "native",
        stealth: bool = True,
    ) -> CompressionStats:
        """Convenience method: extract compression statistics only."""
        result = self.extract(url, format="stats", engine=engine, stealth=stealth)
        assert isinstance(result, CompressionStats)
        return result
