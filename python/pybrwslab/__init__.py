"""
pybrwslab — Python wrapper for the brwslab browser automation toolkit.

This package wraps the Go CLI binaries (``brwslab``, ``stealth``,
``semantic``, ``labd``) so you can use them from Python without
writing Go code.

Quick start::

    from pybrwslab import Brwslab, Stealth, Semantic

    # Fetch with stealth
    br = Brwslab()
    result = br.fetch("https://example.com", engine="chromium")
    print(result.status, result.body[:200])

    # Semantic extraction
    sem = Semantic()
    tree = sem.extract("https://example.com", format="json")
    print(tree.title)

    # Start fingerprint lab
    from pybrwslab import Labd
    lab = Labd()
    proc = lab.start(http_port=8080)
    # ... capture fingerprints ...
    lab.stop(proc)

Before using, build the Go binaries::

    make build
    # or individually:
    go build -o build/brwslab ./cmd/brwslab
    go build -o build/stealth  ./cmd/stealth
    go build -o build/semantic ./cmd/semantic
    go build -o build/labd     ./cmd/labd

Then either install the wrappers into the same directory or add
``build/`` to your ``PATH``.
"""

from __future__ import annotations

from ._base import BrwslabError, FetchResult
from .brwslab import Brwslab
from .labd import Labd
from .semantic import Semantic, SemanticTree, SemanticNode, CompressionStats
from .stealth import Stealth

__all__ = [
    "Brwslab",
    "BrwslabError",
    "CompressionStats",
    "FetchResult",
    "Labd",
    "Semantic",
    "SemanticNode",
    "SemanticTree",
    "Stealth",
]

__version__ = "0.1.0"
