# Agentic Graph Scraping — Integration Summary

> Session: 2026-05-08  
> Branch: `feature/stealth_plus`  
> Commit: `b2f2cf9`

---

## Overview

Added a **ScrapeGraphAI-style directed-graph execution engine** as an independent side-arm to the existing stealth product. It lives in `brws/content/agentic/` and does **not** modify or override any code in the existing CDP-based agent (`brws/content/agent/`), browser engine, or stealth infrastructure.

The new package provides an LLM-centric scraping pipeline where workflows are composed as graphs of reusable nodes operating on a shared `State` dictionary.

---

## Files Added

| File | Lines | Purpose |
|---|---|---|
| `brws/content/agentic/doc.go` | ~120 | Package documentation, quick-start guide, architecture overview |
| `brws/content/agentic/engine.go` | ~220 | Core abstractions: `State`, `Node` interface, `BaseGraph` execution loop, boolean input-expression parser (`&`, `\|`, parentheses) |
| `brws/content/agentic/llm.go` | ~90 | `LLM` interface + `SemanticLLM` wrapper around existing `semantic.LLMClient`, token-limit registry |
| `brws/content/agentic/nodes_core.go` | ~280 | `FetchNode` (HTTP + local file ingestion), `ParseNode` (HTML→text conversion, token-aware chunking), HTML helpers |
| `brws/content/agentic/nodes_llm.go` | ~470 | `GenerateAnswerNode` (single-chunk direct extraction + multi-chunk parallel map-reduce), `ReasoningNode`, `MergeAnswersNode`, `SearchInternetNode` (DuckDuckGo search via LLM-generated queries) |
| `brws/content/agentic/nodes_control.go` | ~170 | `ConditionalNode` with Go-AST-based expression evaluator (`not`, `and`, `or`, `==`, `!=`) |
| `brws/content/agentic/graphs.go` | ~320 | `Pipeline` scaffolding, `SmartScraperGraph` (8 strategy variations), `SearchGraph`, `GraphIteratorNode` (semaphore-controlled parallel URL scraping) |
| `brws/content/agentic/agentic_test.go` | ~120 | Unit tests for expression parser, graph execution, conditional branching, text chunking |
| `examples/agentic_scraper.go` | ~80 | Standalone runnable example showing `SmartScraperGraph` and `SearchGraph` usage |

**Total:** ~1,870 lines of new Go code.

---

## Architecture

```
User Request (prompt + url)
         │
         ▼
┌─────────────────┐     ┌─────────────┐     ┌─────────────┐
│   Pipeline      │────▶│  BaseGraph  │────▶│    Node     │
│ (LLM + Config)  │     │  (Executor) │     │ (Pipeline)  │
└─────────────────┘     └─────────────┘     └─────────────┘
                                                     │
                              ┌──────────────────────┘
                              ▼
                        Shared State Map
                        {url, doc, parsed_doc, answer, ...}
```

### Three Core Abstractions

1. **Node** — processing unit  
   - Declares required state keys via boolean expressions: `"user_prompt & (parsed_doc \| doc)"`  
   - Reads inputs from `State`, performs work, writes outputs back to `State`

2. **BaseGraph** — execution engine  
   - While-loop driver that routes state from node to node  
   - Supports conditional branching (true/false edges)  
   - Returns per-node execution telemetry (timing, token counts)

3. **Pipeline** — scaffolding  
   - `SmartScraperGraph` and `SearchGraph` assemble concrete node/edge configurations  
   - Strategy pattern selects pipeline shape based on `html_mode`, `reasoning`, `reattempt` flags

---

## Key Capabilities

| Capability | Implementation |
|---|---|
| **Direct Extraction** | `GenerateAnswerNode` prompts LLM with content + question → structured JSON |
| **Map-Reduce** | Multi-chunk docs are processed in parallel (goroutines + semaphore), then merged via a synthesis LLM call |
| **Conditional Retry** | `ConditionalNode` evaluates expressions like `not answer or answer=="NA"` to branch to a regeneration node |
| **Autonomous Search** | `SearchInternetNode` generates a search query via LLM, scrapes DuckDuckGo HTML results, returns top-N URLs |
| **Parallel Multi-URL** | `GraphIteratorNode` runs `SmartScraperGraph` per URL with configurable concurrency (`BatchSize`) |
| **Reasoning Pre-process** | `ReasoningNode` analyzes user prompt against a JSON schema to produce an extraction strategy before execution |

---

## LLM Integration

The package defines a minimal provider-agnostic interface:

```go
type LLM interface {
    Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error)
    CompleteJSON(ctx context.Context, systemPrompt, userPrompt string, v interface{}) error
}
```

A wrapper around the existing `semantic.LLMClient` (OpenRouter) is provided:

```go
llm := agentic.NewSemanticLLM(semantic.NewLLMClient(os.Getenv("OPENROUTER_API_KEY")))
// or
llm, err := agentic.NewLLMFromEnv()
```

Custom providers can be plugged in by implementing the two-method interface.

---

## Independence Guarantee

- **Zero imports** into `brws/content/agent/` (existing CDP-based browser agent)
- **Zero imports** into `brws/browser/engine/chromium` (browser engine)
- **Zero imports** into `brws/stealth/` (evasion/detection infrastructure)
- Relies only on `brws/content/semantic` for the default LLM client and standard library packages for HTTP/HTML parsing

This ensures the existing agentic stack remains fully functional and untouched.

---

## Usage Example

```go
graph, err := agentic.NewSmartScraperGraph(
    "Extract all product names and prices",
    "https://example.com/products",
    map[string]interface{}{
        "reasoning": true,
        "reattempt": true,
    },
    nil, // optional schema
    llm,
)
if err != nil { log.Fatal(err) }

state, info, err := graph.Run(context.Background())
// state["answer"] holds the extracted JSON
// info holds per-node execution telemetry
```

See `examples/agentic_scraper.go` for a complete runnable example.

---

## Quality Gates

| Gate | Result |
|---|---|
| `go build ./brws/content/agentic/...` | ✅ Pass |
| `go vet ./brws/content/agentic/...` | ✅ Pass |
| `go test ./brws/content/agentic/...` | ✅ 4/4 tests pass |
| Pushed to remote | ✅ `feature/stealth_plus` up to date with origin |

---

## Notable Absences (Future Work)

The following ScrapeGraphAI features were **not** implemented in this MVP and can be added incrementally without breaking existing code:

| Feature | Status |
|---|---|
| `GenerateCodeNode` (self-correcting Python code generation loop) | ❌ Not implemented |
| `ImageToTextNode` / vision-based extraction | ❌ Not implemented |
| `RAGNode` (vector DB retrieval) | ❌ Not implemented |
| Pydantic v2 schema enforcement via native structured output | ❌ Not implemented (prompt-based JSON only) |
| `RobotsNode` (LLM-powered robots.txt compliance check) | ❌ Not implemented |
| Provider-specific native JSON modes (OpenAI `with_structured_output`) | ❌ Not implemented |

---

*Document generated from source code analysis and integration session.*
