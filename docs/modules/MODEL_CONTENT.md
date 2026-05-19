# Model: Content Extraction Module

> **Purpose:** Multi-modal content extraction, semantic analysis, browser agent automation, and LLM-centric scraping pipelines.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                   Content Extraction Layer                   │
├─────────────┬─────────────┬─────────────┬───────────────────┤
│   Interact  │  Understand │  Pipeline   │     Crawl         │
│  (Browser)  │  (Semantic) │  (Graph)    │  (Spider)         │
└──────┬──────┴──────┬──────┴──────┬──────┴────────┬──────────┘
       │             │             │               │
       ▼             ▼             ▼               ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│ CDP-based   │ │ DOM chunker │ │ FetchNode   │ │ Scheduler   │
│ observe→    │ │ LLM summary │ │ ParseNode   │ │ Middleware  │
│ decide→     │ │ Vision      │ │ Generate    │ │ Pipeline    │
│ execute     │ │ grounding   │ │ AnswerNode  │ │ Orchestrator│
└─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘
```

---

## Agent (`content/agent/`)

CDP-based browser agent implementing the classic **observe → decide → execute** loop.

### Components

| Component | File | Purpose |
|---|---|---|
| **Agent** | `agent.go` | Top-level orchestrator; ties Observer, Formatter, Executor |
| **Observer** | `observer.go` | Captures `PageSnapshot` from live browser tab via CDP |
| **Formatter** | `formatter.go` | Formats page context for LLM consumption |
| **Executor** | `executor.go` | Executes agent-chosen actions on browser |
| **ActionSpace** | `actionspace.go` | Enumerates possible actions from page state |
| **SemanticEnhancer** | `semantic_enhancer.go` | LLM-based semantic enrichment |

### PageSnapshot

Captures everything observable:
- URL, title, viewport, scroll position
- Visible elements (ID, selector, tag, text, bounds, interactivity)
- Forms, links, tabs
- Semantic enrichment: meta, images, social links, colors, fonts, semantic tree

### Actions

| Action | Description |
|---|---|
| `click` | Click element |
| `type` | Type text into input |
| `select` | Select dropdown option |
| `toggle` | Toggle checkbox/radio |
| `scroll_down/up/bottom/top/to` | Scroll actions |
| `navigate` | Navigate to URL |
| `back/forward/reload` | Browser navigation |
| `wait` | Wait for duration |
| `screenshot` | Capture screenshot |
| `new_tab/switch_tab/close_tab` | Tab management |

### Agent Loop

```go
for {
    ctx, actions, formatted, _ := agent.Observe(context)
    action := decideFn(ctx, actions, formatted, history)
    result, _ := agent.Execute(context, action)
    // record step
}
```

### Decision Helpers

Built-in decision functions for common cases:
- `ClickFirstLink`
- `ScrollThenClick`
- `ScrollToBottom`
- `SubmitFirstForm`

---

## Semantic Pipeline (`content/understand/`)

LLM-powered semantic analysis of web pages.

### Components

| Component | Purpose |
|---|---|
| **DOM Chunker** | Splits DOM into hierarchical chunks |
| **Semantic Tree** | Builds hierarchical summary tree of page structure |
| **LLM Client** | OpenRouter API client with compression and vision models |
| **Vision Grounding** | Maps natural language to DOM elements |
| **Extractor** | Extracts structured data from semantic tree |
| **Forms** | Form schema extraction and analysis |
| **Images** | Image metadata and description |

### Semantic Tree

```go
type SemanticNode struct {
    ID                string
    Summary           string
    StructuralHash    string
    IsDynamic         bool
    DOMSelector       string
    TokenCount        uint32
    SubtreeTokenCount uint32
    Actions           []Action
    Children          []SemanticNode
}
```

### Pipeline Flow

1. **Chunk** DOM into hierarchical chunks
2. **Summarize** each chunk (no-LLM heuristic or LLM-based)
3. **Build tree** from chunk hierarchy
4. **Extract** structured data or action space from tree
5. **Export** to JSON or feed into agent

### LLM Client (`llm.go`)

```go
type LLMClient struct {
    client        *http.Client
    apiKey        string
    compressModel string    // default: openai/gpt-oss-120b
    visionModel   string    // default: google/gemini-2.5-flash
}

func (c *LLMClient) Complete(ctx, systemPrompt, userPrompt string) (string, error)
func (c *LLMClient) CompleteJSON(ctx, systemPrompt, userPrompt string, v interface{}) error
```

---

## Graph Pipeline (`content/scrapegraph/`)

**New side-arm** — ScrapeGraphAI-style directed-graph execution engine.

### Core Abstractions

| Abstraction | Purpose |
|---|---|
| `State` | Shared mutable map flowing through graph |
| `Node` | Processing unit with input expression and outputs |
| `BaseGraph` | While-loop execution engine with conditional branching |
| `Pipeline` | Scaffolding for concrete scrapers |

### Nodes

| Node | Purpose |
|---|---|
| **FetchNode** | Ingest URLs (HTTP) or local files |
| **ParseNode** | HTML→text, token-aware chunking |
| **GenerateAnswerNode** | LLM extraction (single + map-reduce) |
| **ExtractorNode** | Replaces Parse + GenerateAnswer with a single `content/extract` call; provides chunking, schema validation, and multi-provider extraction without a separate LLM dependency |
| **ReasoningNode** | Pre-process prompt against schema |
| **MergeAnswersNode** | Synthesize multiple partial answers |
| **SearchInternetNode** | LLM-generated queries + DuckDuckGo scrape |
| **ConditionalNode** | Runtime branching with expression evaluator |
| **GraphIteratorNode** | Parallel multi-URL scraping |

### Graphs

| Graph | Pipeline | Config Flags |
|---|---|---|
| **SmartScraperGraph** | Fetch → Parse → (Reasoning) → GenerateAnswer → (Conditional → Regen) | `html_mode`, `reasoning`, `reattempt` |
| **SmartScraperGraph** (extractor path) | Fetch → ExtractorNode | pass `extract.Option` values to `NewSmartScraperGraphWithExtractor`; no LLM param required |
| **SearchGraph** | SearchInternet → GraphIterator → MergeAnswers | `max_results` |

### Map-Reduce

Multi-chunk documents processed in parallel (goroutines + semaphore), then merged via synthesis LLM call.

---

## Crawl (`crawl/`)

Spider and pipeline infrastructure for large-scale crawling.

### Spider (`crawl/spider/`)

| Component | Purpose |
|---|---|
| **Spider** | Core crawler with configurable concurrency |
| **Scheduler** | URL frontier management |
| **Middleware** | Request/response processing pipeline |
| **Settings** | Crawler configuration |
| **Semantic Spider** | LLM-guided crawling via semantic tree |

### Integration (`crawl/integration/`)

| Component | Purpose |
|---|---|
| **Orchestrator** | Coordinates spider + stealth + extraction |
| **Smart Navigator** | Intelligent link selection |
| **Form Filler** | Automatic form completion |
| **Data Extractor** | Structured data extraction |
| **Change Detector** | Detects page changes over time |
| **Session Manager** | Persistent crawling sessions |

---

## Key Files

| File | Description |
|---|---|
| `content/agent/agent.go` | Agent orchestrator |
| `content/agent/observer.go` | CDP page observation |
| `content/agent/executor.go` | Action execution on browser |
| `content/agent/types.go` | Agent types (PageSnapshot, Action, Context) |
| `content/understand/pipeline.go` | Semantic analysis pipeline |
| `content/understand/tree.go` | Semantic tree builder |
| `content/understand/llm.go` | LLM client for semantic pipeline |
| `content/understand/vision_grounding.go` | Vision-based element grounding |
| `content/scrapegraph/engine.go` | Graph execution engine |
| `content/scrapegraph/nodes_core.go` | FetchNode, ParseNode |
| `content/scrapegraph/nodes_llm.go` | LLM-driven nodes |
| `content/scrapegraph/nodes_control.go` | ConditionalNode |
| `content/scrapegraph/graphs.go` | SmartScraperGraph, SearchGraph |
| `crawl/spider/spider.go` | Core spider |
| `crawl/spider/scheduler.go` | URL frontier |
| `crawl/integration/orchestrator.go` | Crawl orchestrator |
