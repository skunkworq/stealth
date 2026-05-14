# brws — Browser Automation Stack

`brws` is a layered Go library for stealth browser automation, AI-driven web agents, and large-scale crawling. Packages are organized into four dependency layers; nothing in a lower layer imports from a higher one.

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 4 — Scale          crawl/   ml/   fingerprint/       │
├─────────────────────────────────────────────────────────────┤
│  Layer 3 — Content        content/agent   content/scrapegraph          │
│                           content/understand   content/extract          │
├─────────────────────────────────────────────────────────────┤
│  Layer 2 — Stealth        stealth/                          │
├─────────────────────────────────────────────────────────────┤
│  Layer 1 — Engine         browser/   network/               │
├─────────────────────────────────────────────────────────────┤
│  Cross-cutting            core/                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Layer 1 — Engine

Raw browser and network primitives. No stealth logic lives here.

### `browser/engine`

Defines the `Engine` interface and optional capability interfaces implemented by every backend:

```go
type Engine interface {
    Name() string
    Capabilities() Capabilities
    Do(ctx context.Context, req *Request) (*Response, error)
    Close() error
}
```

Optional interfaces engines may implement:

| Interface | Method(s) | Purpose |
|---|---|---|
| `InteractiveEngine` | `Mouse`, `Click`, `Type`, `Scroll`, `ScrollTo` | Human-like interaction |
| `TabEngine` | `DoOnTab(ctx, tabCtx, req)` | Execute on an existing tab |
| `AllocatorEngine` | `Allocator()` | Expose browser allocator context |
| `TabCreator` | `NewTab()` | Create new persistent tabs |
| `ProfileNavigator` | `NavigateWithReferrer(ctx, url, referrer)` | Referrer-profile navigation |

Engines are registered by name and constructed via `engine.New(name, opts)`:

```go
eng, _ := engine.New("chromium-stealth", engine.Options{Headless: true})
resp, _ := eng.Do(ctx, &engine.Request{URL: "https://example.com"})
```

#### Browser engines (`browser/engine/browser/`)

| Package | Backend | When to use |
|---|---|---|
| `browser/chromium` | Chromedp / Chrome CDP | Base Chromium engine; authentic TLS/HTTP2/HTTP3; supports TabEngine, InteractiveEngine |
| `stealth/chromium` | Chromedp + anti-detection | **Default**; script injection, behavioral simulation (Bézier mouse, keystroke timing) |
| `browser/chromium/cdp` | CDP actions | UA override, timezone, locale via CDP protocol |
| `browser/firefox` | Playwright/Firefox | Firefox TLS fingerprint, alternate UA pool |
| `browser/webkit` | WebKit | Safari-profile pages |

#### HTTP engines (`browser/engine/http/`)

| Package | Backend | When to use |
|---|---|---|
| `http/native` | `net/http` + uTLS | Fast, lightweight; no JS, TLS fingerprint spoofing. Registered as `"native"` engine. |
| `http/http3` | `quic-go` | **Stub** — HTTP/3 client utilities. Does not implement `engine.Engine`; use a browser engine for HTTP/3. |

#### Meta engines (`browser/engine/meta/`)

| Package | Purpose |
|---|---|
| `meta/waterfall` | Races multiple engines with timeout-based tier promotion. Starts the fastest engine, launches progressively heavier engines after configurable delays, cancels all losers when a winner responds. Used by `stealth.Adaptive` to balance speed against detection resistance. |

#### Test utilities (`browser/engine/testutil/`)

| Package | Purpose |
|---|---|
| `testutil/testserver` | Stub HTTP server for engine tests |

### `browser/instancepool`

A concurrency-safe pool of `browser/engine` instances. Callers acquire an engine, use it, then release it back. Prevents browser process churn under concurrent load.

### `network/client`

Stealth-grade HTTP client: correct header order, realistic Accept/Accept-Language values, optional proxy routing.

### `network/proxy/connpool`

Per-domain tiered proxy pool. Records errors per domain and promotes to the next proxy tier (residential → datacenter → raw) on repeated failures. Used by `stealth.Adaptive.escalate()`.

### `network/sniff`

Packet-level traffic capture and analysis (Rust FFI). Used by `fingerprint/` tools to collect real browser traffic for training data.

---

## Layer 2 — Stealth

`stealth.Adaptive` is the main entry point for the library. It wraps a `browser/engine` (or waterfall) and adds all anti-bot layers. **It is engine-agnostic** — it works with any `engine.Engine` implementation via optional interface checks.

Most callers only import this package.

```go
client, _ := stealth.NewAdaptive(
    stealth.WithHeadless(false),
    stealth.WithProxy("http://proxy:8080"),
    stealth.WithChallengeSolver("capsolver", "KEY"),
    stealth.WithEscalation(stealth.DefaultEscalationConfig()),
    stealth.WithWaterfall(wf),
)
resp, _ := client.Navigate(ctx, "https://example.com")
```

### `stealth/` (root)

- **`client.go`** — `Client`: navigate with auto-challenge detection, escalation, session tracking. Uses `engine.Do()` for generic navigation and optional interfaces (`ProfileNavigator`, `AllocatorEngine`, `TabCreator`, `InteractiveEngine`) for engine-specific features.
- **`escalation.go`** — `escalate()`: on a ban signal (401/403/429), records the ban, promotes the proxy tier, and promotes the waterfall tier. Configurable via `WithEscalation`.
- **`policy.go`** — RL-driven stealth adaptation. `ApplyAction` mutates an `engine.StealthConfig` interface (actions toggle features like CanvasNoise, WebGLSpoof, etc.).
- **`response_types.go`** / **`response_extract.go`** — typed `Response` and helpers to pull cookies, headers, and body.
- **`semantic_integration.go`** — bridges `stealth.Adaptive` to `content/semantic` for snapshot extraction directly from a live tab.

### `stealth/challenge`

Detects and defeats anti-bot challenges. A single flat package (40+ files) because all challenge types share internal state and orchestration types.

- Cloudflare (JS challenge, Turnstile, 5s interstitial)
- DataDome
- reCAPTCHA v2/v3
- Generic iframe/overlay detection

#### `stealth/challenge/fsm`

Finite state machine governing escalation between evasion strategies (passive → active → solve → escalate). `stealth.Adaptive` drives it via `evasionFSM.RecordBanSignal()`.

### `stealth/captcha`

CAPTCHA detection logic and integration with external solver services.

#### `stealth/captcha/solver`

Solver backends (CapSolver API, etc.). Called by the challenge orchestrator when a CAPTCHA is detected and cannot be bypassed passively.

### `stealth/behavior`

Human behavior simulation: randomized mouse movement curves, keystroke timing, scroll jitter, click dwell time. Injected into engine interactions via the `InteractiveEngine` optional interface to defeat behavioral analytics. The `SimulateBehavior` flag on `agent.Config` wires these simulators directly into the agent executor — click, type, and scroll all get human-like timing when enabled.

- **`evasion_strategy.go`** — picks a strategy profile (desktop, mobile, careful).
- **`simulator.go`** — executes mouse/scroll/timing sequences.
- **`adaptive_generator.go`** — adapts behavior profiles based on observed bot-signal feedback.

### `stealth/profile`

Browser profile management: UA strings, viewport sizes, locale, timezone, WebGL/Canvas fingerprint seed.

#### `stealth/profile/session`

Session health tracking. Records ban signals, computes a health score, and marks a session as blocked when the score crosses a threshold. `stealth.Adaptive.escalate()` checks `sess.IsBlocked()` before retrying.

### `stealth/script/spoof`

Browser-agnostic TLS/HTTP fingerprint spoofing using uTLS. Supports Chrome, Firefox, Safari, Edge signatures. Used by fingerprint benchmark/lab tools — **not** a runtime stealth script; it has no CDP or browser dependency.

---

## Layer 3 — Content

Content packages turn a raw HTML response or live browser tab into structured data or AI-driven actions. They depend on `stealth/` for tab management but are otherwise independent of each other.

### `content/agent`

Goal-directed browser agent. Implements an observe→decide→execute loop over a live browser tab.

**Core flow:**

```
NewAgent → NewStealthTab → Step(decideFn) × N → History()
```

Each `Step`:
1. **Observe** — snapshots the DOM into an `agent.Context` (URL, title, elements, links, forms).
2. **Build action space** — `BuildActionSpace` (DOM) or `BuildSemanticActionSpace` (semantic tree); returns a `[]Action` the LLM can choose from.
3. **Decide** — caller-supplied `decideFn(ctx, actions, formatted, history) (Action, error)`.
4. **Execute** — dispatches the chosen action (click, type, navigate, scroll, wait, solve-challenge).

**Two page representations** available to `decideFn`:

| Representation | Source | Token cost | Use when |
|---|---|---|---|
| DOM (`RepresentationDOM`) | Raw element list | Higher | Need exact selectors, form structure |
| Semantic (`RepresentationSemantic`) | Compressed tree | Lower (~40%) | LLM navigation, Q&A, search |

See `content/agent/README.md` for the full API reference.

### `content/scrapegraph`

LLM graph execution engine. Composes higher-level tasks from typed nodes connected into a DAG.

**Node types:**

| Node | Purpose |
|---|---|
| `SearchGraph` | Navigates to a domain, submits a search, returns results |
| `GenerateAnswerNode` | Reads page content (with map-reduce for long pages) and generates an answer |
| `SemanticNode` | Runs a `content/semantic` pipeline on a URL and returns the semantic tree |

**LLM interface:**

```go
type LLM interface {
    Complete(ctx, system, user string) (string, error)
    CompleteJSON(ctx, system, user string, out any) error
}
```

`NewLLMFromEnv()` builds an OpenRouter client from `OPENROUTER_API_KEY`.

**`SearchCoordinator`** (in `search.go`) is the bridge between `content/scrapegraph` and `content/agent`: it wires an `agent.Agent` step-loop to an LLM `decideFn`, handles search system prompts, and extracts structured `[]ResultItem` from the final page.

### `content/understand`

Converts raw HTML into a compressed semantic tree suitable for LLM consumption and vector search.

**Pipeline:** `Parse → Clean → Compress → Annotate → Index`

Key outputs:

- `SemanticTree` — hierarchical representation of page content (headings, paragraphs, lists, tables, forms, images with alt text).
- Compression: removes boilerplate, deduplicates repeated blocks. Typically 30–60% smaller than the raw DOM representation.
- Form extraction: detects forms and returns typed `FormField` slices.
- Visual grounding: maps semantic nodes back to DOM coordinates (for click targets).
- Vector index (`content/semantic/index`): embeds semantic nodes for similarity search across crawled pages.
- Serialization: JSON and binary (protobuf) formats for caching.

### `content/extract`

Lowest-level text extraction. Strips all HTML tags and returns clean plain text via `htmlToText()`. No structure, no compression — used when the LLM only needs the raw words.

---

## Layer 4 — Scale

Packages for running `brws` at crawl scale: scheduling, instrumentation, ML-driven adaptation, and fingerprint tooling.

### `crawl/spider`

Scrapy-inspired high-throughput crawler.

**Architecture:**

```
Scheduler → Downloader → Spider → ItemPipeline
                ↑              ↓
           Middleware       ItemMiddleware
```

- **Scheduler**: priority queue + deduplication filter.
- **Downloader middlewares**: proxy rotation, retry, rate limiting, cookie jar.
- **Spider**: user-defined `Parse(response) (items, requests)`.
- **Item pipelines**: validation, deduplication, persistence.

See `crawl/spider/doc.go` for the full API.

### `crawl/integration`

Bridges `stealth.Adaptive` with `content/semantic` at crawl scale. Provides components that operate on the semantic tree rather than raw HTML, enabling intent-driven crawling.

**Components:**

| Type | Role |
|---|---|
| `Navigator` | Navigates with semantic intent ("find login form"); uses `content/semantic` to locate the target |
| `SmartNavigator` | Multi-step navigation with backtracking via semantic tree diff |
| `FormFiller` | Detects and fills forms using semantic field matching |
| `ChangeDetector` | Compares semantic trees across visits to detect meaningful content changes |
| `DataExtractor` | Pulls structured data from semantic trees using schema templates |
| `AdaptiveCrawler` | Steers crawl frontier using semantic signals (page quality, freshness) |
| `SessionManager` | Manages stealth sessions across adaptive crawl workers |
| `Orchestrator` | Coordinates the above components for a full crawl run |
| `Monitoring` | Emits crawl-specific metrics (pages/s, extraction quality, challenge rate) |

Distinct from `crawl/spider`: spider operates on raw responses; `integration` operates on the semantic tree and requires a live stealth browser.

### `crawl/pipeline`

OpenTelemetry and Prometheus instrumentation for crawl pipelines. Provides trace spans, metrics server, and Prometheus exporter — decoupled from any particular crawler so it can wrap either `spider` or `integration` crawls.

### `ml/adaptive`

ML-backed adaptive crawl strategy. Currently provides:

- **`storage.go`** — persists crawl observations (page type, extraction quality, challenge frequency) per domain.
- **`tracker.go`** — tracks per-domain performance and suggests strategy adjustments (engine tier, request rate, proxy tier) to `crawl/integration`.

### `fingerprint/`

Tools for collecting, analyzing, and training on browser fingerprints. Not used in production crawl paths — these are data-collection and model-training utilities.

| Package | Purpose |
|---|---|
| `fingerprint/tls` | Parse TLS ClientHello; compute JA3/JA4 hashes |
| `fingerprint/tls/parser` | Low-level TLS record parser |
| `fingerprint/tls/rust` | Rust FFI for high-throughput TLS capture |
| `fingerprint/http` | HTTP header fingerprint comparison (`fingerprint/http/diff`) and browser profile matching (`fingerprint/http/browser`) |
| `fingerprint/lab` | Interactive fingerprint lab; `lab/export` for structured output, `lab/static` for baseline profiles |
| `fingerprint/train` | Training data generation (`train/datagen`) for fingerprint classifiers |
| `fingerprint/bench` | Benchmarks comparing engine fingerprints against real browser baselines |

---

## Cross-cutting — `core/`

Shared primitives imported by all layers. Nothing in `core/` imports from `browser/`, `stealth/`, `content/`, or `crawl/`.

| Package | Contents |
|---|---|
| `core/config` | Config file loading, environment variable binding |
| `core/constants` | Package-wide constants (timeouts, limits, version strings) |
| `core/instrumentation` | **Active logging layer**: structured logger, distributed tracer, hook registry. All 10 packages that log or trace import this. |
| `core/observability` | Metrics collection interface and adapters |
| `core/resilience` | Retry with exponential backoff, circuit breaker |
| `core/signals` | Shared signal types (ban signals, challenge signals) flowing between layers |
| `core/telemetry` | Telemetry aggregation and export |
| `core/types` | Shared type definitions used across multiple packages |

---

## Dependency graph (condensed)

```
core/
  └─ imported by everything

browser/engine/*  ←  network/client
                  ←  network/proxy/connpool
browser/engine/meta/waterfall  ←  browser/engine/*
browser/instancepool           ←  browser/engine/*

stealth/
  ←  browser/engine            (Engine interface + optional interfaces)
  ←  browser/engine/meta/waterfall
  ←  browser/instancepool
  ←  network/proxy/connpool
  ←  stealth/challenge
  ←  stealth/behavior
  ←  stealth/captcha
  ←  stealth/profile/session
  ←  stealth/script/spoof      (fingerprint benchmarks only)

content/agent  ←  stealth/
content/understand ←  stealth/  (optional; for live-tab snapshots)
content/scrapegraph  ←  content/agent
                  ←  content/understand
content/extract   ←  (stdlib only)

crawl/spider      ←  stealth/
crawl/integration ←  stealth/
                  ←  content/semantic
crawl/pipeline    ←  (observability only; no browser dep)
ml/adaptive       ←  (stdlib only; read by crawl/integration)
fingerprint/*     ←  network/sniff  (for data collection)
```

---

## Quick-start examples

### Navigate with stealth

```go
client, _ := stealth.NewAdaptive(stealth.WithChallengeSolver("capsolver", key))
defer client.Close()

resp, _ := client.Navigate(ctx, "https://target.com")
fmt.Println(string(resp.Body))
```

### AI search agent

```go
coord, _ := pipeline.NewSearchCoordinator(pipeline.SearchConfig{
    Domain:        "amazon.com",
    Query:         "laptop under $500",
    StealthClient: client,
})
result, _ := coord.Run(ctx)
for _, item := range result.Items {
    fmt.Println(item.Title, item.Price)
}
```

### Goal-directed agent with custom decideFn

```go
ag := agent.NewAgent(agent.DefaultConfig(), nil, nil, nil)
tabCtx, cancel, _ := ag.NewStealthTab(ctx, "https://example.com")
defer cancel()

for i := 0; i < 20; i++ {
    step, _ := ag.Step(tabCtx, func(pageCtx *agent.Context, actions []agent.Action, formatted string, history []agent.Step) (agent.Action, error) {
        // call your LLM here
        return chosenAction, nil
    })
    if step.Decision.Type == agent.ActionNone {
        break
    }
}
```

### Semantic extraction

```go
pipe := semantic.NewPipeline(semantic.DefaultConfig())
tree, _ := pipe.Process(ctx, rawHTML, pageURL)
fmt.Println(tree.Compress().String())
```

### Adaptive crawl

```go
crawler := integration.NewAdaptiveCrawler(client, pipe)
crawler.Crawl(ctx, []string{"https://shop.com"}, "find product listings")
```
