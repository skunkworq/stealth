# Implementation Summary

> **Module:** `github.com/skunkworq/stealth`  
> **Go Version:** 1.26+  
> **Total Go Lines:** ~170,000 (library + commands)  
> **Packages:** 80+  

This document provides a high-level overview of the `stealth` implementation. For deeper dives into individual modules, see the [`MODEL_*.md`](../modules/MODELS_INDEX.md) documentation suite.

---

## Project Structure

```
stealth/
├── brws/                        # Library packages (~160K lines)
│   ├── browser/                 # Browser automation engines
│   │   ├── engine/              # Engine interface + 4 implementations
│   │   │   ├── native/          # Go net/http + uTLS TLS spoofing
│   │   │   ├── chromium/        # Chrome CDP (chromedp)
│   │   │   ├── firefox/         # Firefox via Playwright
│   │   │   ├── webkit/          # WebKit via Playwright
│   │   │   ├── http3/           # QUIC/HTTP3 (quic-go)
│   │   │   └── waterfall/       # Multi-engine racing
│   │   └── pool/                # Browser instance pooling
│   ├── content/                 # Content extraction & agents
│   │   ├── agent/               # CDP-based autonomous browser agent
│   │   ├── agentic/             # ScrapeGraphAI-style graph scraping (~1,870 lines)
│   │   ├── semantic/            # Semantic tree + LLM compression
│   │   └── text/                # Text processing utilities
│   ├── core/                    # Shared infrastructure
│   │   ├── config/              # Central configuration
│   │   ├── constants/           # Defaults and known headers
│   │   ├── instrumentation/     # OpenTelemetry tracing
│   │   ├── observability/       # Prometheus metrics
│   │   ├── resilience/          # Circuit breakers, retry
│   │   ├── signals/             # OS signal handling
│   │   ├── telemetry/           # Distributed tracing
│   │   └── types/               # Canonical shared types
│   ├── crawl/                   # Large-scale crawling
│   │   ├── spider/              # Web spider framework
│   │   ├── pipeline/            # Batch processing
│   │   └── integration/         # Spider + stealth orchestrator
│   ├── fingerprint/             # Fingerprint capture & spoofing
│   │   ├── tls/                 # uTLS spoofing, JA3/JA4, parser
│   │   ├── http/                # HTTP/1.1 & HTTP/2 fingerprinting
│   │   ├── lab/                 # Fingerprint capture lab server
│   │   └── train/datagen/       # ML training data collection
│   ├── ml/                      # ML integration
│   │   └── adaptive/            # Adaptive behavior tracking
│   ├── network/                 # Network infrastructure
│   │   ├── proxy/               # MITM proxy for capture
│   │   │   └── pool/            # Proxy rotation & tier escalation
│   │   ├── client/              # HTTP client factory
│   │   └── sniff/               # CGO packet capture (Rust/libpcap)
│   └── stealth/                 # Anti-detection & challenge solving
│       ├── behavior/            # Behavioral simulation
│       ├── captcha/             # CAPTCHA solving
│       └── challenge/           # Cloudflare challenge detection
├── cmd/                         # CLI applications (~9K lines)
│   ├── brwslab/                 # Network fingerprinting CLI
│   ├── stealth/                 # Spider framework CLI
│   ├── labd/                    # Fingerprint lab server
│   ├── semantic/                # Semantic extraction CLI
│   ├── agent/                   # Browser automation CLI
│   ├── stealth-mcp/             # MCP server (browser automation)
│   ├── semantic-mcp/            # MCP server (semantic analysis)
│   ├── crawl/                   # Standalone crawler
│   ├── pipeline/                # Batch processing pipeline
│   ├── benchmark/               # Performance benchmarks
│   ├── train/                   # ML training orchestration
│   ├── eval_e2e/                # End-to-end evaluation
│   ├── evalbench/               # Evaluation suite
│   ├── extract/                 # Structured extraction
│   ├── gencert/                 # TLS cert generation
│   └── ml_datagen/              # ML training data generation
├── examples/                    # Usage examples
├── lab-ui/                      # React UI for fingerprint lab
├── models/                      # Trained PyTorch models (.pt)
├── pkg/                         # Public utility packages
│   ├── mathutils/               # Statistical functions
│   └── types/                   # Common detection types
├── deploy/                      # Kubernetes & Prometheus configs
└── training-data/               # ML training traces
```

---

## Key Capabilities

### 1. Multi-Engine HTTP Abstraction (`brws/browser/engine/`)

Unified `Engine` interface with four implementations:

| Engine | TLS | HTTP/2 | HTTP/3 | JS | Use Case |
|--------|-----|--------|--------|----|----------|
| `native` | uTLS spoofing | Yes | No | No | Fast API scraping |
| `chromium` | Real Chrome | Yes | Yes | Yes | Full browser automation |
| `firefox` | Real Firefox | Yes | Yes | Yes | Alternative fingerprint |
| `webkit` | Real Safari | Yes | Yes | Yes | Mobile/Apple testing |

Engines self-register via `init()`:
```go
func init() {
    engine.Register("native", newNativeEngine)
}
```

### 2. TLS/HTTP Fingerprint Spoofing (`brws/fingerprint/`)

- **Capture:** MITM proxy intercepts real browser traffic → parses ClientHello → builds `CompleteFingerprint`
- **Analysis:** JA3, JA4, GREASE detection, HTTP/2 SETTINGS frame analysis
- **Spoofing:** uTLS-based `ClientHelloID` selection to match target browser signatures
- **Adaptive:** ML-driven fingerprint selection based on success/failure outcomes

### 3. Anti-Detection & Challenge Solving (`brws/stealth/`)

- **21+ stealth detection vectors** fixed (screen mismatch, canvas format, WebGL extensions, etc.)
- **Behavioral simulation:** Bézier mouse curves, human-like typing, scroll patterns
- **Cloudflare solver:** Auto-detects JS/Managed/Turnstile challenges → solves → obtains `cf_clearance`
- **Session-pinned fingerprints:** Same browser instance uses consistent hardware fingerprints across requests
- **Escalation:** 6-tier retry (basic → proxy → browser → behavioral → CAPTCHA → human fallback)

### 4. Semantic Extraction (`brws/content/semantic/`)

- DOM chunking + LLM compression (~99% token reduction)
- SQLite-backed content-addressed cache
- Form schema extraction
- Visual grounding (bounding boxes)
- Incremental diffing

### 5. Agentic Graph Scraping (`brws/content/agentic/`)

- ScrapeGraphAI-style directed-graph execution engine
- Nodes: Fetch, Parse, GenerateAnswer, Reasoning, MergeAnswers, SearchInternet, Conditional
- Graphs: `SmartScraperGraph` (8 strategy variations), `SearchGraph`
- Map-reduce parallel chunk processing with goroutines + semaphores
- Zero imports into existing `brws/content/agent/` or browser engine packages

### 6. Autonomous Browser Agent (`brws/content/agent/`)

- CDP-based observe → decide → execute loop
- `PageSnapshot` with interactive elements, forms, links, tabs
- Action space: click, type, scroll, navigate, tab management
- LLM-formatted compact prompts for decision-making

### 7. Lab & Training (`brws/fingerprint/lab/`, `brws/ml/`)

- Fingerprint capture lab with TLS/HTTP2/HTTP analysis
- PyTorch RL models (`fsm_rl_policy.pt`, `shield_sword_policy.pt`)
- SQLite-backed training data collection
- Python training scripts for RL and adversarial shield/sword

---

## Design Decisions

### 1. Engine Registry Pattern
Engines self-register in `init()` functions, allowing import-side discovery without central registration files.

### 2. Independence Principle
The `agentic` package has **zero imports** into `brws/content/agent/`, `brws/browser/engine/browser/chromium/`, or `brws/stealth/`. It reuses only `brws/content/semantic` for the default LLM client.

### 3. Fingerprint-Bound Identity
Browser instances are coupled to a `CompleteFingerprint` for consistent headers, UA, TLS, and pacing across an entire session.

### 4. Server-Side Measurement
The fingerprint lab measures from the server side because that's what real defenses see. Client-side self-reporting can be misleading.

---

## Testing

```bash
# All tests
go test ./...

# With race detector
go test -race -count=1 -timeout 120s ./...

# Specific packages
go test ./brws/content/agentic/... -v
go test ./brws/stealth/... -v
go test ./brws/fingerprint/tls/... -v

# Lint
make lint

# Benchmarks
make bench
```

---

## Dependencies

**Core:**
- `github.com/chromedp/chromedp` — Chrome DevTools Protocol
- `github.com/playwright-community/playwright-go` — Cross-browser automation
- `github.com/refraction-networking/utls` — TLS fingerprint spoofing
- `github.com/quic-go/quic-go` — QUIC/HTTP3
- `github.com/spf13/cobra` — CLI framework
- `github.com/prometheus/client_golang` — Metrics
- `go.opentelemetry.io/otel` — Distributed tracing
- `go.uber.org/zap` — Structured logging
- `github.com/mattn/go-sqlite3` — SQLite (CGO)

---

## Documentation

| Document | Purpose |
|---|---|
| [`QUICKSTART.md`](../getting-started/QUICKSTART.md) | Get started in 15 minutes |
| [`MODELS_INDEX.md`](../modules/MODELS_INDEX.md) | Master index for module docs |
| [`GO_CONCEPTS.md`](../guides/GO_CONCEPTS.md) | Go patterns used in the codebase |
| [`AGENTIC_INTEGRATION.md`](../guides/AGENTIC_INTEGRATION.md) | Agentic graph engine summary |
| [`docs/ARCHITECTURE.md`](./ARCHITECTURE.md) | Complete system architecture |

---

## License

MIT License — See LICENSE file for details.
