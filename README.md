# brwslab

A Go toolkit for **browser-grade network fidelity**, **semantic web extraction**, and **stealth browser automation**.

## What It Does

brwslab provides four layers of capability:

1. **Engine Layer** — Unified HTTP client abstraction across native Go, Chromium (CDP), Firefox, and WebKit with real browser TLS/HTTP2/HTTP3 fingerprints
2. **Semantic Layer** — Extract hierarchical semantic trees from web pages with LLM-powered compression, diffing, form schemas, and token budget management
3. **Stealth Layer** — Anti-detection browser automation with Cloudflare challenge auto-solving, behavioral simulation, and RL-driven policy selection
4. **Agentic Layer** — ScrapeGraphAI-style directed-graph execution engine for LLM-centric scraping pipelines (`brws/content/agentic`)

## Installation

### Library

```bash
go get github.com/skunkworq/stealth
```

### CLI Tools

```bash
# Core tools
go install github.com/skunkworq/stealth/cmd/brwslab@latest
go install github.com/skunkworq/stealth/cmd/stealth@latest
go install github.com/skunkworq/stealth/cmd/labd@latest

# Semantic extraction
go install github.com/skunkworq/stealth/cmd/semantic@latest

# MCP servers (for Claude Desktop)
go install github.com/skunkworq/stealth/cmd/stealth-mcp@latest
go install github.com/skunkworq/stealth/cmd/semantic-mcp@latest
```

### Prerequisites

- **Go 1.26+**
- **For Chromium engine:** Chrome or Chromium browser installed
- **For Firefox/WebKit engines:**
  ```bash
  go run github.com/playwright-community/playwright-go/cmd/playwright@latest install --with-deps
  ```

---

## Quick Start

### Fetch a page with stealth

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/skunkworq/stealth/brws/stealth"
)

func main() {
    client, err := stealth.NewWithConfig(&stealth.Config{
        EngineName: "native",
        Stealth: &stealth.StealthConfig{
            Enabled:         true,
            RemoveWebDriver: true,
            CanvasNoise:     true,
        },
        Challenge: &stealth.ChallengeConfig{
            AutoDetect: true,
            AutoSolve:  true,
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    resp, err := client.Navigate(context.Background(), "https://example.com")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Status: %d, Size: %d bytes\n", resp.Status, len(resp.Body))
}
```

### Extract semantic tree

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/skunkworq/stealth/brws/semantic"
)

func main() {
    html := `<html><body><h1>Hello</h1><p>World</p></body></html>`

    tree, stats, err := semantic.HTMLToSemanticTree(
        context.Background(), html, "https://example.com", nil,
    )
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Title: %s, Nodes: %d\n", tree.Title, len(tree.RootNodes))
    fmt.Printf("Compression: %d -> %d tokens\n",
        stats.FullTreeTokens, stats.CompressedTokens)
}
```

### Use the engine directly

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/skunkworq/stealth/brws/browser/engine"
    _ "github.com/skunkworq/stealth/brws/browser/engine/browser/chromium"
    _ "github.com/skunkworq/stealth/brws/browser/engine/http/native"
)

func main() {
    eng, err := engine.New("chromium", engine.Options{Headless: true})
    if err != nil {
        log.Fatal(err)
    }
    defer eng.Close()

    resp, err := eng.Do(context.Background(), &engine.Request{
        URL: "https://example.com",
    })
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Status: %d, Protocol: %s\n", resp.Status, resp.Protocol)
}
```

---

## Library API

### `brws/engine` — HTTP Engine Abstraction

Unified interface for HTTP requests across different browser implementations.

```go
// Create an engine
eng, err := engine.New("native", engine.Options{
    Headless:    true,
    Timeout:     30 * time.Second,
    Stealth:     true,
    StealthTLS:  true,
    ProfileName: "chrome-120-macos",
})

// Make a request
resp, err := eng.Do(ctx, &engine.Request{
    URL:     "https://example.com",
    Method:  "GET",
    Headers: map[string][]string{"Accept": {"text/html"}},
    Timeout: 10 * time.Second,
})

// Response includes timing, protocol info, and trace data
fmt.Println(resp.Status, resp.Protocol, resp.Timing.Total)
```

**Available engines:**

| Engine | TLS | HTTP/2 | HTTP/3 | JavaScript | Notes |
|--------|-----|--------|--------|------------|-------|
| `native` | Go + uTLS | Yes | No | No | Fast, TLS fingerprint spoofing via uTLS |
| `chromium` | Chrome | Yes | Yes | Yes | Full CDP, NetLog export |
| `firefox` | Firefox | Yes | Yes | Yes | Via Playwright |
| `webkit` | Safari | Yes | Yes | Yes | Via Playwright |

### `brws/stealth` — Stealth Browser Client

High-level client with anti-detection, challenge solving, and behavioral simulation.

```go
client, _ := stealth.NewWithConfig(&stealth.Config{
    EngineName: "native",
    Headless:   true,

    // Anti-detection
    Stealth: &stealth.StealthConfig{
        Enabled:         true,
        RemoveWebDriver: true,
        CanvasNoise:     true,
        WebGLSpoof:      true,
        RandomUserAgent: true,
    },

    // Human-like behavior
    Behavior: &stealth.BehaviorConfig{
        HumanizeMouse:  true,
        RandomDelays:   true,
        TypingSpeedMin: 50 * time.Millisecond,
        TypingSpeedMax: 150 * time.Millisecond,
    },

    // Cloudflare challenge auto-solving
    Challenge: &stealth.ChallengeConfig{
        AutoDetect:     true,
        AutoSolve:      true,
        MaxSolveRetries: 3,
    },
})

// Navigate auto-solves CF challenges when encountered
resp, err := client.Navigate(ctx, "https://protected-site.com")
```

### `brws/semantic` — Semantic Tree Extraction

Extract structured, hierarchical representations of web pages with LLM compression.

```go
// Basic extraction (no LLM, structural only)
tree, stats, err := semantic.HTMLToSemanticTree(ctx, html, url, nil)

// With LLM compression
config := &semantic.PipelineConfig{
    LLMClient:       semantic.NewLLMClient(apiKey),
    EmbeddingClient: semantic.NewEmbeddingClient(apiKey),
    Cache:           cache,
}
tree, stats, err := semantic.HTMLToSemanticTreeCached(ctx, html, url, config)

// Compare two pages
diff := semantic.ComputeDiff(oldTree, newTree)
fmt.Printf("Changes: %s\n", diff.Summary())

// Serialize for LLM context with token budget
state := semantic.InitialPack(tree, 4000, 16000)
text := semantic.SerializeTree(tree, state, nil)

// Extract form schemas
forms := semantic.ExtractFormSchemas(html)
```

### `brws/content/agentic` — Agentic Graph Scraping

LLM-driven directed-graph execution engine for structured data extraction. Compose reusable nodes into graphs that fetch, parse, reason, and extract answers.

```go
// Single-page extraction with reasoning and retry
graph, _ := agentic.NewSmartScraperGraph(
    "Extract all product names and prices",
    "https://example.com/products",
    map[string]interface{}{"reasoning": true, "reattempt": true},
    nil, llm,
)
state, info, _ := graph.Run(ctx)
fmt.Println(state["answer"])

// Multi-URL search then scrape
searchGraph, _ := agentic.NewSearchGraph(
    "What are the latest features in Go 1.26?",
    map[string]interface{}{"max_results": 3},
    nil, llm,
)
state, _, _ = searchGraph.Run(ctx)
```

### `brws/adversarial` — Cloudflare Challenge Lab

Reproduce and test against realistic Cloudflare challenges locally.

```go
// Create a CF challenge emulator
cc := adversarial.NewCloudflareChallenger()

// Mount on an HTTP server
mux := http.NewServeMux()
cc.MountRoutes(mux)  // Mounts /api/cloudflare/* with rate limiting

// Or protect any handler with CF-style challenges
protected := cc.HandleProtectedPage(myHandler)

// Challenge types: JS, Managed, Turnstile
// Includes: PoW validation, fingerprint checking, behavioral analysis,
//           __cf_bm cookies, cf_clearance tokens, rate limiting
```

### `brws/session` — Session Management

Persistent cookie jars and browser profiles.

```go
mgr := session.NewManager(session.Options{
    StorageDir: "~/.brwslab/sessions",
})

sess, _ := mgr.Create("my-session", session.Config{
    Engine: "chromium",
})

// Sessions persist cookies, local storage, and browser state
```

---

## CLI Tools

### `brwslab` — Network Fingerprinting CLI

Multi-engine HTTP client with fingerprint capture and comparison.

```bash
# Fetch with a specific engine
brwslab fetch https://example.com --engine=chromium

# Capture TLS/HTTP2 fingerprint against the lab
brwslab fingerprint --engine=chromium --lab=http://localhost:8080

# Compare fingerprints across engines
brwslab diff --engine=native --engine=chromium --lab=http://localhost:8080

# Trace a request with timing data
brwslab trace https://example.com --engine=chromium --output=json

# Manage persistent browser sessions
brwslab session new --name=mytest --engine=chromium
brwslab session list
brwslab fetch https://example.com --session=<session-id>

# Interactive REPL
brwslab repl

# List available engines
brwslab engines
```

### `stealth` — Spider & Web Crawling Framework

```bash
# Crawl with a spider
stealth crawl -s myspider -e native -d 5 -c 16

# Fetch URL with semantic extraction
stealth fetch -e native https://example.com
stealth fetch -e native -j https://example.com  # JSON output

# Interactive shell
stealth shell
> get https://example.com
> help
> exit

# List spiders and engines
stealth list
```

### `semantic` — Semantic Extraction CLI

Extract and compress web page content for LLM consumption.

```bash
# Extract semantic tree (default: tree format)
semantic -url https://example.com

# JSON output
semantic -url https://example.com -format json -pretty

# Serialized text format for LLM context
semantic -url https://example.com -format serialized

# Compression statistics only
semantic -url https://example.com -format stats

# With LLM compression (requires OpenRouter API key)
export OPENROUTER_API_KEY=sk-or-...
semantic -url https://example.com -model openai/gpt-oss-120b

# Custom token budgets
semantic -url https://example.com -initial-budget 5000 -max-budget 128000

# With stealth engine
semantic -url https://example.com -engine native -stealth
```

### `labd` — Fingerprint Lab Server

Captures complete TLS, HTTP/2, and HTTP fingerprints from any browser.

```bash
# Start the lab server
labd --http-port 8080 --https-port 8443

# With MITM proxy for transparent capture
labd --proxy-port 8081 --tls-cert server.crt --tls-key server.key

# Auto-launch Chrome with proxy configured
labd --chrome -v
```

**Lab endpoints:**

| Endpoint | Description |
|----------|-------------|
| `GET /` | Web UI with real-time updates |
| `GET /capture/json` | JSON fingerprint |
| `GET /capture/yaml` | YAML export |
| `GET /health` | Server health check |
| `GET /proxy.pac` | Proxy auto-configuration |
| `WS /ws` | WebSocket for live fingerprint updates |

---

## MCP Servers

Both MCP servers integrate with [Claude Desktop](https://claude.ai/download) to provide browser automation and semantic extraction as tools.

### `stealth-mcp` — Browser Automation Server

Provides browser fetching with stealth mode and semantic extraction.

**Claude Desktop config** (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "stealth": {
      "command": "/path/to/stealth-mcp"
    }
  }
}
```

**Tools:**

| Tool | Description | Parameters |
|------|-------------|------------|
| `stealth_fetch` | Fetch URL with stealth browser and extract semantic tree | `url` (required) |
| `stealth_search` | Search within last fetched page by CSS selector or text | `query` (required) |
| `stealth_links` | Extract all links from last fetched page | — |
| `stealth_forms` | Extract all forms from last fetched page | — |

**Example interaction with Claude:**
> "Fetch https://example.com and tell me what forms are on the page"
>
> Claude calls `stealth_fetch` then `stealth_forms` and describes the results.

### `semantic-mcp` — Semantic Analysis Server

Advanced semantic tree extraction with LLM compression, diffing, and form analysis.

**Claude Desktop config:**

```json
{
  "mcpServers": {
    "semantic": {
      "command": "/path/to/semantic-mcp",
      "env": {
        "OPENROUTER_API_KEY": "sk-or-..."
      }
    }
  }
}
```

**Tools:**

| Tool | Description | Parameters |
|------|-------------|------------|
| `extract_semantic_tree` | Extract hierarchical page structure with compression | `url` (required), `html`, `include_forms`, `include_grounding` |
| `diff_semantic_trees` | Compare two pages and find differences | `old_url`, `new_url` (required) |
| `get_form_schemas` | Extract form field types, labels, validation constraints | `html` (required) |
| `serialize_tree` | Serialize tree to text format for LLM context | `url` (required), `token_budget` (default: 4000) |

---

## Adversarial Testing Lab

The `brws/adversarial` package provides a local Cloudflare challenge emulation environment for testing the stealth solver.

### Challenge Types

- **JS Challenge** — Proof-of-Work (SHA-256 hash prefix matching)
- **Managed Challenge** — PoW + fingerprint validation + behavioral analysis
- **Turnstile** — PoW + CAPTCHA token simulation

### Running the Lab

```go
// In test code
cc := adversarial.NewCloudflareChallenger()
mux := http.NewServeMux()
cc.MountRoutes(mux)  // Rate-limited CF endpoints

ts := httptest.NewServer(mux)
defer ts.Close()

// Now point the solver at ts.URL
solver := stealth.NewCloudflareSolverClient()
result, err := solver.SolveChallenge(ts.URL, adversarial.ChallengeJS)
```

### What It Emulates

- `__cf_bm` session cookies with validation
- `cf_clearance` tokens in realistic format (`{token}-{timestamp}-{version}-{hmac}`)
- Per-IP token bucket rate limiting with 429 responses
- `Cf-Mitigated`, `Cf-Ray`, `Server: cloudflare` headers
- Challenge page HTML with fingerprint collection JavaScript
- XHR callbacks to `/cdn-cgi/challenge-platform/h/g/cv/result/{rayID}`
- Solve time bounds (rejects superhuman < 1.5s solves)
- Challenge escalation (JS -> Managed -> Blocked)

---

## Project Structure

```
stealth/
├── brws/                        # Library packages
│   ├── browser/                 # Browser automation
│   │   ├── engine/              # HTTP engine abstraction
│   │   │   ├── native/          # Go net/http + uTLS
│   │   │   ├── chromium/        # Chrome CDP
│   │   │   ├── firefox/         # Firefox via Playwright
│   │   │   ├── webkit/          # WebKit via Playwright
│   │   │   ├── http3/           # QUIC/HTTP3
│   │   │   ├── testserver/      # Mock detection server
│   │   │   └── waterfall/       # Multi-engine racing
│   │   └── pool/                # Browser instance pooling
│   ├── content/                 # Content extraction
│   │   ├── agent/               # CDP-based autonomous browser agent
│   │   ├── agentic/             # ScrapeGraphAI-style graph scraping
│   │   ├── semantic/            # Semantic tree extraction + LLM compression
│   │   │   └── index/           # HNSW vector indexing
│   │   └── text/                # Text processing utilities
│   ├── core/                    # Shared infrastructure
│   │   ├── config/              # Central configuration
│   │   ├── constants/           # Default values and headers
│   │   ├── instrumentation/     # OpenTelemetry tracing + metrics
│   │   ├── log/                 # Structured logging
│   │   ├── observability/       # Prometheus metrics + health checks
│   │   ├── resilience/          # Circuit breakers, retry logic
│   │   ├── signals/             # OS signal handling
│   │   ├── telemetry/           # Distributed tracing
│   │   └── types/               # Shared canonical types
│   ├── crawl/                   # Large-scale crawling
│   │   ├── integration/         # Spider + stealth orchestrator
│   │   ├── pipeline/            # Batch processing pipeline
│   │   └── spider/              # Web spider framework
│   ├── fingerprint/             # Fingerprint capture & spoofing
│   │   ├── bench/               # Performance benchmarks
│   │   ├── http/                # HTTP/1.1 & HTTP/2 fingerprinting
│   │   ├── lab/                 # Fingerprint capture lab server
│   │   ├── tls/                 # TLS spoofing, JA3/JA4, parser
│   │   │   └── parser/          # Binary TLS ClientHello parser
│   │   └── train/datagen/       # ML training data collection
│   ├── ml/                      # ML integration
│   │   └── adaptive/            # Adaptive behavior tracking & storage
│   ├── network/                 # Network infrastructure
│   │   ├── client/              # HTTP client factory
│   │   ├── proxy/               # MITM proxy for capture
│   │   │   └── pool/            # Proxy rotation & tier escalation
│   │   └── sniff/               # CGO packet capture (libpcap/Rust)
│   └── stealth/                 # Anti-detection & challenge solving
│       ├── behavior/            # Behavioral simulation (mouse, typing, scroll)
│       ├── captcha/             # CAPTCHA solving (segmentation, ML, external)
│       └── challenge/           # Cloudflare challenge detection & solving
├── cmd/                         # CLI applications
│   ├── agent/                   # Browser automation CLI
│   ├── benchmark/               # Performance benchmarks
│   ├── brwslab/                 # Network fingerprinting CLI
│   ├── crawl/                   # Standalone crawler
│   ├── eval_e2e/                # End-to-end evaluation
│   ├── evalbench/               # Evaluation suite
│   ├── extract/                 # Structured extraction CLI
│   ├── gencert/                 # TLS cert generation for MITM
│   ├── labd/                    # Fingerprint lab server
│   ├── ml_datagen/              # ML training data generation
│   ├── pipeline/                # Processing pipeline CLI
│   ├── semantic/                # Semantic extraction CLI
│   ├── semantic-mcp/            # MCP server (semantic analysis)
│   ├── stealth/                 # Spider framework CLI
│   ├── stealth-mcp/             # MCP server (browser automation)
│   └── train/                   # ML training orchestration
├── deploy/                      # Deployment configs
│   ├── kubernetes/              # K8s manifests
│   └── prometheus/              # Prometheus rules
├── docs/                        # Architecture docs (gitignored)
├── examples/                    # Usage examples
│   └── navigation/              # Navigation examples
├── fingerprints/                # Captured browser fingerprints (JSON)
├── lab-ui/                      # React UI for fingerprint lab
├── models/                      # Trained PyTorch models (.pt)
├── pkg/                         # Public utility packages
│   ├── mathutils/               # Statistical functions
│   └── types/                   # Common detection types
├── python/                      # Python bindings
│   └── pybrwslab/               # Python wrapper package
├── scripts/                     # Build & install scripts
├── training-data/               # ML training traces
├── go.mod                       # Go module definition
├── Makefile                     # Build, test, run targets
├── Dockerfile                   # Container image
└── .golangci.yml                # Linter configuration
```

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENROUTER_API_KEY` | API key for LLM compression (semantic tools) | — |
| `BRWSLAB_SESSIONS_DIR` | Session storage directory | `~/.brwslab/sessions` |
| `BRWSLAB_LAB_URL` | Default lab server URL | — |
| `CHROME_PATH` / `CHROMIUM_PATH` | Browser executable path | Auto-detected |

### Stealth Configuration

```go
&stealth.Config{
    EngineName: "native",        // or "chromium", "firefox", "webkit"
    Headless:   true,

    Stealth: &stealth.StealthConfig{
        Enabled:         true,
        RemoveWebDriver: true,   // Remove navigator.webdriver
        CanvasNoise:     true,   // Add canvas fingerprint noise
        WebGLSpoof:      true,   // Spoof WebGL renderer info
        ClientHints:     true,   // Spoof client hints
        FakeScreen:      true,   // Fake screen dimensions
        FakeTimezone:    true,   // Fake timezone
        RandomUserAgent: true,   // Rotate user agents
    },

    Behavior: &stealth.BehaviorConfig{
        HumanizeMouse: true,     // Bezier curve mouse movements
        RandomDelays:  true,     // Human-like timing jitter
    },

    Challenge: &stealth.ChallengeConfig{
        AutoDetect: true,        // Detect CF challenges in responses
        AutoSolve:  true,        // Auto-solve PoW + fingerprint challenges
    },
}
```

---

## Development

### Build

```bash
# Build all binaries
make build

# Build specific binary
go build -o build/stealth ./cmd/stealth

# Run the fingerprint lab with UI
make run
```

### Test

```bash
# Run all tests
go test ./...

# With race detector
go test -race -count=1 -timeout 120s ./...

# Specific package
go test ./brws/stealth/ -v
go test ./brws/adversarial/ -v
go test ./brws/semantic/ -v

# Short mode (skip slow tests)
go test -short ./...
```

### Lint

```bash
# Install golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Run linter
golangci-lint run ./...

# Or via make
make lint
```

### Benchmarks

```bash
make bench           # Run all benchmarks
make bench-cpu       # With CPU profiling
make bench-mem       # With memory profiling
```

---

## Documentation

| Document | Purpose |
|---|---|
| [`QUICKSTART.md`](docs/getting-started/QUICKSTART.md) | Get from zero to scraping in 15 minutes |
| [`MODELS_INDEX.md`](docs/modules/MODELS_INDEX.md) | Master index for all module documentation |
| [`MODEL_STEALTH.md`](docs/modules/MODEL_STEALTH.md) | Anti-detection, CAPTCHA solving, behavioral evasion |
| [`MODEL_FINGERPRINT.md`](docs/modules/MODEL_FINGERPRINT.md) | TLS/HTTP fingerprint capture, JA3/JA4, uTLS spoofing |
| [`MODEL_BROWSER.md`](docs/modules/MODEL_BROWSER.md) | Browser engine (Chromium, Firefox, WebKit) |
| [`MODEL_NETWORK.md`](docs/modules/MODEL_NETWORK.md) | MITM proxy, proxy rotation, tier escalation |
| [`MODEL_CONTENT.md`](docs/modules/MODEL_CONTENT.md) | CDP agent, semantic pipeline, agentic scraping, crawl |
| [`MODEL_ML.md`](docs/modules/MODEL_ML.md) | RL models, training, types, config, telemetry |
| [`AGENTIC_INTEGRATION.md`](docs/guides/AGENTIC_INTEGRATION.md) | ScrapeGraphAI-style graph engine integration summary |
| [`GO_CONCEPTS.md`](docs/guides/GO_CONCEPTS.md) | Go language patterns used throughout the codebase |
| [`docs/ARCHITECTURE.md`](docs/architecture/ARCHITECTURE.md) | Complete system architecture overview |
| [`TODO.md`](docs/planning/TODO.md) | Feature parity checklist and completed phases |
| [`ROADMAP.md`](docs/planning/ROADMAP.md) | Battle testing & advanced use cases roadmap |
| [`REFACTORING_PLAN.md`](docs/planning/REFACTORING_PLAN.md) | Code modularization plan and progress |

---

## License

MIT

## Acknowledgments

- [curl-impersonate](https://github.com/lwthiker/curl-impersonate) — TLS fingerprint impersonation
- [uTLS](https://github.com/refraction-networking/utls) — Go TLS fingerprint spoofing
- [JA3/JA4](https://github.com/salesforce/ja3) — TLS fingerprinting from Salesforce
- [chromedp](https://github.com/chromedp/chromedp) — Chrome DevTools Protocol for Go
- [playwright-go](https://github.com/playwright-community/playwright-go) — Playwright for Go
- [mcp-go](https://github.com/mark3labs/mcp-go) — Model Context Protocol for Go
