# Project Directory Map

> **Note:** This map describes the conceptual package organization. The actual directory structure has evolved — engines live under `brws/browser/engine/`, fingerprint code under `brws/fingerprint/`, stealth code under `brws/stealth/`, core infrastructure under `brws/core/`, network code under `brws/network/`, and crawl code under `brws/crawl/`. See [`README.md`](../README.md) for the current directory tree.

**Stealth** is a large project because web scraping at scale is a hard problem that touches many domains: networking, cryptography, browser automation, machine learning, distributed systems, and UI. Here's what every folder does and why it exists.

---

## Quick Overview

| Category | Count | Purpose |
|----------|-------|---------|
| Core Go packages (`brws/*`) | 35 | The actual scraping/stealth/agent library |
| CLI tools (`cmd/*`) | 23 | Binaries you run from the shell |
| Lab UI (`lab-ui/*`) | 1 app | Next.js dashboard for the fingerprint lab |
| Deployment (`deploy/*`) | 2 configs | Kubernetes + Prometheus for production |
| Docs & examples | 3 dirs | Documentation and sample code |
| Assets | 2 dirs | ML models, fingerprint JSON files |
| Dev infrastructure | 3 dirs | CI, scripts, agent workflows |

---

## `brws/*` — The Core Go Library

These are the heart of the project. They're organized by concern, not by layer. Most real-world Go projects of this size split into ~20–40 packages.

### The four layers + cross-cutting

| Package | What it does | Layer |
|---------|-------------|-------|
| `brws/browser/engine` | Engine interface + registry (`native`, `http3`, `chromium`, `firefox`, `webkit`) | 1 — Engine |
| `brws/network/` | HTTP client, MITM proxy, packet sniffer | 1 — Engine |
| `brws/stealth` | Main client — orchestrates engine, session, challenges, escalation | 2 — Stealth |
| `brws/content/understand` | DOM extraction, LLM compression, semantic trees, form schemas | 3 — Content |
| `brws/content/agent` | Observation-action loop for autonomous agents | 3 — Content |
| `brws/content/scrapegraph` | ScrapeGraphAI-style graph execution for LLM-driven scraping | 3 — Content |
| `brws/crawl/` | Crawler, spider, integration layer, ingest pipeline | 4 — Scale |
| `brws/fingerprint/` | TLS/HTTP fingerprint capture and spoofing | 4 — Scale |
| `brws/core/` | Shared infrastructure (instrumentation, resilience, events, config…) | Cross-cutting |
| `brws/llm/` | LLM abstraction (completions + embeddings) used by Layers 2–4 | Cross-cutting |
| `brws/research/` | Offline benchmarks, training data, detection analysis, evasion labs | Out-of-band |

### Engine sub-packages

| Package | What it does | Why it exists |
|---------|-------------|---------------|
| `brws/browser/engine/http/native` | Go `net/http` + uTLS fingerprint spoofing | Fast, no-JS requests that look like Chrome/Firefox |
| `brws/browser/engine/http/http3` | QUIC/HTTP3 via quic-go | Modern transport for sites that require HTTP3 |
| `brws/browser/engine/browser/chromium` | Full Chrome via chromedp/CDP | JS execution, NetLog, request interception |
| `brws/browser/engine/browser/firefox` | Firefox via Playwright | Alternative browser fingerprint |
| `brws/browser/engine/browser/webkit` | Safari via Playwright | Mobile/Apple testing |
| `brws/browser/instancepool` | Browser instance pooling | Recycle expensive browser instances |
| `brws/browser/engine/meta/waterfall` | Engine fallback logic (native → chromium → etc.) | Automatic retry with harder configs |
| `brws/fingerprint/tls` | TLS fingerprint generation and spoofing | Impersonate Chrome/Firefox TLS handshakes |
| `brws/fingerprint/tls/parser` | Raw TLS ClientHello parsing | Inspect TLS from packet captures |

### Anti-detection & evasion

| Package | What it does | Why it exists |
|---------|-------------|---------------|
| `brws/stealth/behavior` | Human-like event generation (mouse, typing, scroll) + evasion strategies | Bot detectors check mouse paths and keystroke timing |
| `brws/stealth/challenge` | Challenge detection + FSM solver (Cloudflare, reCAPTCHA, hCaptcha, DataDome) | Know what you're facing before trying to solve it |
| `brws/stealth/challenge/cloudflare` | Cloudflare-specific solve handlers | Isolated from the generic FSM for faster iteration |
| `brws/stealth/captcha` | CAPTCHA solving — ML model, vision LLM, external services (CapSolver) | Auto-solve when browser automation isn't enough |
| `brws/stealth/script/spoof` | JS payload injection for navigator/canvas/WebGL spoofing | Patch browser APIs to remove headless signals |
| `brws/stealth/solver` | Adapters bridging `challenge/fsm` to external solver APIs | Decouple challenge FSM from service integrations |
| `brws/stealth/profile/session` | Persistent browser profiles and session storage | Maintain identity across requests |
| `brws/research/rl/adaptive` | Adaptive strategy tracking and RL-based performance storage | Remember which evasion strategies worked on which sites |

### Content extraction & processing

| Package | What it does | Why it exists |
|---------|-------------|---------------|
| `brws/content/understand` | DOM → semantic tree compression | LLM-friendly page representation |
| `brws/content/scrapegraph` | ScrapeGraphAI-style graph scraping engine | LLM-driven structured data extraction |
| `brws/crawl/ingest` | Integrated crawler pipeline with distributed tracing + Prometheus metrics | Production-grade crawling with observability |
| `brws/fingerprint/http/diff` | Diff between HTTP responses/fingerprints | Detect page changes, validate stealth |
| `brws/llm/completions` | `LLM` interface + OpenAI and Anthropic implementations | Shared LLM abstraction across layers |
| `brws/llm/embed` | `Embedder` interface for vector embeddings | Shared embedding abstraction |

### Crawling & spidering

| Package | What it does | Why it exists |
|---------|-------------|---------------|
| `brws/crawl/spider` | Scrapy-inspired web crawler | Concurrent crawling with middleware, scheduling, dedup |
| `brws/network/client` | HTTP client utilities | Shared HTTP logic across engines |
| `brws/crawl/integration` | Spider + stealth orchestrator | Coordinate crawling with anti-detection |

### Session & state management

| Package | What it does | Why it exists |
|---------|-------------|---------------|
| `brws/browser/instancepool` | Browser instance pooling and session reuse | Stay logged in across requests |
| `brws/core/events` | Event bus for crawler lifecycle signals (ban, challenge, complete) | Decouple components across layer boundaries |
| `brws/core/types` | Shared domain types | Common structs used across packages |

### Resilience & reliability

| Package | What it does | Why it exists |
|---------|-------------|---------------|
| `brws/core/resilience` | Retry, circuit breaker, rate limiting | Don't hammer dead sites, back off gracefully |

### ML & intelligence

| Package | What it does | Why it exists |
|---------|-------------|---------------|
| `brws/ml` | RL policy loader (PyTorch DQN models) | Load trained stealth policies at runtime |
| `brws/research/rl/adaptive` | Per-domain strategy storage and performance tracking | Research loop for the RL training pipeline |

### Observability & ops

| Package | What it does | Why it exists |
|---------|-------------|---------------|
| `brws/core/instrumentation` | Logging, tracing, hooks, FSM state tracking | Debug why a request failed |
| `brws/core/observability` | Health checks, metrics HTTP handler | Production monitoring |
| `brws/core/telemetry` | OpenTelemetry integration | Distributed tracing in production |
| `brws/core/detection` | Bot-detection vector analysis | Understand which signals are being checked |
| `brws/core/trust` | Proxy/identity trust scoring | Route requests through the right proxy tier |

### Network & proxy

| Package | What it does | Why it exists |
|---------|-------------|---------------|
| `brws/network/proxy` | MITM TLS/HTTP proxy for fingerprint capture | Inspect TLS handshakes and HTTP/2 frames |
| `brws/network/sniff` | Packet capture via libpcap + Rust bridge (`sniff/rust`) | Capture raw network traffic for analysis |

### Configuration & constants

| Package | What it does | Why it exists |
|---------|-------------|---------------|
| `brws/core/config` | Configuration loading and validation | YAML/JSON config files |
| `brws/core/constants` | Shared constants | Magic numbers, header names, etc. |

### Research & training (`brws/research/`)

All research, benchmarking, and training-data packages live here. Nothing in the production layers imports from `research/`.

| Package | What it does | Why it exists |
|---------|-------------|---------------|
| `brws/research/evasion/cloudflare` | Local Cloudflare emulator (formerly `brws/adversarial`) | Test challenge solver without hitting production |
| `brws/research/evasion/recaptcha` | reCAPTCHA evasion research server | Offline experimentation |
| `brws/research/detection/` | Detection analysis: analyzers, scoring, trace lab | Understand and replay bot-detection signals |
| `brws/research/fingerprint/capture` | Live fingerprint capture harness | Capture real browser signatures for training |
| `brws/research/fingerprint/training` | Training data generation for TLS/HTTP fingerprint models | SQLite-backed episode storage for RL training |
| `brws/research/captcha/ml` | Vision LLM CAPTCHA solver experiments | Prototype before promoting to `stealth/captcha` |
| `brws/research/captcha/training` | CAPTCHA training data collection | Build labelled datasets |
| `brws/research/bench/fingerprint` | Fingerprint detection benchmarks and blackbox probing | Measure engine speed, memory, success rates |
| `brws/research/bench/understand` | SemanticTree compression benchmarks | Measure token reduction and latency |

---

## `cmd/*` — CLI Tools (23 binaries)

Each `cmd/<name>/main.go` compiles to a standalone binary. This is standard Go practice — one `main` package per binary.

### Core tools you use daily

| Binary | Path | What it does |
|--------|------|-------------|
| `stealth` | `cmd/scrape/stealth/stealth` | Main stealth fetch/crawl CLI |
| `brwslab` | `cmd/lab/cli/brwslab` | Network fidelity testing — diff engines, trace requests, fingerprint analysis |
| `semantic` | `cmd/semantic/cli/semantic` | Extract semantic trees from URLs via CLI |
| `agent` | `cmd/scrape/agent/agent` | Browser automation — observe, execute, step |

### Servers & APIs

| Binary | Path | What it does |
|--------|------|-------------|
| `agent-server` | `cmd/scrape/agent/server` | WebSocket/REST hub for the agent UI |
| `semantic-server` | `cmd/semantic/server/semantic-server` | HTTP REST API for semantic extraction |
| `semantic-mcp` | `cmd/semantic/server/semantic-mcp` | MCP (Model Context Protocol) server for Claude Desktop |
| `stealth-mcp` | `cmd/scrape/stealth/stealth-mcp` | MCP server for stealth operations |
| `labd` | `cmd/lab/server/labd` | Fingerprint capture lab daemon |

### Specialized tools

| Binary | Path | What it does |
|--------|------|-------------|
| `crawl` | `cmd/scrape/core/crawl` | Standalone crawler |
| `semanticcrawl` | `cmd/scrape/core/semanticcrawl` | Crawl + extract semantic trees in one pass |
| `extract` | `cmd/scrape/core/extract` | Standalone content extractor |
| `pipeline` | `cmd/scrape/core/pipeline` | Run processing pipelines |
| `ml_datagen` | `cmd/ml/train/ml_datagen` | Generate datasets for ML model training |
| `gencert` | `cmd/lab/cli/gencert` | TLS certificate generation for MITM proxy |
| `scanciphers` | `cmd/lab/cli/scanciphers` | TLS cipher suite scanner |

### Testing & benchmarking

| Binary | Path | What it does |
|--------|------|-------------|
| `evalbench` | `cmd/bench/evalbench` | Evaluation benchmark suite |
| `eval_e2e` | `cmd/bench/eval_e2e` | End-to-end evaluation |
| `vecbench` | `cmd/bench/vecbench` | Vector embedding benchmarks |
| `test_realworld` | `cmd/semantic/cli/test_realworld` | Real-world integration tests |
| `test_semantic` | `cmd/semantic/cli/test_semantic` | Semantic extraction tests |

---

## `lab-ui/*` — Fingerprint Lab Dashboard

| Path | What it does |
|------|-------------|
| `lab-ui/` | Next.js (React) web application |
| `lab-ui/src/` | Frontend components |
| `lab-ui/public/` | Static assets |

**What it shows:** A visual dashboard for the fingerprint capture lab. You can:
- See captured fingerprints in real-time
- Compare your stealth config against human baselines
- Visualize TLS handshakes, HTTP/2 frames, header orders
- Trigger training sessions

**Why a separate UI?** The lab is used by researchers and developers who want to see fingerprints visually, not just JSON logs.

---

## `deploy/*` — Production Infrastructure

| Path | What it does |
|------|-------------|
| `deploy/kubernetes/` | K8s manifests for deploying semantic-server, labd, etc. |
| `deploy/prometheus/` | Prometheus scraping configs for metrics |

**Why included?** This project is designed to run at scale — multiple instances scraping in parallel, with monitoring and auto-scaling.

---

## `docs/*` — Documentation

| Path | What it does |
|------|-------------|
| `docs/ARCHITECTURE.md` | System architecture overview (what you just read) |
| `docs/IMPLEMENTATION_PLAN.md` | Feature roadmap and implementation timeline |
| `docs/SEMANTIC_COSTS.md` | LLM API cost analysis for semantic extraction |

---

## `fingerprints/` — Fingerprint Database

| Path | What it does |
|------|-------------|
| `fingerprints/samples/chrome/chrome-116-custom.json` | A captured Chrome 116 fingerprint (TLS, HTTP/2, headers) |

**Why a directory?** The lab generates hundreds of these. They're used to:
- Validate stealth configs (does my spoofed Chrome match the real one?)
- Train ML models
- Build the trace library for replay-based solving

---

## `models/` — ML Models

| Path | What it does |
|------|-------------|
| `models/fsm_rl_policy.pt` | DQN policy for adaptive stealth config |
| `models/shield_sword_policy.pt` | DQN policy for challenge escalation |

**Why checked in?** These are the trained models that the RL system loads at runtime. They're relatively small (~MBs) and version-controlled alongside the code.

---

## `examples/` — Go Examples

| Path | What it does |
|------|-------------|
| `examples/basic_fetch.go` | Simple HTTP fetch example |

**Why so few?** Most examples are in the READMEs and docs.

---

## `pkg/` — Shared Utilities

| Path | What it does |
|------|-------------|
| `pkg/mathutils/` | Math utilities (used by behavioral generators) |
| `pkg/types/` | Shared type definitions |

**Why `pkg/`?** Go convention — packages in `pkg/` are meant to be imported by external projects.

---

## `scripts/` — Dev Scripts

| Path | What it does |
|------|-------------|
| `scripts/install-golangci-lint.sh` | Install linter |
| `scripts/install-hooks.sh` | Install git hooks |
| `scripts/run_benchmarks.sh` | Run benchmark suite |

---

## `.github/` — CI/CD

| Path | What it does |
|------|-------------|
| `.github/workflows/` | GitHub Actions workflows (tests, builds, releases) |

---

## `.agents/` — Agent Workflows

| Path | What it does |
|------|-------------|
| `.agents/workflows/` | Kimi agent workflow definitions |

---

## Training Data

Training data lives under the relevant `brws/research/` subpackage alongside the code that uses it.

| Path | What it does |
|------|-------------|
| `brws/research/fingerprint/training/session-001/` | Captured fingerprint sessions (TLS, HTTP headers, navigation traces) |
| `brws/research/captcha/training/traces/` | Turnstile challenge recordings (session + per-challenge JSON) |

**Why checked in?** Sample data for development and testing. Real production data is not checked in.

---

## Summary: Why So Many Folders?

| Reason | Explanation |
|--------|-------------|
| **Separation of concerns** | Each package does one thing well. `tlsfprint` doesn't know about `semantic`. |
| **Swappability** | You can replace `engine/chromium` with `engine/firefox` without touching `stealth`. |
| **Testability** | Small packages are easier to unit test in isolation. |
| **Team scale** | Multiple developers can work on different packages without conflicts. |
| **CLI granularity** | Each binary is a focused tool. You don't ship a 500MB monolith when you just need `gencert`. |
| **Language boundaries** | Go does the heavy lifting (browser automation, crypto, ML). Python does the UX (notebooks, AI frameworks). |
| **Research vs production** | `brws/research/` contains labs, benchmarks, and training-data tools. `crawl/ingest`, `core/resilience`, and `core/observability` are production tools. Both coexist without cross-importing. |

**The project looks big, but it's organized.** If you just want to scrape a page, you only touch 3–4 packages. If you want to research TLS fingerprints, you dive into `tlsfprint/` and `lab/`. If you want to build an AI agent, you use `agent/` and `semantic/`.
