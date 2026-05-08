# Project Directory Map

> **Note:** This map describes the conceptual package organization. The actual directory structure has evolved — engines live under `brws/browser/engine/`, fingerprint code under `brws/fingerprint/`, stealth code under `brws/stealth/`, core infrastructure under `brws/core/`, network code under `brws/network/`, and crawl code under `brws/crawl/`. See [`README.md`](README.md) for the current directory tree.

**Stealth** is a large project because web scraping at scale is a hard problem that touches many domains: networking, cryptography, browser automation, machine learning, distributed systems, and UI. Here's what every folder does and why it exists.

---

## Quick Overview

| Category | Count | Purpose |
|----------|-------|---------|
| Core Go packages (`brws/*`) | 35 | The actual scraping/stealth/agent library |
| CLI tools (`cmd/*`) | 23 | Binaries you run from the shell |
| Python wrappers (`python/*`) | 1 package | Python interface to the Go binaries |
| Lab UI (`lab-ui/*`) | 1 app | Next.js dashboard for the fingerprint lab |
| Deployment (`deploy/*`) | 2 configs | Kubernetes + Prometheus for production |
| Docs & examples | 3 dirs | Documentation and sample code |
| Assets | 2 dirs | ML models, fingerprint JSON files |
| Dev infrastructure | 3 dirs | CI, scripts, agent workflows |

---

## `brws/*` — The Core Go Library (35 packages)

These are the heart of the project. They're organized by concern, not by layer. Most real-world Go projects of this size split into ~20–40 packages.

### The five layers you already know

| Package | What it does | Size |
|---------|-------------|------|
| `brws/browser/engine` | Engine interface + registry (`native`, `chromium`, `firefox`, `webkit`) | Core |
| `brws/stealth` | Main client — orchestrates engine, session, challenges, escalation | Core |
| `brws/content/semantic` | DOM extraction, LLM compression, semantic trees, form schemas | Core |
| `brws/content/agent` | Observation-action loop for autonomous agents | Core |
| `brws/content/agentic` | ScrapeGraphAI-style graph execution for LLM-driven scraping | Core |

### Engine sub-packages

| Package | What it does | Why it exists |
|---------|-------------|---------------|
| `brws/browser/engine/native` | Go `net/http` + uTLS fingerprint spoofing | Fast, no-JS requests that look like Chrome/Firefox |
| `brws/browser/engine/chromium` | Full Chrome via chromedp/CDP | JS execution, NetLog, request interception |
| `brws/browser/engine/firefox` | Firefox via Playwright | Alternative browser fingerprint |
| `brws/browser/engine/webkit` | Safari via Playwright | Mobile/Apple testing |
| `brws/browser/pool` | Browser instance pooling | Recycle expensive browser instances |
| `brws/browser/engine/waterfall` | Engine fallback logic (native → chromium → etc.) | Automatic retry with harder configs |
| `brws/fingerprint/tls` | TLS fingerprint generation and spoofing | Impersonate Chrome/Firefox TLS handshakes |
| `brws/fingerprint/tls/parser` | Raw TLS ClientHello parsing | Inspect TLS from packet captures |
| `brws/fingerprint/lab` | Fingerprint capture lab server | Capture real browser signatures for training |

### Anti-detection & evasion

| Package | What it does | Why it exists |
|---------|-------------|---------------|
| `brws/stealth/behavior` | Human-like event generation (mouse, typing, scroll) + evasion strategies | Bot detectors check mouse paths and keystroke timing |
| `brws/stealth/challenge` | Challenge type detection (Cloudflare, reCAPTCHA, hCaptcha, DataDome) | Know what you're facing before trying to solve it |
| `brws/stealth/captcha` | CAPTCHA solving (segmentation, ML model, external services) | Auto-solve when browser automation isn't enough |
| `brws/ml/adaptive` | Adaptive strategy tracking and storage | Remember which evasion strategies worked on which sites |

### Content extraction & processing

| Package | What it does | Why it exists |
|---------|-------------|---------------|
| `brws/content/semantic` | DOM → semantic tree compression | LLM-friendly page representation |
| `brws/content/agentic` | ScrapeGraphAI-style graph scraping engine | LLM-driven structured data extraction |
| `brws/content/text` | Text processing utilities | Language-aware chunking and cleaning |
| `brws/crawl/pipeline` | Integrated crawler pipeline with tracing + metrics | Production-grade crawling with observability |
| `brws/fingerprint/http/diff` | Diff between HTTP responses/fingerprints | Detect page changes, validate stealth |

### Crawling & spidering

| Package | What it does | Why it exists |
|---------|-------------|---------------|
| `brws/crawl/spider` | Scrapy-inspired web crawler | Concurrent crawling with middleware, scheduling, dedup |
| `brws/network/client` | HTTP client utilities | Shared HTTP logic across engines |
| `brws/crawl/integration` | Spider + stealth orchestrator | Coordinate crawling with anti-detection |

### Session & state management

| Package | What it does | Why it exists |
|---------|-------------|---------------|
| `brws/browser/pool` | Browser instance pooling and session reuse | Stay logged in across requests |
| `brws/core/signals` | Event bus for crawler lifecycle events | Decouple components |
| `brws/core/types` | Shared domain types | Common structs used across packages |

### Resilience & reliability

| Package | What it does | Why it exists |
|---------|-------------|---------------|
| `brws/core/resilience` | Retry, circuit breaker, rate limiting | Don't hammer dead sites, back off gracefully |

### ML & intelligence

| Package | What it does | Why it exists |
|---------|-------------|---------------|
| `brws/ml` | RL policy loader (PyTorch DQN models) | Adapt stealth config based on detection feedback |
| `brws/fingerprint/bench` | Performance benchmarks | Measure engine speed, memory, success rates |

### Observability & ops

| Package | What it does | Why it exists |
|---------|-------------|---------------|
| `brws/core/instrumentation` | Logging, tracing, hooks, FSM state tracking | Debug why a request failed |
| `brws/core/observability` | Metrics and health checks | Production monitoring |
| `brws/core/telemetry` | Usage telemetry and analytics | Understand system behavior at scale |
| `brws/core/log` | Structured logging utilities | Consistent log format across the project |

### Network & proxy

| Package | What it does | Why it exists |
|---------|-------------|---------------|
| `brws/network/proxy` | MITM TLS/HTTP proxy for fingerprint capture | Inspect TLS handshakes and HTTP/2 frames |
| `brws/network/sniffer` | Packet capture via libpcap + Rust bridge | Capture raw network traffic for analysis |

### Configuration & constants

| Package | What it does | Why it exists |
|---------|-------------|---------------|
| `brws/core/config` | Configuration loading and validation | YAML/JSON config files |
| `brws/core/constants` | Shared constants | Magic numbers, header names, etc. |

### Lab & training

| Package | What it does | Why it exists |
|---------|-------------|---------------|
| `brws/fingerprint/lab` | Fingerprint capture lab (covered in ARCHITECTURE.md) | Capture real browser signatures for training |
| `brws/fingerprint/train/datagen` | ML training data collection | SQLite-backed episode storage for RL training |

### Integration

| Package | What it does | Why it exists |
|---------|-------------|---------------|
| `brws/integration` | Third-party integrations | Connect to external services |

---

## `cmd/*` — CLI Tools (23 binaries)

Each `cmd/<name>/main.go` compiles to a standalone binary. This is standard Go practice — one `main` package per binary.

### Core tools you use daily

| Binary | File | What it does |
|--------|------|-------------|
| `stealth` | `cmd/stealth` | Main CLI — fetch URLs, run spiders, start lab, training sessions |
| `brwslab` | `cmd/brwslab` | Network fidelity testing — diff engines, trace requests, fingerprint analysis |
| `semantic` | `cmd/semantic` | Extract semantic trees from URLs via CLI |
| `agent` | `cmd/agent` | Browser automation — observe, execute, step |

### Servers & APIs

| Binary | File | What it does |
|--------|------|-------------|
| `semantic-server` | `cmd/semantic-server` | HTTP REST API for semantic extraction |
| `semantic-mcp` | `cmd/semantic-mcp` | MCP (Model Context Protocol) server for Claude Desktop |
| `stealth-mcp` | `cmd/stealth-mcp` | MCP server for stealth operations |
| `labd` | `cmd/labd` | Fingerprint capture lab daemon |

### Specialized tools

| Binary | File | What it does |
|--------|------|-------------|
| `crawl` | `cmd/crawl` | Standalone crawler (lighter than `stealth crawl`) |
| `semanticcrawl` | `cmd/semanticcrawl` | Crawl + extract semantic trees in one pass |
| `extract` | `cmd/extract` | Standalone content extractor |
| `train` | `cmd/train` | ML training data generation |
| `ml_datagen` | `cmd/ml_datagen` | Generate datasets for ML model training |
| `gencert` | `cmd/gencert` | TLS certificate generation for MITM proxy |
| `scanciphers` | `cmd/scanciphers` | TLS cipher suite scanner |

### Testing & benchmarking

| Binary | File | What it does |
|--------|------|-------------|
| `benchmark` | `cmd/benchmark` | Performance benchmarks |
| `evalbench` | `cmd/evalbench` | Evaluation benchmark suite |
| `vecbench` | `cmd/vecbench` | Vector embedding benchmarks |
| `test_realworld` | `cmd/test_realworld` | Real-world integration tests |
| `test_semantic` | `cmd/test_semantic` | Semantic extraction tests |

### Pipeline

| Binary | File | What it does |
|--------|------|-------------|
| `pipeline` | `cmd/pipeline` | Run processing pipelines |

---

## `python/*` — Python Wrappers

| Path | What it does |
|------|-------------|
| `python/pybrwslab/` | Python package wrapping all Go CLI binaries |
| `python/pybrwslab/_base.py` | Base `CLIWrapper` class (subprocess runner) |
| `python/pybrwslab/stealth.py` | Wraps `stealth` binary |
| `python/pybrwslab/semantic.py` | Wraps `semantic` binary |
| `python/pybrwslab/agent.py` | Wraps `agent` binary |
| `python/pybrwslab/brwslab.py` | Wraps `brwslab` binary |
| `python/pybrwslab/labd.py` | Wraps `labd` binary |
| `python/pybrwslab/__init__.py` | Package exports |
| `python/examples/` | Example scripts (Pydantic AI research agent) |
| `python/pyproject.toml` | Python package config |
| `python/README.md` | Python package docs |

**Why subprocess?** The Go binaries are compiled and fast. Python wraps them because:
1. No CGo complexity
2. Easy to install (`pip install pybrwslab`, just need binaries in PATH)
3. Process isolation — Go crashes don't kill Python
4. Language-agnostic — any language can call the CLI binaries

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
| `fingerprints/chrome-116-custom.json` | A captured Chrome 116 fingerprint (TLS, HTTP/2, headers) |

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

**Why so few?** Most examples are in the READMEs and docs. The Python examples (`python/examples/`) are more comprehensive.

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

## `training-data/` — Training Data

| Path | What it does |
|------|-------------|
| `training-data/session-001/` | Captured fingerprint session |
| `training-data/traces/` | Human interaction traces |

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
| **Research vs production** | `lab/`, `adversarial/`, `benchmark/` are research tools. `pipeline/`, `resilience/`, `observability/` are production tools. Both coexist. |

**The project looks big, but it's organized.** If you just want to scrape a page, you only touch 3–4 packages. If you want to research TLS fingerprints, you dive into `tlsfprint/` and `lab/`. If you want to build an AI agent, you use `agent/` and `semantic/`.
