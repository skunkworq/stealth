# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Module

`github.com/skunkworq/stealth` — Go 1.26, with a React frontend (`lab-ui/`) and a Rust FFI sniffer (`brws/network/sniff/rust/`).

## Commands

```bash
# Build all Go binaries (requires Rust sniffer first)
make build

# Run CI checks (build + lint + tests, no frontend)
make ci

# Run full validation suite (Go + frontend)
make test

# Run Go tests only
go test ./...
go test -short ./...                         # skip slow/network tests
go test -race -count=1 -timeout 120s ./...   # with race detector

# Run a single package
go test ./brws/stealth/ -v
go test ./brws/content/understand/ -v -run TestName

# Lint
make lint                  # Go + frontend
make lint-fix              # auto-fix where possible
golangci-lint run ./...    # Go only

# Format
make fmt                   # gofumpt via golangci-lint

# Build the fingerprint lab + start it
make run-lab               # HTTP only, foreground
make run-lab-https         # with TLS (generates certs if needed)
make run-proxy             # with MITM proxy
make run-chrome            # MITM proxy + auto-launch Chrome

# Build the agent server UI (Next.js → server/web/)
make agent-ui
make run-agent

# Frontend (lab-ui)
cd lab-ui && npm run build
cd lab-ui && npm test -- --run
cd lab-ui && npx tsc --noEmit

# Benchmarks
make bench
make bench-cpu    # with pprof CPU profile
```

Install `golangci-lint` if missing: `make install-lint`.

## Architecture

`brws/` is a four-layer library. **Nothing in a lower layer imports from a higher one.**

```
Layer 4 — Scale:     brws/crawl/   brws/fingerprint/
Layer 3 — Content:   brws/content/{agent,scrapegraph,understand,extract}
Layer 2 — Stealth:   brws/stealth/
Layer 1 — Engine:    brws/browser/   brws/network/
Cross-cutting:       brws/core/   brws/llm/
Out-of-band:         brws/research/
```

### Layer 1 — Engine (`brws/browser/engine`)

`engine.Engine` is the single interface all backends implement (`Do`, `Close`, `Capabilities`). Engines self-register by name; callers use `engine.New("chromium", opts)`.

Optional capability interfaces (checked at runtime): `InteractiveEngine`, `TabEngine`, `AllocatorEngine`, `TabCreator`, `ProfileNavigator`.

| Registered name | Package | Notes |
|---|---|---|
| `native` | `engine/http/native` | `net/http` + uTLS; no JS; fast |
| `http3` | `engine/http/http3` | QUIC/HTTP3 via quic-go |
| `chromium` | `engine/browser/browser/chromium` | CDP via chromedp; authentic TLS/HTTP2/HTTP3 |
| `chromium-stealth` | `stealth/chromium` | CDP + anti-detection JS injection + behavioral simulation; **default** |
| `firefox` / `webkit` | `engine/browser/browser/firefox`, `webkit` | Playwright |

`engine/meta/waterfall` races engines with timeout-based tier promotion. `browser/instancepool` pools browser processes for concurrent use.

### Layer 2 — Stealth (`brws/stealth`)

`stealth.Adaptive` is the main library entry point. It wraps any `engine.Engine` (or a waterfall of them) and adds:

- **Challenge solving** (`stealth/challenge`): Cloudflare JS/Turnstile/Managed, DataDome, reCAPTCHA. FSM at `challenge/fsm` governs passive→active→solve→escalate transitions. Cloudflare-specific handlers live in `challenge/cloudflare`.
- **Behavioral simulation** (`stealth/behavior`): Bézier mouse curves, keystroke timing, scroll jitter.
- **CAPTCHA** (`stealth/captcha`): ML-based solver + vision LLM solver + external service integration (CapSolver via `captcha/external_service`).
- **Script spoofing** (`stealth/script/spoof`): JS payload injection for navigator/canvas/WebGL spoofing.
- **Solver registry** (`stealth/solver`): Adapters that bridge `challenge/fsm.ChallengeSolver` to external services (e.g. CapSolver).
- **Profile/session** (`stealth/profile/session`): Persistent browser profiles and session storage.
- **Escalation** (`escalation.go`): on 401/403/429, promotes proxy tier and waterfall tier.
- **RL policy** (`policy.go`): `ApplyAction` mutates `engine.StealthConfig` (toggles CanvasNoise, WebGLSpoof, etc.).

Key note: **`CanvasNoise` defaults to false** — ANGLE GPU produces natural fingerprints; enabling noise adds detectable entropy.

### Layer 3 — Content (`brws/content`)

Four independent packages; each can be used without the others.

| Package | Role |
|---|---|
| `agent` | Goal-directed CDP agent. Observe→Decide→Execute loop. Exposes both DOM and semantic action spaces to the LLM `decideFn`. |
| `understand` | HTML → `SemanticTree`. Pipeline: Parse→Clean→Compress→Annotate→Index. 30–60% token reduction. Also handles form extraction, visual grounding, and embedding/vector index (`understand/index` — HNSW). |
| `scrapegraph` | DAG execution for LLM tasks. Key types: `SmartScraperGraph`, `SearchGraph`, `GenerateAnswerNode`. `scrapegraph.LLM` is a type alias of `llm/completions.LLM`; `NewLLMFromEnv()` reads `OPENROUTER_API_KEY`. |
| `extract` | Bare HTML→text stripping. No structure. |

### Layer 4 — Scale

| Package | Role |
|---|---|
| `crawl/spider` | Scrapy-style scheduler→downloader→spider→pipeline with middleware stacks |
| `crawl/integration` | `AdaptiveCrawler`, `SmartNavigator`, `FormFiller`, `ChangeDetector` — operates on semantic trees, requires a live browser |
| `crawl/ingest` | Integrated crawler pipeline with distributed tracing and Prometheus metrics; orchestrates URL→semantic extraction→vector indexing |
| `fingerprint/tls` | TLS fingerprint capture, JA3/JA4, uTLS spoof; Rust parser under `tls/rust` |
| `fingerprint/http` | HTTP/2 fingerprint capture and browser profile diffing (`http/browser`, `http/diff`) |

### Cross-cutting (`brws/core`, `brws/llm`)

`core/instrumentation` is the active logging/FSM layer — all packages that log import this, not `log` directly. `core/resilience` provides retry + circuit breaker. `core/events` carries ban/challenge signals across layer boundaries (replaces the removed `core/signals`). Other subpackages: `core/detection` (bot-detection vector analysis), `core/observability` (health checks, metrics HTTP handler), `core/telemetry` (OpenTelemetry), `core/trust` (proxy/identity trust scoring), `core/config`, `core/constants`, `core/types`.

`brws/llm/` is the shared LLM abstraction used by both Layer 2 (vision CAPTCHA solver) and Layer 3 (scrapegraph, agent). It provides:
- `llm/completions` — `LLM` interface + OpenAI and Anthropic implementations
- `llm/embed` — `Embedder` interface for vector embedding

### `server/` — Agent Server

WebSocket hub + REST API for the browser agent UI. `server/ui/` is the Next.js frontend (built to `server/web/`, embedded in the binary). Entry point: `cmd/scrape/agent/server`.

### `brws/research/` — Research & Experimentation

Out-of-band packages used for data collection, model training, and offline analysis. Nothing in the production layers imports from here.

| Package | Role |
|---|---|
| `research/evasion/cloudflare` | Local Cloudflare emulator (formerly `brws/adversarial`). Emulates JS/Managed/Turnstile challenges, `__cf_bm` cookies, `cf_clearance` tokens, rate limiting (429), and solve-time bounds. Mount via `cc.MountRoutes(mux)` in tests. |
| `research/evasion/recaptcha` | reCAPTCHA evasion research server |
| `research/detection/` | Detection analysis: `analyzers`, `scoring`, and a trace lab (`tracing`) for recording and replaying bot-detection signals |
| `research/fingerprint/capture` | Live fingerprint capture harness (export via `capture/export`) |
| `research/fingerprint/training` | Training data generation for TLS/HTTP fingerprint models |
| `research/captcha/ml` | Vision LLM CAPTCHA solver experiments |
| `research/captcha/training` | CAPTCHA training data collection |
| `research/rl/adaptive` | Per-domain strategy storage and RL-based performance tracking (production scheduling via `brws/ml`) |
| `research/bench/fingerprint` | Fingerprint detection benchmarks and blackbox probing |
| `research/bench/understand` | SemanticTree compression benchmarks |

## Environment Variables

| Variable | Purpose |
|---|---|
| `OPENROUTER_API_KEY` | LLM for `content/scrapegraph` and semantic compression |
| `BRWSLAB_SESSIONS_DIR` | Session storage (default `~/.brwslab/sessions`) |
| `CHROME_PATH` / `CHROMIUM_PATH` | Browser executable (auto-detected if unset) |

## Session Completion (AGENTS.md)

When ending a work session, ALL changes must be committed and pushed (`git pull --rebase && git push`). Work is not complete until `git status` shows "up to date with origin".
