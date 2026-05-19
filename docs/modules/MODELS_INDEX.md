# Project Models — Documentation Index

> Complete documentation for every major module in the Stealth scraping framework.

---

## Quick Navigation

| Model | File | Purpose |
|---|---|---|
| **Stealth** | [`MODEL_STEALTH.md`](MODEL_STEALTH.md) | Bot detection evasion, CAPTCHA solving, Cloudflare bypass, behavioral mimicry |
| **Fingerprint** | [`MODEL_FINGERPRINT.md`](MODEL_FINGERPRINT.md) | TLS/HTTP fingerprint capture, JA3/JA4 analysis, uTLS spoofing |
| **Browser** | [`MODEL_BROWSER.md`](MODEL_BROWSER.md) | Browser automation engine (Chromium, Firefox, WebKit) with stealth patches |
| **Network** | [`MODEL_NETWORK.md`](MODEL_NETWORK.md) | MITM proxy, certificate management, proxy rotation, tier escalation |
| **Content** | [`MODEL_CONTENT.md`](MODEL_CONTENT.md) | CDP agent, semantic pipeline, agentic graph scraping, crawl spider |
| **ML & Core** | [`MODEL_ML.md`](MODEL_ML.md) | RL models, shield/sword training, types, config, telemetry, resilience |
| **Research** | [`MODEL_RESEARCH.md`](MODEL_RESEARCH.md) | Offline benchmarks, challenge emulators, fingerprint capture lab, training data pipeline, RL strategy storage |

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              User Interface                                  │
│                         (CLI / API / Lab UI)                                 │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │
┌─────────────────────────────────────▼───────────────────────────────────────┐
│                            Content Extraction                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │    Agent    │  │   Semantic  │  │   Agentic   │  │       Crawl         │ │
│  │  (CDP)      │  │  (LLM)      │  │  (Graph)    │  │     (Spider)        │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │
┌─────────────────────────────────────▼───────────────────────────────────────┐
│                           Browser Automation                                 │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  Engine Interface: native │ chromium │ chromium-stealth │ firefox │ webkit │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │
┌─────────────────────────────────────▼───────────────────────────────────────┐
│                           Stealth / Evasion                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │  Challenge  │  │  Behavior   │  │   Client    │  │      Policy         │ │
│  │  Solving    │  │  Evasion    │  │   Engine    │  │      Engine         │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │
┌─────────────────────────────────────▼───────────────────────────────────────┐
│                           Fingerprint Layer                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Capture   │  │   Parser    │  │   Spoofer   │  │   Training Data     │ │
│  │   (Lab)     │  │ (JA3/JA4)   │  │  (uTLS)     │  │     Generation      │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │
┌─────────────────────────────────────▼───────────────────────────────────────┐
│                           Network Layer                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │  MITM Proxy │  │ Proxy Pool  │  │    Tier     │  │  Packet Sniffer     │ │
│  │  (Capture)  │  │  (Rotation) │  │ Escalation  │  │  (libpcap/Rust)     │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
┌─────────────────────────────────────▼───────────────────────────────────────┐
│                         ML & Core Infrastructure                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │  RL Models  │  │    Types    │  │ Observability│  │    Resilience       │ │
│  │  (PyTorch)  │  │   Config    │  │   Metrics    │  │  Circuit Breaker    │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Module Interactions

### Happy Path: Single Page Scrape

1. **Content** receives user prompt + URL
2. **Browser** launches stealth Chromium with fingerprint binding
3. **Network** routes through proxy pool (tier 0 → datacenter)
4. **Stealth** applies JS patches and human-like behavior
5. **Fingerprint** spoofs TLS ClientHello to match target browser
6. **Browser** loads page; **Stealth** detects no challenge
7. **Content** extracts data via agentic graph or semantic pipeline
8. **ML** records success for adaptive fingerprint selection

### Challenge Path: Cloudflare Turnstile

1. **Browser** loads page; **Stealth** detects Cloudflare challenge
2. **Stealth** escalates to level 4 (CAPTCHA solving)
3. **Stealth** classifies challenge type (`challenge_classifier.go`)
4. **Stealth** selects appropriate solver (`cloudflare_solver.go`)
5. **Browser** executes challenge solution via CDP
6. **Stealth** verifies solution; retries on failure
7. **Network** may escalate proxy tier if IP is blocked
8. **Content** extracts data after challenge clearance

### Research Path: Multi-URL Search

1. **Content** (Agentic) `SearchGraph` generates search query via LLM
2. **Content** scrapes DuckDuckGo results
3. **Content** `GraphIteratorNode` launches parallel `SmartScraperGraph` per URL
4. **Browser** pool reuses instances across scrapes
5. **Network** rotates proxies per request
6. **Content** `MergeAnswersNode` synthesizes final answer

---

## Data Flow

### Fingerprint Capture → Spoofing Loop

```
Real Browser → MITM Proxy → TLS Parser → CompleteFingerprint
                                                  │
                    ┌─────────────────────────────┘
                    ▼
            Fingerprint Database
                    │
                    ▼
            Feature Extractor → ML Model → AdaptiveSpoofer
                    │
                    ▼
            uTLS ClientHelloID → Spoofed Request
```

### Training Data Loop

```
Stealth Client → Attempt Request → Detection Outcome
        │                                    │
        ▼                                    ▼
   datagen.Collector  ←──────────────  Bot Score / Reward
        │
        ▼
   SQLite Database
        │
        ▼
   Python Training Scripts
        │
        ▼
   Updated Policy Models (.pt files)
        │
        ▼
   Policy Loader (Go) → Improved Evasion
```

---

## Technology Stack

| Layer | Technologies |
|---|---|
| Language | Go 1.26, Python 3, Rust |
| Browser | chromedp (CDP), Playwright |
| TLS | uTLS, custom parser, Rust FFI |
| ML | PyTorch, SQLite |
| Network | net/http, quic-go, libpcap (Rust) |
| Observability | OpenTelemetry, Prometheus |
| Storage | SQLite, JSON |

---

## Key Design Principles

1. **Independence**: Each module can operate standalone (`agentic/` has zero imports into `agent/`)
2. **Composability**: Engines, nodes, and strategies are swappable via interfaces
3. **Observability**: Every layer emits metrics, traces, and structured logs
4. **Resilience**: Circuit breakers, retry logic, and proxy tier escalation handle failures gracefully
5. **Adaptivity**: ML models continuously improve fingerprint selection and behavior based on outcomes

---

*Generated from source code analysis.*
