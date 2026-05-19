# Module: Research

> **Purpose:** Offline experimentation, data collection, and analysis tools. Nothing in this module is imported by the production layers — it exists to feed the training pipeline, benchmark engines, and prototype new evasion techniques before they graduate to `brws/stealth/`.

---

## Submodule Map

```
brws/research/
├── bench/
│   ├── fingerprint/   — Engine & detection benchmarks against live/mock endpoints
│   └── understand/    — SemanticTree pipeline performance benchmarks
├── captcha/
│   ├── ml/            — Neural network + vision-LLM CAPTCHA solver prototypes
│   └── training/      — Type re-exports; trace data in training/traces/
├── detection/
│   └── tracing/       — Request tracing, solve metrics, bot-detection lab server
├── evasion/
│   ├── cloudflare/    — Local Cloudflare challenge emulator (JS, Turnstile, Managed)
│   └── recaptcha/     — Local reCAPTCHA v2/v3 challenge emulator
├── fingerprint/
│   ├── capture/       — Full fingerprint capture lab server + REST API (needs libpcap)
│   └── training/      — SQLite-backed episode collector + JSON/CSV export
└── rl/
    └── adaptive/      — RL strategy storage and DOM element tracker
```

---

## `bench/fingerprint` — Engine & Detection Benchmarks

**Goal:** Measure how well each engine avoids detection across a range of protected endpoints, and track performance regressions over time.

| File | What it does |
|------|-------------|
| `suite.go` | Master benchmark suite; configures which engines and endpoint tiers to test |
| `runner.go` | Executes a suite with optional CPU/memory pprof profiling |
| `endpoints.go` | Catalogue of endpoint types by protection level (Cloudflare, Incapsula, Akamai, none) |
| `capabilities.go` | Tests each engine for JS execution, HTTP/2 support, and headless-signal leakage |
| `fingerprint.go` | Verifies TLS and HTTP/2 signature consistency across repeated requests |
| `shield.go` | Measures bot-detection scores for each engine/config combination |
| `blackbox.go` | Black-box framework for running third-party scraping tools and scoring results |
| `tool_comparison.go` | Compares internal engines against external tools (curl-impersonate, playwright, etc.) |
| `benchmark_test.go` | Micro-benchmarks for spoof engine hot paths |
| `blackbox_test.go` | Unit tests for tool filtering and execution helpers |
| `suite_test.go` | Integration harness for the full benchmark suite |
| `tool_comparison_test.go` | Unit tests for comparison scoring and ranking logic |

---

## `bench/understand` — SemanticTree Benchmarks

**Goal:** Measure token reduction, latency, and accuracy of the content understanding pipeline across page types.

| File | What it does |
|------|-------------|
| `benchmark.go` | Benchmarks the full parse→clean→compress→annotate pipeline; reports token counts and LLM/embedding latency |
| `benchmark_test.go` | Integration tests that run the benchmark suite against fixture HTML |

---

## `captcha/ml` — CAPTCHA Solver Prototypes

**Goal:** Research and prototype CAPTCHA solvers — both a CNN-based image classifier and a vision-LLM approach — before promoting winners to `brws/stealth/captcha/`.

| File | What it does |
|------|-------------|
| `model.go` | Convolutional neural network for CAPTCHA image classification (Conv2D + pooling layers) |
| `trainer.go` | Training loop with learning rate scheduling, early stopping, and checkpoint saving |
| `vision_solver.go` | Stateless vision-LLM solver — wraps `brws/llm` to ask a multimodal model to interpret CAPTCHA images |
| `model_forward_test.go` | Unit tests for Conv2D forward-pass correctness |

---

## `captcha/training` — CAPTCHA Training Types

**Goal:** Shared type definitions for CAPTCHA training data so the capture server and the training pipeline agree on schema.

| File | What it does |
|------|-------------|
| `captcha_training.go` | Type aliases re-exporting canonical CAPTCHA training structs from `brws/stealth/captcha` |

Training data (Turnstile session recordings) lives in `traces/` alongside this package.

---

## `detection/tracing` — Bot-Detection Trace Lab

**Goal:** Record detailed request traces during live challenge interactions to understand exactly which signals bot detectors examine, and replay those traces to validate solver accuracy.

| File | What it does |
|------|-------------|
| `tracing_detector.go` | Extended detection analysis — augments standard bot-score checks with per-request TLS, HTTP, and behavioral signal breakdown |
| `detailed_trace.go` | Captures a full request trace: HTTP headers, TLS fingerprint, timing, and behavioral characteristics |
| `trace_lab_handler.go` | HTTP server that serves interactive challenge pages and records human-interaction traces |
| `trace_library.go` | Type alias for `TraceLibrary` from `stealth/challenge`; manages the stored trace corpus |
| `trace_recorder.go` | Type alias for `TraceRecorder` from `stealth/challenge`; writes new traces to the library |
| `solve_metrics.go` | Aggregates CAPTCHA solve attempt statistics (success rate, duration) by challenge type and variant |
| `solve_metrics_test.go` | Unit tests for metrics aggregation and reporting |
| `trace_library_test.go` | Unit tests for trace CRUD and filtering |
| `trace_recorder_test.go` | Test stubs for recorder behaviour |
| `trace_solve_test.go` | Test stubs for trace-replay solve validation |
| `tracing_test.go` | Integration tests for the full tracing detector against a live stealth browser |

---

## `evasion/cloudflare` — Cloudflare Challenge Emulator

**Goal:** Run Cloudflare challenges locally so the solver can be developed and tested without hitting production. Supports JS challenge, Managed challenge, and Turnstile; enforces realistic timing constraints (rejects solves < 1.5 s).

| File | What it does |
|------|-------------|
| `server.go` | Core test server — handles TLS, records detection events, issues `__cf_bm` cookies and `cf_clearance` tokens |
| `advanced_stealth_server.go` | Extended server that integrates the full stealth detection pipeline alongside challenge serving |
| `lab_cloudflare.go` | Challenge type definitions and simulation models (JS, Managed, Turnstile variants) |
| `captcha_shield.go` | CAPTCHA challenge management — presents challenges, validates solves, scores bot signals |
| `turnstile_lab.go` | Type aliases for Turnstile token TTL and interaction types from `stealth/challenge` |
| `turnstile_visual.go` | Proof validation for visual Turnstile interactions (rotate, drag, precision) |
| `turnstile_evaluation.go` | Wraps `CloudflareChallenger` with local test case definitions for evaluation runs |
| `v3_assess.go` | reCAPTCHA v3 invisible risk-score handler embedded in the Cloudflare lab |

---

## `evasion/recaptcha` — reCAPTCHA v2/v3 Challenge Emulator

**Goal:** Serve local reCAPTCHA v2 and v3 challenges to test the solver against both the visible checkbox/image flow and the invisible behavioral-score flow.

| File | What it does |
|------|-------------|
| `recaptcha_widget.go` | Server-side v2 widget flow — checkbox → image challenge → token issuance |
| `lab_recaptcha.go` | v2 challenge definitions and heuristic signal models |
| `recaptcha_v3.go` | v3 invisible challenge — behavioral analysis and detection vector scoring |

---

## `fingerprint/capture` — Fingerprint Capture Lab

**Goal:** Run a full capture lab server that launches real browsers, records multi-layer fingerprints (TLS, HTTP/2, JS navigator), and exposes them via API for training-data generation and stealth validation.

| File | What it does |
|------|-------------|
| `capture.go` | Core capture logic — drives a browser, intercepts TLS and HTTP/2 frames, extracts JS fingerprint |
| `enhanced_server.go` | Full-featured lab HTTP server wiring together fingerprint, CAPTCHA, and proxy endpoints |
| `browser_control.go` | Chrome process lifecycle — launch, attach, teardown |
| `raw_capture.go` | Low-level TLS handshake capture via listener interception (no browser needed) |
| `fingerprint_api.go` | REST endpoints for fingerprint submission, comparison, and diff analysis |
| `fingerprint_discovery.go` | Automated multi-profile fingerprint discovery — iterates engine configs and records results |
| `captcha_api.go` | REST endpoints that serve CAPTCHA challenges for manual and automated labelling |
| `training_api.go` | Endpoint for manual CAPTCHA solve submissions, feeding the training dataset |
| `shield_api.go` | Shield evaluation endpoint — returns bot scores and detection breakdowns for a given request |
| `ml_api.go` | ML evaluation response types and API handler |
| `ml_evaluate_fast.go` | Fast synthetic detection evaluation — no browser launch; replays a fingerprint through the detection pipeline |
| `recaptcha_v3_api.go` | reCAPTCHA v3 assessment endpoint embedded in the lab server |
| `tls_capture.go` | TLS fingerprint storage and retrieval (database-backed) |
| `tls_parser.go` | Type aliases for `ClientHello` parser types from `fingerprint/tls/parser` |
| `trainer.go` | Automated training harness — launches Chrome, navigates a URL list, captures and stores fingerprints |
| `export/exporter.go` | JSON and CSV export interface + implementation for fingerprint datasets |
| `cloudflare_routes_test.go` | Integration test for Cloudflare callback route handling |
| `ml_trace_test.go` | Integration tests for ML-assisted evasion trace extraction |
| `sniffer_integration_test.go` | Integration tests for packet-capture via `network/sniff` |
| `test/headless_integration_test.go` | End-to-end headless browser integration test |

---

## `fingerprint/training` — Episode Collector & Export

**Goal:** Persist RL training episodes (stealth config → detection outcome → FSM state) to SQLite and export them as JSON Lines or CSV for offline model training.

| File | What it does |
|------|-------------|
| `schema.go` | Training data structs — `Episode`, `StealthSnapshot`, `DetectionOutcome`, `FSMStateSnapshot` |
| `collector.go` | SQLite-backed episode store — insert, query, and delete episodes |
| `export.go` | Exports episodes to JSON Lines or CSV with a manifest file |
| `collector_test.go` | Unit tests for collector CRUD operations |
| `integration_test.go` | End-to-end test: collect → export → verify manifest |

Captured fingerprint data lives in `session-001/` (TLS captures, header patterns, training report).

---

## `rl/adaptive` — RL Strategy Storage

**Goal:** Persist and retrieve per-domain evasion strategy decisions and their outcomes to back the reinforcement-learning training loop in `brws/ml`.

| File | What it does |
|------|-------------|
| `storage.go` | SQLite storage layer for RL state — records (domain, action, reward, next-state) tuples |
| `tracker.go` | DOM element profiler — tracks element stability and interaction history for adaptive selector choice |
