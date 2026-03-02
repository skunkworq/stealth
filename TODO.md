# Stealth Platform - Feature Parity TODO

Based on analysis of Scrapy and Scrapling frameworks.

## Priority 0 - Core Framework

### P0.1 Spider Framework
- [x] `brws/spider/spider.go` - Base Spider with callbacks
- [x] `brws/spider/scheduler.go` - Priority queue with disk persistence
- [x] `brws/spider/settings.go` - Settings interface with defaults
- [x] `brws/spider/crawler.go` - Crawler implementation
- [x] `brws/spider/middleware.go` - Middleware chain
- [x] `brws/spider/pipeline.go` - Item pipelines + stats
- [x] `brws/engine/response_types.go` - HtmlResponse with CSS/XPath

### P0.2 Item Pipeline
- [x] `brws/spider/pipeline.go` - Pipeline manager in spider package

---

## Priority 1 - Essential Components

### P1.1 Link Extraction
- [x] `brws/extractors/links.go` - LinkExtractor with CSS/XPath
- [x] `brws/extractors/sitemap.go` - Sitemap parsing

### P1.2 Middleware System
- [x] `brws/spider/middleware.go` - Built-in middlewares (Retry, UserAgent, Redirect)

### P1.3 Settings System
- [x] `brws/spider/settings.go` - Priority-based settings with 40+ defaults

### P1.4 Request/Response Objects
- [x] `brws/engine/request_advanced.go` - FormRequest, JsonRequest
- [x] `brws/engine/response_types.go` - TextResponse, HtmlResponse

---

## Priority 2 - CLI & UX

### P2.1 Signals
- [x] `brws/signals/manager.go` - Event emitter system
- [x] `brws/signals/types.go` - Signal types

### P2.2 Commands
- [x] `cmd/stealth/main.go` - Main CLI with crawl, list, shell commands

### P2.3 Data Export
- [x] `brws/export/exporter.go` - Exporter interface
- [x] `brws/export/json.go` - JSON exporter
- [x] `brws/export/csv.go` - CSV exporter

---

## Priority 3 - Advanced Features

### P3.1 Duplicate Filtering
- [x] `brws/spider/scheduler.go` - Built into scheduler

### P3.2 Extension System
- [x] `brws/extension/manager.go` - Extension loader

### P3.3 Adaptive Parsing (Scrapling Feature)
- [x] `brws/adaptive/tracker.go` - Element property tracking
- [x] `brws/adaptive/storage.go` - SQLite persistence

---

## Priority 4 - Nice to Have

### P4.1 No-Code Extraction
- [ ] `cmd/extract/main.go` - CLI extraction tool

### P4.2 Stealth Enhancements (Completed in Session 8)
- [x] SegmentationSolver as primary solver in SolveFromResponse (dynamic num_chars)
- [x] reCAPTCHA v2 dispatch from client.Navigate
- [x] Connected-component segmentation fallback for overlapping characters
- [x] Expanded WebGL mock (25+ extensions, GL parameters, getExtension stubs)
- [x] Configurable devicePixelRatio (no longer hardcoded to 1)
- [x] Plugin list expanded to 5 entries (matches real Chrome)
- [x] AudioContext mock (sampleRate, baseLatency, outputLatency)
- [x] Keystrokes match solution characters (HumanEventOpts)

### P4.3 Stealth Enhancements
- [ ] Cloudflare/antibot bypass integration
- [x] Canvas fingerprint format (data URL)
- [ ] WebRTC leak prevention
- [ ] Enhanced headless detection patches

#### Shield Detection Vectors

| # | Vector | Shield Check | Weight | Sword Fix | Status |
|---|--------|-------------|--------|-----------|--------|
| 1 | Screen/Nav resolution mismatch | `screen_nav_outer_width_mismatch` (>5px diff) | 0.70 | Shared resolution + scrollbar in `GenerateHeaders()` | Fixed |
| 2 | GPU keywords in masked WebGL vendor | `gpu_keywords_in_masked_vendor` (parenthetical/GPU names) | 0.50 | Split `WebGLVendor` (clean) vs `WebGLUnmaskedVendor` (GPU detail) | Fixed |
| 3 | Non-quantized RTT | `non_quantized_rtt` (not multiple of 25ms) | 0.30 | Pick from `{25,50,75,100,125,150,175,200}` | Fixed |
| 4 | Bare hex canvas hash | `synthetic_canvas_hash_format` (32-128 hex chars) | 0.50 | Format as `data:image/png;base64,...` | Fixed |
| 5 | Missing navigator.languages | `missing_navigator_languages` | 0.50 | Add `Languages` field to `BrowserProfile`, emit in navigator | Fixed |
| 6 | Color depth cross-header mismatch | `screen_nav_color_depth_mismatch` (screen vs nav) | 0.65 | Shared `colorDepth` in `sharedDimensions` struct | Fixed |
| 7 | Canvas payload too short | `canvas_payload_too_short` (<200 base64 chars) | 0.50 | Generate ~8KB pseudo-random bytes (~11000 base64 chars) | Fixed |
| 8 | Missing navigator.productSub | `missing_navigator_productSub` | 0.30 | Add `ProductSub` to `BrowserProfile` (Chrome: "20030107", Firefox: "20100101") | Fixed |
| 9 | Missing navigator.maxTouchPoints | `missing_navigator_maxTouchPoints` | 0.20 | Emit `maxTouchPoints: 0` in navigator data | Fixed |
| 10 | Missing WebGL shading_version | `missing_shading_version` | 0.40 | Add `WebGLShadingVersion` to profile ("WebGL GLSL ES 3.00") | Fixed |
| 11 | Canvas PNG magic header | `canvas_png_magic_header` (base64 doesn't start with "iVBOR") | 0.55 | Prefix canvas bytes with PNG signature + IHDR chunk header | Fixed |
| 12 | Navigator appVersion consistency | `missing_app_version` / `inconsistent_app_version` | 0.45/0.40 | Emit `appVersion = UA[len("Mozilla/"):]` in navigator data | Fixed |
| 13 | WebGL missing max_texture_size | `missing_max_texture_size` (value is 0) | 0.35 | Add `WebGLMaxTextureSize` to profile (16384), emit in WebGL data | Fixed |
| 14 | Connection missing effectiveType | `missing_connection_effective_type` | 0.30 | Add `"effectiveType": "4g"` to connection map in navigator | Fixed |
| 15 | Timing entry count too low | `too_few_timing_entries` (<10 entries) | 0.30 | Expand from 5 to 18 entries (HTML→CSS×3→JS×4→Image×5→Font×3→JSON×2) | Fixed |
| 16 | WebGL extensions missing | `missing_webgl_extensions` (nil/empty/few) | 0.40 | Add 20-30 platform-specific extensions per profile (ANGLE/Apple/Mesa/MOZ) | Fixed |
| 17 | AudioContext missing | `missing_audio_data` / `invalid_audio_sample_rate` / `audio_base_latency_out_of_range` / `audio_channel_count_anomaly` | 0.45 | New `generateAudio()` method with profile-specific sample rates (48kHz/44.1kHz) | Fixed |
| 18 | Canvas IDAT chunk structure | `canvas_missing_idat_chunk` (bytes 37-40 ≠ "IDAT") | 0.40 | Proper PNG: signature(8) + IHDR(25) + IDAT(~8KB) + IEND(12) | Fixed |
| 19 | RTT/Downlink anticorrelation | `rtt_downlink_anticorrelated` (low latency + low bandwidth or vice versa) | 0.35 | Correlated selection: rtt≤50→dl 5-10, rtt≤100→dl 3-8, rtt>100→dl 1.5-6 | Fixed |
| 20 | Behavioral scroll events missing | `missing_scroll_events` (no scrolls despite mouse+typing) | 0.30 | New `generateScrollEvents()`: 3-10 events, 80-400ms intervals, deceleration | Fixed |
| 21 | Sec-Ch-Ua / UA version mismatch | `sec_ch_ua_version_mismatch` (Chrome major differs) | 0.40 | Profiles already use consistent versions; BrokenGenerator tests mismatch | Fixed |

---

## Priority 5 — Advanced Sword & ML

### P5.1 ML-Based Captcha Solver (CNN)
- [ ] Train a CNN on synthetic captcha data generated by `captcha.Generator`
- [ ] Character-level classification with 10k+ images per difficulty level
- [ ] Use the generator to create infinite labeled training data (all difficulty levels: easy/medium/hard/extreme)
- [ ] Target: >95% accuracy on medium difficulty, >80% on hard
- [ ] Integration: replace SegmentationSolver as primary when model is available

### P5.2 Sequence-to-Sequence Attention Model
- [ ] End-to-end captcha solving without explicit segmentation
- [ ] Encoder-decoder with spatial attention learns character boundaries automatically
- [ ] Handles variable-length captchas without knowing num_chars in advance
- [ ] Train on synthetic data from `captcha.Generator` with rotation/overlap augmentation

### P5.3 Contrastive Learning Fix
- [ ] Fix broken `ContrastiveSolver` in `brws/adversarial/captcha/solver.go`
- [ ] Proper Gaussian RNG (replace uniform with Box-Muller)
- [ ] NT-Xent loss with negative sampling (temperature-scaled cosine similarity)
- [ ] Working backprop + optimizer step (gradient descent on embedding space)
- [ ] Save/Load persistence for trained embeddings

### P5.4 Residential Proxy Rotation
- [ ] IP vector currently flags datacenter ranges
- [ ] Integrate residential proxy pool for IP diversity
- [ ] Rotation strategy: new IP per session, sticky sessions for multi-request flows
- [ ] Geo-targeting to match timezone/locale headers

### P5.5 Behavioral Feedback Loop
- [ ] Wire `BehavioralTracker` recordings from real navigation back into `GenerateHumanEvents`
- [ ] Collect mouse/keyboard/scroll distributions from real browsing sessions
- [ ] Use recorded distributions to parameterize log-normal intervals
- [ ] Continuously improve realism based on shield feedback (pass/fail signals)

### P5.6 Font Enumeration Injection
- [ ] Canvas-based font detection to report realistic font lists
- [ ] Inject via `X-Font-Data` header or JavaScript `document.fonts` API mock
- [ ] Platform-specific font lists (Windows vs macOS vs Linux)
- [ ] Match font list to reported platform in navigator

### P5.7 RL Policy for Captcha Strategy
- [ ] Extend the DQN action space to include captcha-specific decisions
- [ ] Actions: solver choice (segmentation vs template vs ML), retry strategy, behavioral intensity
- [ ] State: captcha type, difficulty estimate, previous attempt results, shield response codes
- [ ] Reward: successful solve = +1, failed solve = -0.5, detection = -1

---

## Semantic Pipeline - Completed 2026-03-02

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     APPLICATION LAYER                        │
│   cmd/pipeline │ cmd/semantic-mcp │ cmd/test_semantic       │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                     PIPELINE LAYER                           │
│                  brws/pipeline/                              │
│                                                              │
│   Pipeline.ProcessURL ─▶ fetch → extract → embed            │
│   Pipeline.ProcessBatch (concurrent)                        │
│                                                              │
│   + Tracing (TraceID, SpanID, hierarchical spans)           │
│   + Metrics Server (/metrics, /health, /stats)              │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                     SEMANTIC LAYER                           │
│                  brws/semantic/                              │
│                                                              │
│   pipeline.go - DOM chunking + LLM compression              │
│   cache.go - SQLite content-hash cache                      │
│   forms.go - Form schema extraction                         │
│   diff.go - Incremental updates                             │
│   vision_grounding.go - Bounding boxes                      │
│   index/hnsw.go - Vector similarity search                  │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                   OBSERVABILITY LAYER                        │
│                  brws/observability/                         │
│                                                              │
│   InMemoryCollector - Counters, Gauges, Histograms          │
│   Timer helpers for duration tracking                       │
└─────────────────────────────────────────────────────────────┘
```

### Key Files Created

| Package | File | Purpose |
|---------|------|---------|
| pipeline | `tracing.go` | Distributed tracing |
| pipeline | `pipeline.go` | 3-stage processing |
| pipeline | `metrics_server.go` | HTTP endpoints |
| semantic | `diff.go` | Tree diffing |
| semantic | `forms.go` | Form extraction |
| semantic | `vision_grounding.go` | Bounding boxes |
| cmd | `pipeline/main.go` | CLI tool |
| cmd | `semantic-mcp/main.go` | MCP server |

### Performance Results

| Site | HTML | Duration | Tokens | Compressed |
|------|------|----------|--------|------------|
| GitHub | 561KB | 40s | 4,862 → 18 | 99.6% |
| Hacker News | 34KB | 59s | 5,436 → 8 | 99.9% |
| httpbin | 3.8KB | 1.1s | 953 → 55 | 94.2% |

### Commits

- `e321b23` - feat(brws/pipeline): add integrated crawler pipeline with tracing
- `861a027` - docs: add semantic extraction cost analysis
- `d507601` - perf(brws/semantic): optimize for large pages
- `d6f2f6b` - feat(cmd/semantic-mcp): add MCP server
- `644ceed` - test(brws/semantic): add comprehensive tests for diff.go
- `5fd14a0` - feat(brws/semantic): add visual grounding and incremental diff
- `5704b62` - feat(brws/semantic): add form schema extraction

