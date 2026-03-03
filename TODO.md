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
- [x] Cloudflare/antibot bypass integration (Phase 5-6: CF challenge reproduction + auto-solve)
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

## Cloudflare Shield/Sword — Completed Phases

### Phase 1-4: CF Challenge Reproduction + Solver (Complete)
- [x] `brws/adversarial/cloudflare.go` — DetectChallenge (JS/Managed/Turnstile/Blocked)
- [x] `brws/adversarial/cloudflare_challenge.go` — CloudflareChallenger with PoW, fingerprint, behavioral validation
- [x] `brws/adversarial/cloudflare_handler.go` — HTTP handlers (init, solve/js, solve/managed, solve/turnstile, verify)
- [x] `brws/stealth/cloudflare_solver.go` — SolveJSChallenge, SolveManagedChallenge, SolveTurnstile
- [x] uTLS + HTTP/2 integration confirmed 100% bypass on real CF sites

### Phase 5: Real-World Validation (Complete)
- [x] Tree traversal tests against real CF-protected URLs
- [x] Chrome browser integration for real-world testing

### Phase 6: Realistic Shield + Sword Auto-Solve Integration (Complete)
- [x] `Cf-Mitigated: challenge` header on challenge pages, removed on solve
- [x] `__cf_bm` cookie generation with session-bound values
- [x] `Cache-Control`, `X-Frame-Options` realistic headers
- [x] Session state machine: pending → in_progress → solved/escalated/failed
- [x] Solve time bounds: managed challenges reject < 1.5s (superhuman detection)
- [x] Challenge escalation: JS → Managed → Blocked
- [x] `HandleProtectedPage` middleware wrapping any handler with CF protection
- [x] `submitSolution()` in CloudflareSolverClient for auto-solve flow
- [x] CF detection + auto-solve wired into `client.Navigate()`
- [x] 15 integration tests all passing

---

## Phase 7 — Session Fingerprint Consistency (Tier 1 - Highest Impact) ✅ COMPLETE

The single biggest gap: every request generates fresh random hardware fingerprints. Fixed by binding fingerprints to sessions (shield) and pinning fingerprints per client instance (sword).

### P7.1 Shield: Session Fingerprint Binding
- [x] `brws/adversarial/cloudflare_challenge.go` — `BoundFingerprint` + `FingerprintDrift` fields on `CloudflareChallengeSession`
- [x] `ValidateFingerprint()` binds first-seen fingerprint, detects drift on subsequent calls
- [x] `fingerprintDrift()` scores 9 hardware dimensions (canvas, GPU, platform, cores, memory, screen, timezone, color depth)
- [x] `GetFingerprintDrift()` API for querying session drift score
- [x] Drift contributes to bot score with 0.5× weight

### P7.2 Sword: Session-Pinned Fingerprint
- [x] `brws/stealth/cloudflare_solver.go` — `pinnedFingerprint` + `pinnedProfile` fields on `CloudflareSolverClient`
- [x] `generateFingerprint()` returns cached fingerprint after first call (same pointer)
- [x] `ResetFingerprint()` clears pin for new session
- [x] All hardware params pinned: concurrency, memory, screen, GPU, canvas, timezone, colorDepth, platform

### P7.3 Tests
- [x] Shield test: same session, different fingerprints → flagged (platform drift, full hardware swap)
- [x] Shield test: same session, consistent fingerprints → zero drift
- [x] Sword test: pinned fingerprint returns same values across calls
- [x] Sword test: pinned fingerprint passes shield drift check with zero drift
- [x] Sword test: ResetFingerprint generates new fingerprint
- [x] 5 shield tests + 7 sword tests all passing

---

## Phase 8 — Fix Known Heuristic Bugs (Tier 1) ✅ COMPLETE

Concrete bugs that were trivially detectable. Each fix closes a detection vector.

### P8.1 Canvas PNG CRC Checksums
- [x] `brws/behavior/request_generator.go` — Computed CRC32 for IHDR and IDAT chunks using `hash/crc32`
- [x] Test: decoded PNG has non-zero CRC bytes

### P8.2 Timing baseURL Hardcoded to `example.com`
- [x] `brws/behavior/request_generator.go` — Added `targetURL` field + `SetTargetURL()`, `GenerateRequest()` sets it
- [x] Timing referrers now use actual target URL instead of example.com
- [x] Test: timing data references target URL when set

### P8.3 Timezone Hardcoded to EST in CF Solver
- [x] `brws/stealth/cloudflare_solver.go` — `timezoneToOffset()` maps 10 IANA timezones to UTC offsets
- [x] `generateFingerprint()` derives offset from profile's Timezone field
- [x] Test: 8 known timezones + unknown fallback

### P8.4 Firefox/Safari Profiles with Chrome Client Hints
- [x] `brws/engine/profiles/profiles.go` — Cleared `SecChUa*` + `SecFetch*` from Firefox and Safari profiles
- [x] Also fixed `GetFirefox120Mac()` (was already fixed) and Safari mobile

### P8.5 CF Solver Canvas Hash Pattern
- [x] `brws/stealth/cloudflare_solver.go` — Replaced `"canvas_%x"` with valid `data:image/png;base64,...` PNG
- [x] Test: canvas hash starts with `data:image/png;base64,` and decodes to valid PNG

---

## Phase 9 — HTTP/2 Deep Fingerprint Evasion (Tier 2) ✅ COMPLETE

### P9.1 Profile-Aware HTTP/2 Transport
- [x] `brws/engine/native/native.go` — Added `h2Profile` struct with Chrome/Firefox HTTP/2 settings
- [x] `uTLSRoundTripper` now selects h2Profile based on TLS fingerprint (Chrome vs Firefox)
- [x] `getH2Transport()` sets MaxHeaderListSize, MaxDecoderHeaderTableSize, MaxReadFrameSize per profile
- [x] Chrome: 262144/65536/16384, Firefox: 0/131072/16384
- [x] Note: INITIAL_WINDOW_SIZE (Chrome 6MB vs Go 4MB) cannot be overridden in `http2.Transport`; `CustomHTTP2Transport` provides full control

### P9.2 PRIORITY Frame Spoofing
- [x] `brws/engine/spoof/http2_custom.go` — Added PriorityWeight, PriorityExclusive, PriorityDependsOn, SendPriority fields
- [x] Chrome: weight=255, exclusive=true, depends on stream 0, embedded in HEADERS frame
- [x] Firefox: SendPriority=false (uses urgency-based RFC 9218 priority instead)

### P9.3 WINDOW_UPDATE Timing
- [x] Stream WINDOW_UPDATE deferred to after first DATA frame received (Chrome behavior)
- [x] Moved from SendRequest (pre-response) to readResponse (post-DATA)
- [x] readResponse enhanced: multi-frame body assembly, GOAWAY/SETTINGS/WindowUpdate handling

### P9 Tests
- [x] 11 tests in `brws/engine/spoof/http2_custom_test.go`
- [x] Chrome vs Firefox SETTINGS values, window sizes, pseudo-header order, PRIORITY config
- [x] Header encoding for both Chrome and Firefox profiles

---

## Phase 10 — Advanced Behavioral Vectors (Tier 2) ✅

### P10.1 Keystroke Hold Time + Digraph Timing ✅
- [x] Shield: `behavioral_analyzer.go` — Check #25: keystroke hold time CV (< 0.25 = uniform = bot)
- [x] Shield: Check #26: digraph timing anomaly — inter-key interval ratio CV (< 0.20 = no digraph effect)
- [x] Sword: `generator.go` — Multi-modal hold times: taps (60-120ms), space/mod (100-200ms), long hold (250-450ms)
- [x] Tests: 4 shield tests (uniform/natural hold times, uniform/natural digraph timing)

### P10.2 Scroll Direction + Momentum ✅
- [x] Shield: Check #30: `scroll_direction_monotonic` — all same direction with >5 events
- [x] Shield: Check #30: `scroll_direction_alternating` — perfect up-down alternation >85%
- [x] Shield: Check #31: `scroll_direction_change_abrupt` — all direction changes at high velocity
- [x] Sword: `generator.go` — Mixed up-scrolls (~20%), forced up-scroll with >5 events, reduced delta at direction changes
- [x] Tests: 4 shield tests (monotonic, alternating, natural, abrupt direction change), 1 sword direction test

### P10.3 Mouse Velocity Autocorrelation at Higher Lags ✅
- [x] Shield: Check #27: lag-2 autocorrelation anomaly (expect 0.15-0.60)
- [x] Shield: Check #28: lag-3 autocorrelation anomaly (expect 0.05-0.40)
- [x] Shield: `lagNAutocorrelation()` generalized method for arbitrary lag
- [x] Sword: Temporal velocity smoothing (55%/25%/13%/7% weights) + dual-pass 5-point Gaussian post-filter
- [x] Tests: 2 shield tests (random vs smooth velocity), 1 sword test (P10 evasion suite)

### P10.4 Fitts' Law Compliance ✅
- [x] Shield: Check #29: `fitts_law_violation` — Pearson r of ID vs movement time (expect 0.3-0.95, needs ≥3 pairs)
- [x] Shield: `pearsonCorrelation()` method for Fitts' law correlation
- [x] Sword: `generator.go` — Fitts' law-based click timing: MT = (300 + 200*log2(D/W+1)) * noise + jitter
- [x] Tests: 1 shield test (distance-independent timing), included in P10 evasion suite

---

## Phase 11 — JS API Surface Completeness (Tier 2) ✅

### P11.1 chrome.app / chrome.csi / chrome.runtime Shape ✅
- [x] Shield: Check `chrome.app` exists with `isInstalled`, `InstallState`, `RunningState` (stealth_detector.go)
- [x] Shield: Check `chrome.csi` exists (stealth_detector.go)
- [x] Shield: Check `chrome.runtime` shape (existing check, enhanced with P11 additions)
- [x] Sword: Inject chrome.app, chrome.csi, chrome.loadTimes stubs in generateNavigator() (request_generator.go)

### P11.2 Plugin MIME Types ✅
- [x] Shield: Validate `navigator.plugins[i].mimeTypes` array has correct entries (plugin_analyzer.go check 5)
- [x] Shield: Chrome PDF Viewer should have `application/pdf` MIME type
- [x] Sword: Include MIME type arrays in plugin generation (request_generator.go, profiles.go)

### P11.3 Screen.orientation API ✅
- [x] Shield: Check `screen.orientation.type` is valid orientation string (screen_analyzer.go checks 6-7)
- [x] Shield: Check orientation/geometry mismatch (landscape-primary but width < height)
- [x] Sword: Inject `screen.orientation` as landscape-primary angle 0 for desktops (request_generator.go)

### P11.4 Performance.memory API (Chrome-only) ✅
- [x] Shield: Check `performance.memory` exists for Chrome UA (stealth_detector.go)
- [x] Shield: Validate `usedJSHeapSize` <= `totalJSHeapSize` <= `jsHeapSizeLimit`
- [x] Sword: Inject plausible memory values (limit: ~4GB, total: 20-80MB, used: 30-80% of total)

---

## Phase 12 — Cloudflare Shield Hardening (Tier 2) ✅

### P12.1 Challenge Page JavaScript Complexity ✅
- [x] Enhanced challenge page HTML with realistic CSS, meta tags (`noindex,nofollow`), spinner
- [x] Inline fingerprint collection JS (navigator, screen, WebGL, timezone, hardwareConcurrency)
- [x] XHR callback to `/cdn-cgi/challenge-platform/h/g/cv/result/{rayID}` during solve
- [x] `HandleChallengeCallback` endpoint accepts fingerprint/timing reports
- [x] `HandleManagedJS` serves stub `managed.js` script referencing `_cf_chl_opt`

### P12.2 Token Bucket Rate Limiting ✅
- [x] `TokenBucket` per-IP rate limiter (`rate_limiter.go`) — configurable capacity + refill rate
- [x] `RateLimitMiddleware` wraps solve handlers, returns 429 with CF-style headers
- [x] `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `Retry-After` headers on all responses
- [x] `MountRoutes()` convenience method: rate-limits solve endpoints, registers XHR callbacks
- [x] Per-IP isolation — independent buckets per client IP (X-Forwarded-For aware)

### P12.3 cf_clearance Cookie Structure ✅
- [x] Realistic format: `{32hex_token}-{unix_timestamp}-1.0.1-{base64url_hmac}`
- [x] `__cf_bm` cookie validation on all solve handlers (JS, Managed, Turnstile)
- [x] Init endpoint sets `__cf_bm` cookie — solver's cookie jar forwards it on solve
- [x] Wrong/missing `__cf_bm` → 403 rejection with `Cf-Mitigated: challenge` header
- [x] `ValidateClearanceCookie` verifies format + expiry + session lookup

---

## Priority 5 — ML & Advanced Sword (Phases 13-14+)

> **Assessment (2026-03-03):** Phases 7-12 cover heuristic gaps that yield higher ROI than ML investment.
> ML becomes the bottleneck once session consistency, cross-vector coherence, and JS API surface are solid.
> Current state: 24 behavioral checks (statistical), 19 detection passes, 4-layer DQN (18 actions).
> CNN CAPTCHA model architecture exists but forward() is identity — needs training.
> DQN trains against simulated env, not real shield — generalization gap.

### Phase 13 — CAPTCHA CNN + Sequence Model

#### P13.1 CNN Character Classifier
- [ ] Train CNN model in `brws/adversarial/captcha/model.go` (architecture exists, forward() is stub)
- [ ] Character-level classification with 10k+ images per difficulty level
- [ ] Use `captcha.Generator` to create infinite labeled training data
- [ ] Target: >95% accuracy on medium difficulty, >80% on hard
- [ ] Integration: replace SegmentationSolver as primary when model weights available

#### P13.2 Sequence-to-Sequence Attention Model
- [ ] End-to-end captcha solving without explicit segmentation
- [ ] Encoder-decoder with spatial attention learns character boundaries automatically
- [ ] Handles variable-length captchas without knowing num_chars in advance
- [ ] Train on synthetic data with rotation/overlap augmentation

#### P13.3 Contrastive Learning Fix
- [ ] Fix broken `ContrastiveSolver` in `brws/adversarial/captcha/solver.go`
- [ ] Proper Gaussian RNG (replace uniform with Box-Muller)
- [ ] NT-Xent loss with negative sampling (temperature-scaled cosine similarity)
- [ ] Working backprop + optimizer step
- [ ] Save/Load persistence for trained embeddings

### Phase 14 — Adversarial Training Loop (GAN-style)

#### P14.1 Shield Discriminator
- [ ] Train a binary classifier on (real_human, sword_synthetic) behavioral traces
- [ ] Input: full behavioral event sequence (mouse + typing + scroll + click)
- [ ] Architecture: LSTM or Transformer encoder → binary output
- [ ] Requires labeled dataset of real human behavioral traces

#### P14.2 Sword Generator
- [ ] Train behavioral event generator to fool the discriminator
- [ ] GAN-style minimax: discriminator improves → generator adapts → discriminator improves
- [ ] The generator replaces the hand-tuned Bézier + log-normal model in `generator.go`

#### P14.3 Behavioral Sequence Model (LSTM/Transformer)
- [ ] Replace aggregate statistical checks with sequence-level detection
- [ ] Catches: unnatural transition patterns, missing hesitation, implausible acceleration
- [ ] Small model: 2-layer LSTM, 64 hidden, trained on real mouse trajectories

#### P14.4 Latent Fingerprint Embedding
- [ ] Train autoencoder on real browser fingerprint vectors (screen + WebGL + plugins + audio + fonts)
- [ ] Bot fingerprints fall outside learned manifold ("uncanny valley" detection)
- [ ] More robust than 19 individual threshold checks

### Phase 15 — Infrastructure

#### P15.1 Residential Proxy Rotation
- [ ] IP vector currently flags datacenter ranges (3.x, 34.x, 52.x etc.)
- [ ] Integrate residential proxy pool for IP diversity
- [ ] Rotation strategy: new IP per session, sticky sessions for multi-request flows
- [ ] Geo-targeting to match timezone/locale headers

#### P15.2 Behavioral Feedback Loop
- [ ] Wire `BehavioralTracker` recordings from real navigation back into `GenerateHumanEvents`
- [ ] Collect mouse/keyboard/scroll distributions from real browsing sessions
- [ ] Continuously improve realism based on shield feedback (pass/fail signals)

#### P15.3 RL Policy Enhancement
- [ ] Train DQN against live shield (not simulated env) — use `train_shield_sword.py`
- [ ] Extend action space to include captcha-specific decisions
- [ ] Actions: solver choice, retry strategy, behavioral intensity
- [ ] State: captcha type, difficulty estimate, previous attempt results
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

