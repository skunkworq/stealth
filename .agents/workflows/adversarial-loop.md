---
description: Adversarial enhancement loop to iteratively strengthen both the stealth detector (sword) and stealth engine (shield)
---

# Adversarial Enhancement Loop

This workflow defines the iterative process for extending both the **Sword** (detection engine) and the **Shield** (stealth/evasion engine). Each loop iteration follows: **Detect → Evade → Verify → Harden**.

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                       SWORD (Detector)                          │
│  brws/adversarial/stealth_detector.go  (~3000 lines, 85 items)  │
│  Vectors: TLS, HTTP, Navigator, Canvas, WebGL, Timing,          │
│           Behavioral, Screen, Plugin, Audio, Isomorphic          │
│  Tests:   adversarial/sword_vs_shield_test.go                    │
│           adversarial/stealth_detector_test.go                   │
└────────────────────────┬─────────────────────────────────────────┘
                         │ DetectionReport (score, fired_checks)
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│                   FEEDBACK LOOP (Adaptive)                       │
│  brws/behavior/adaptive_generator.go  (49 mutation functions)    │
│  Maps fired check names → MutationFunc closures                  │
│  Tracks: history[], evasion rate, applied mutations              │
└────────────────────────┬─────────────────────────────────────────┘
                         │ Config mutations
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│                       SHIELD (Engines)                           │
│  Chromium:  brws/engine/chromium/stealth.go  (JS injection)      │
│  Native:    brws/engine/native/native.go     (uTLS + HTTP/2)     │
│  Spoof:     brws/engine/spoof/spoof.go       (Fingerprint replay)│
│  Signatures: brws/engine/spoof/signature.go                      │
└──────────────────────────────────────────────────────────────────┘
```

## Pre-Loop: Setup & Baseline

Before starting any enhancement loop, establish a working baseline:

// turbo-all

1. **Ensure `labd` is running** for local TLS/fingerprint capture:
   ```bash
   cd cmd/labd && go build -o lab_server . && ./lab_server
   ```
   This starts HTTPS on `:8443`, HTTP on `:8080`, Proxy on `:8081`.

2. **Run the existing test suite** to confirm nothing is broken:
   ```bash
   go test ./brws/adversarial/... -count=1 -run TestSwordVsShield -v
   go test ./brws/behavior/... -count=1 -v
   ```

3. **Record the baseline score** from the `TestSwordVsShield` output. The shield should currently achieve `Score: 0.000, IsBot: false`.

## Loop Phase 1: Strengthen the Sword (Add Detection)

**Goal:** Identify a new detection vector or improve an existing one so the sword catches traffic that currently passes.

### Step 1a: Identify a Gap
- Review real-world anti-bot systems (Cloudflare, Akamai, DataDome, PerimeterX) for new detection techniques.
- Check these detection categories in `stealth_detector.go` for coverage gaps:
  - **TLS**: JA3/JA4 hash allowlists, extension ordering, GREASE patterns, post-quantum extensions
  - **HTTP**: Header ordering, missing standard headers, Client Hints consistency
  - **Navigator**: `navigator.webdriver`, plugin count, language consistency
  - **Canvas**: PNG magic bytes, IDAT entropy, deterministic hash detection
  - **WebGL**: Renderer/vendor mismatch, extension count, parameter ranges
  - **Timing**: Navigation timing plausibility, resource timing entries
  - **Behavioral**: Mouse velocity autocorrelation, scroll momentum, click intervals
  - **Audio**: AudioContext fingerprint consistency
  - **Screen**: Resolution/DPR plausibility, available height gaps
  - **Isomorphic**: Cross-layer consistency (TLS version vs HTTP/2, UA vs Client Hints)

### Step 1b: Implement the New Check
- Add a new `check*` method to `stealth_detector.go` following the existing pattern:
  ```go
  func (d *StealthDetector) checkNewVector(r *http.Request, ...) CheckReport {
      report := CheckReport{CheckName: "new_vector_name"}
      // ... detection logic ...
      return report
  }
  ```
- Wire it into the appropriate `analyze*` method (e.g. `analyzeTLS`, `analyzeHTTP`, `analyzeNavigator`).
- Assign an appropriate weight in `DefaultDetectorConfig()`.
- Add the check name to the `DetectorConfig.Enable*` toggle if it's a distinct category.

### Step 1c: Write Sword Tests
- Add test cases to the relevant `*_test.go` file in `brws/adversarial/`.
- Confirm the new check fires on known-bot traffic and does NOT fire on real browser traffic.
- Run: `go test ./brws/adversarial/... -count=1 -run TestNewCheck -v`

### Step 1d: Verify the Sword Catches the Shield
- Run `TestSwordVsShield` — it should now FAIL (the shield's score should be > 0):
  ```bash
  go test ./brws/adversarial/... -count=1 -run TestSwordVsShield -v
  ```
- Record which checks fired and their scores. This is the target list for Phase 2.

## Loop Phase 2: Strengthen the Shield (Add Evasion)

**Goal:** Update the shield engines so they pass the newly strengthened sword.

### Step 2a: Identify Fired Checks
- From Phase 1d output, extract the `fired_checks` list.
- Map each fired check to the appropriate shield component:

| Check Category | Shield Component | Key File |
|---|---|---|
| TLS fingerprint | Native uTLS / Spoof Engine | `native.go`, `spoof.go` |
| HTTP headers | Request Generator / Stealth Config | `request_generator.go`, `stealth.go` |
| Navigator props | Chromium JS injection | `stealth.go` `GenerateStealthScript()` |
| Canvas/WebGL | Chromium JS injection | `stealth.go` canvas/WebGL overrides |
| Behavioral | Event Generator | `behavior/generator.go` |
| Timing | Request Generator | `request_generator.go` |

### Step 2b: Implement the Evasion
- **For JS-level evasion** (Navigator, Canvas, WebGL): Modify `GenerateStealthScript()` in `brws/engine/chromium/stealth.go`.
- **For TLS-level evasion**: Modify `native.go` `DialTLSContext` or `spoof.go` `buildTLSConfig()`.
- **For HTTP-level evasion**: Modify `behavior/request_generator.go` or the profile in `engine/profiles/`.
- **For behavioral evasion**: Modify `behavior/generator.go` (mouse/scroll/timing generation).

### Step 2c: Register the Adaptive Mutation
- In `brws/behavior/adaptive_generator.go`, in `registerMutations()`:
  ```go
  ag.mutations["new_check_name"] = mutateFixNewCheck
  ```
- Implement `mutateFixNewCheck(ag *AdaptiveRequestGenerator)` to apply the config change that fixes the check.

### Step 2d: Run E2E Validation
- Run `TestSwordVsShield` again — the shield should now pass:
  ```bash
  go test ./brws/adversarial/... -count=1 -run TestSwordVsShield -v
  ```
- Confirm `Score: 0.000, IsBot: false`.

## Loop Phase 3: TLS Fingerprint Validation (if TLS changes were made)

**Goal:** Verify TLS-layer changes produce the correct JA3/JA4 fingerprint.

### Step 3a: Capture Chromium Baseline
- Use `cmd/eval_e2e/main.go` configured to launch headless Chromium against `labd`:
  ```bash
  cd brws/cmd/eval_e2e && go run main.go
  ```
- Record the Chromium JA3 hash from `curl -s http://localhost:8080/captures | jq`.

### Step 3b: Capture Go Native Fingerprint
- Modify `eval_e2e` to use the `native.New(engine.Options{StealthTLS: true})` engine.
- Run and capture the Go JA3 via `labd`.
- Compare against the Chromium baseline.

### Step 3c: Fix Discrepancies
- If hashes differ, adjust `native.go` (`utls.HelloChrome_Auto` or custom `ClientHelloSpec`).
- If using `spoof.go`, ensure no duplicate extensions (the `seenExtensions` dedup guard).
- Verify `InsecureSkipVerify` is only `true` for local testing, production should validate certs.

## Loop Phase 4: Cross-Validation & Hardening

**Goal:** Ensure changes don't break other vectors or introduce regressions.

### Step 4a: Full Test Suite
```bash
go test ./brws/adversarial/... -count=1 -v
go test ./brws/behavior/... -count=1 -v
go test ./brws/engine/native/... -count=1 -v
go test ./brws/engine/spoof/... -count=1 -v
```

### Step 4b: Isomorphic Consistency Check
- Verify cross-layer consistency: the TLS fingerprint, HTTP/2 settings, User-Agent, and Client Hints should all tell a coherent story.
- The sword's `isomorphic_check` vector should NOT fire on the shield.

### Step 4c: Record Results
- Update `task.md` with the completed loop iteration.
- Document any new detection vectors or evasion techniques in `implementation_plan.md`.

## Loop Phase 5: External Validation (Optional)

**Goal:** Test against real-world anti-bot services to validate evasion.

### Step 5a: Cloudflare Challenge
```bash
go test ./brws/adversarial/... -count=1 -run TestCloudflareChallenge -v
```

### Step 5b: External Fingerprint Services
- Navigate to `https://tls.peet.ws/api/all` or `https://browserleaks.com/tls` using the shield engine.
- Compare the fingerprint output against known Chrome profiles.

## Key Files Reference

### Sword (Detection)
| File | Purpose |
|---|---|
| `brws/adversarial/stealth_detector.go` | Main detection engine (~3000 lines) |
| `brws/adversarial/stealth_detector_test.go` | Unit tests for detector |
| `brws/adversarial/sword_vs_shield_test.go` | Integration test: sword vs shield |
| `brws/adversarial/shield_checks_test.go` | Individual shield check tests |

### Shield (Evasion)
| File | Purpose |
|---|---|
| `brws/engine/chromium/stealth.go` | JS injection for Chrome CDP (~1040 lines) |
| `brws/engine/native/native.go` | Go HTTP engine with uTLS (~500 lines) |
| `brws/engine/spoof/spoof.go` | Fingerprint replay engine (~420 lines) |
| `brws/engine/spoof/signature.go` | Browser signature definitions |
| `brws/engine/spoof/adapter.go` | Fingerprint → Signature conversion |

### Feedback Loop
| File | Purpose |
|---|---|
| `brws/behavior/adaptive_generator.go` | Adaptive mutations (~594 lines, 49 items) |
| `brws/behavior/generator.go` | Mouse/scroll/timing event generation |
| `brws/behavior/request_generator.go` | HTTP request construction |

### Test Harnesses
| File | Purpose |
|---|---|
| `brws/cmd/eval_e2e/main.go` | End-to-end TLS/fingerprint evaluator |
| `cmd/labd/main.go` | Local TLS capture lab server |

## Common Pitfalls

1. **uTLS duplicate extensions**: The `SupportedVersions` (0x002b) extension can appear twice in Chrome traces — deduplicate with `seenExtensions` map in `spoof.go`.
2. **Padding extension crash**: Skip `0x0015` (padding) in custom `ClientHelloSpec` — it causes decode errors on some servers.
3. **Canvas determinism**: Never use `Math.random()` in canvas/WebGL overrides — use seeded PRNG based on pixel index (`Math.sin(i * seed)`).
4. **Platform consistency**: `randomGPURenderer()` must match the declared `navigator.platform` — Apple GPUs for MacIntel, NVIDIA/AMD for Win32.
5. **InsecureSkipVerify**: Set to `true` ONLY for local `labd` testing; production must validate certificates.
6. **HTTP/2 SETTINGS**: When using `utls.HelloChrome_Auto`, ensure the HTTP/2 transport SETTINGS match Chrome's expected values (`native.chromeH2Profile()`).

## Fingerprint Vector Database

This is the living reference of all detection vectors implemented in the adversarial loop. Each entry documents the browser API being exploited, what the sword checks, how the shield evades, and the adaptive mutation. **Update this section after every loop iteration.**

---

### Phase 20: `pdf_viewer_disabled` (Navigator)

| | Detail |
|---|---|
| **Browser API** | `navigator.pdfViewerEnabled` |
| **Real behavior** | All modern browsers (Chrome 90+, Firefox 99+) return `true` — built-in PDF viewers are standard |
| **Sword check** | `analyzeNavigatorData()` — flags `pdfViewerEnabled: false` on modern browser UAs |
| **Score** | +0.25 |
| **Shield fix** | `request_generator.go` `generateNavigator()` — hardcoded `pdfViewerEnabled: true` |
| **Mutation** | `mutateFixPdfViewer` → `ag.rebuild()` |
| **Fired checks** | `pdfViewerEnabled_false_modern_browser`, `pdf_viewer_disabled` |

---

### Phase 21: `hardware_coherence_*` (Navigator)

| | Detail |
|---|---|
| **Browser API** | `navigator.deviceMemory` + `navigator.hardwareConcurrency` |
| **Real behavior** | RAM and core counts are correlated: 4GB→2-4 cores, 8GB→4-8, 16GB→8-16, 32GB→16-32 |
| **Sword check** | `analyzeNavigatorData()` — detects ≥32GB with ≤2 cores, ≤4GB with ≥16 cores |
| **Score** | +0.20 per violation |
| **Shield fix** | `request_generator.go` `generateNavigator()` — picks from 9 correlated `(memory, cores)` pairs table |
| **Mutation** | `mutateFixHardwareCoherence` → `ag.rebuild()` |
| **Fired checks** | `hardware_coherence_improbable`, `hardware_coherence_high_ram_low_cores`, `hardware_coherence_low_ram_high_cores` |

---

### Phase 22: `timing_all_zero_duration` (Timing)

| | Detail |
|---|---|
| **Browser API** | `PerformanceResourceTiming.duration` |
| **Real behavior** | Resource load time is always > 0ms — even cached resources take 1-5ms |
| **Sword check** | `analyzeTimingData()` — flags when ALL 18 timing entries have `duration_ms = 0` |
| **Score** | +0.30 |
| **Shield fix** | `request_generator.go` `generateTiming()` — realistic `duration_ms` per type: HTML 200-500ms, CSS 30-100ms, JS 50-150ms, images 80-300ms, fonts 50-200ms, XHR 100-400ms |
| **Mutation** | `mutateFixTimingDuration` → `ag.rebuild()` |
| **Fired checks** | `timing_all_zero_duration` |

---

### Phase 23: `vendor_browser_mismatch` (Navigator)

| | Detail |
|---|---|
| **Browser API** | `navigator.vendor` |
| **Real behavior** | Chrome → `"Google Inc."`, Firefox → `""`, Safari → `"Apple Computer, Inc."` |
| **Sword check** | `analyzeNavigatorData()` — validates vendor string matches UA browser type |
| **Score** | +0.30 |
| **Shield fix** | `request_generator.go` `generateNavigator()` — vendor set per browser profile (already correct) |
| **Mutation** | `mutateFixVendorConsistency` → `ag.rebuild()` |
| **Fired checks** | `vendor_browser_mismatch` |

---

### Phase 24: `chrome_loadtimes_ordering` (Navigator)

| | Detail |
|---|---|
| **Browser API** | `chrome.loadTimes()` (deprecated but still present) |
| **Real behavior** | `requestTime < startLoadTime < commitLoadTime < firstPaintTime < finishDocumentLoadTime < finishLoadTime` — strict monotonic ordering |
| **Sword check** | `analyzeNavigatorData()` — validates strict temporal ordering of all 6 timing fields; also checks total page load plausibility (0.1s-60s) |
| **Score** | +0.35 (ordering) + 0.25 (implausible duration) |
| **Shield fix** | `request_generator.go` `generateNavigator()` — generates each field as cumulative offset from `requestTime`, guaranteeing monotonic order |
| **Mutation** | `mutateFixLoadTimesOrdering` → `ag.rebuild()` |
| **Fired checks** | `chrome_loadtimes_ordering_violation`, `chrome_loadtimes_implausible_duration`, `missing_chrome_loadTimes` |

---

### Phase 25: `audio_zero_output_latency` (Audio)

| | Detail |
|---|---|
| **Browser API** | `AudioContext.outputLatency` |
| **Real behavior** | Real audio hardware always has non-zero output latency: typically 0.005-0.04s depending on buffer size and driver |
| **Sword check** | `analyzeNavigatorData()` — reads `X-Audio-Data` header, flags `output_latency == 0.0` |
| **Score** | +0.20 |
| **Shield fix** | `request_generator.go` `generateAudio()` — `0.005 + rng.Float64()*0.035` (range 0.005-0.04s); also `state: "running"` instead of `"suspended"` |
| **Mutation** | `mutateFixAudioOutputLatency` → `ag.rebuild()` |
| **Fired checks** | `audio_zero_output_latency` |

---

### Phase 26: `csi_loadtimes_timing_mismatch` (Isomorphic)

| | Detail |
|---|---|
| **Browser API** | `chrome.csi().startE` vs `chrome.loadTimes().requestTime` |
| **Real behavior** | `startE` (ms) = `requestTime` (seconds) × 1000 — both derive from the same navigation timestamp |
| **Sword check** | `analyzeIsomorphicAnomalies()` — computes `abs(startE - requestTime*1000)`, flags if > 100ms |
| **Score** | +0.40 |
| **Shield fix** | `request_generator.go` `generateNavigator()` — `startE` is computed as `int64(requestTime * 1000)`, guaranteeing exact match |
| **Mutation** | `mutateFixCSILoadTimes` → `ag.rebuild()` |
| **Fired checks** | `csi_loadtimes_timing_mismatch` |

---

### Phase 27: `timing_all_entries_missing_url` (Timing)

| | Detail |
|---|---|
| **Browser API** | `PerformanceResourceTiming.name` |
| **Real behavior** | Every resource timing entry has a `name` field containing the full resource URL (e.g., `https://example.com/assets/js/app.js`) |
| **Sword check** | `analyzeIsomorphicAnomalies()` — iterates timing entries, flags if ALL have empty `url` field |
| **Score** | +0.25 |
| **Shield fix** | `request_generator.go` `generateTiming()` — 18 entries with realistic paths: `/assets/css/main.css`, `/assets/js/app.js`, `/assets/img/logo.png`, `/api/v1/init`, etc. |
| **Mutation** | `mutateFixTimingURLs` → `ag.rebuild()` |
| **Fired checks** | `timing_all_entries_missing_url` |

---

### Phase 28: `network_effectivetype_rtt_mismatch` (Browser Mode)

| | Detail |
|---|---|
| **Browser API** | `navigator.connection.effectiveType` + `navigator.connection.rtt` |
| **Real behavior** | `effectiveType` is derived from measured RTT: `"4g"` → RTT < 200ms, `"3g"` → 200-400ms, `"2g"` → 400ms+ |
| **Sword check** | `analyzeNavigatorData()` — flags `effectiveType: "4g"` with RTT > 200ms, or downlink < 1.0 Mbps |
| **Score** | +0.20 per violation |
| **Shield fix** | `request_generator.go` `generateNavigator()` — RTT range already 20-150ms for 4g, well within bounds |
| **Mutation** | `mutateFixNetworkCoherence` → `ag.rebuild()` |
| **Fired checks** | `network_effectivetype_rtt_mismatch`, `network_effectivetype_downlink_mismatch` |

---

### Phase 29: `missing_notification_permission` (Browser Mode)

| | Detail |
|---|---|
| **Browser API** | `Notification.permission` |
| **Real behavior** | All desktop browsers expose the Notification API with `permission = "default"` (not asked yet), `"granted"`, or `"denied"` |
| **Sword check** | `analyzeNavigatorData()` — flags complete absence of `Notification_permission` from navigator data |
| **Score** | +0.15 |
| **Shield fix** | `request_generator.go` `generateNavigator()` — includes `"Notification_permission": "default"` |
| **Mutation** | `mutateFixNotificationPermission` → `ag.rebuild()` |
| **Fired checks** | `missing_notification_permission` |

---

### Phase 30: `screen_dpr_resolution_improbable` (Screen)

| | Detail |
|---|---|
| **Browser API** | `window.devicePixelRatio` + `screen.width` |
| **Real behavior** | 2x DPI only exists on 1920px+ screens (MacBook Pro, 4K monitors). A 1366×768 at 2x DPR = 2732×1536 physical — nonexistent hardware |
| **Sword check** | `analyzeIsomorphicAnomalies()` — flags `pixel_ratio >= 2.0` with screen width < 1920px |
| **Score** | +0.25 |
| **Shield fix** | `request_generator.go` `generateScreen()` — clamps DPR to 1.0 when resolution < 1920px |
| **Mutation** | `mutateFixDPRResolution` → `ag.rebuild()` |
| **Fired checks** | `screen_dpr_resolution_improbable` |

---

### Phase 31: `font_nav_platform_mismatch` (Isomorphic)

| | Detail |
|---|---|
| **Browser API** | `X-Font-Data.platform` vs `navigator.platform` |
| **Real behavior** | Font enumeration and navigator always report the same OS. MacIntel fonts on a Win32 navigator is impossible |
| **Sword check** | `analyzeIsomorphicAnomalies()` — cross-checks OS family (Mac/Win/Linux) between font data and navigator data |
| **Score** | +0.35 |
| **Shield fix** | Already consistent — font and navigator both derived from the same browser profile |
| **Mutation** | `mutateFixFontPlatform` → `ag.rebuild()` |
| **Fired checks** | `font_nav_platform_mismatch` |

---

### Phase 32: `canvas_idat_high_entropy` (Canvas)

| | Detail |
|---|---|
| **Browser API** | `HTMLCanvasElement.toDataURL()` |
| **Real behavior** | Real canvas data (a rendered PNG) has lots of solid background regions, resulting in low Shannon entropy (< 6.0) for the uncompressed IDAT payload. |
| **Sword check** | `analyzeCanvasData()` — decompresses IDAT and flags entropy > 7.9. |
| **Score** | +0.45 |
| **Shield fix** | `request_generator.go` `generateCanvas()` — fills with white and a tiny repeated random seed pattern to maintain 256-bit uniqueness with near-zero entropy. |
| **Mutation** | `mutateFixCanvasEntropy` → toggle `EvadeCanvasEntropy` |
| **Fired checks** | `canvas_idat_high_entropy` |

---

### Phase 33: `missing_click_dwell_time` / `instant_click_dwell` (Behavioral)

| | Detail |
|---|---|
| **Browser API** | Mouse events (`mousedown` vs `mouseup`) |
| **Real behavior** | Real users take 50-200ms between depressing the mouse button and releasing it. |
| **Sword check** | `analyzeBehavioralEvents()` — flags totally missing dwell times or if >=50% of clicks are <10ms. |
| **Score** | +0.25 (missing) / +0.35 (instantaneous) |
| **Shield fix** | `generator.go` `generateClickEvents()` — adds 80-200ms `clickDwellTimes` for every click. |
| **Mutation** | `mutateEvadeClickDwellTime` → toggle `EvadeClickDwellTime` |
| **Fired checks** | `missing_click_dwell_time`, `instant_click_dwell` |

---

### Phase 34: WebGL Extension Range
| Property | Details |
|---|---|
| **Context** | The `WebGLRenderingContext` exposes a `getSupportedExtensions()` function. |
| **Sword check** | `insufficient_webgl_extensions`, `missing_webgl_extensions` |
| **Detection logic** | Real commercial browsers expose 25-50+ GL extensions (typically >30 on Win32, >27 on macOS/Linux). Headless environments and rudimentary scrapers often expose $<20$. We detect counts below expected thresholds based on the reported operating system platform. |
| **Shield fix** | Intercept or configure the generator to dynamically supplement `BrowserProfile` WebGL extensions with generic/expected extensions (e.g. `WEBGL_compressed_texture_astc`, `OVR_multiview2`) until the threshold is satisfied. |
| **Mutation** | `mutateFixWebGLCount` → toggles `EvadeWebGLCount` config. |
| **Fired checks** | `insufficient_webgl_extensions`, `missing_webgl_extensions` |

---

### Phase 35: Screen Taskbar Gap
| Property | Details |
|---|---|
| **Context** | Modern desktop operating systems persistently render OS chrome like taskbars or menu bars, slightly reducing available viewing height. |
| **Sword check** | `no_taskbar_gap`, `suspicious_taskbar_gap` |
| **Detection logic** | `screen.height` minus `screen.availHeight` forms the taskbar gap. Real environments typically have a gap containing 24px-150px. A gap of exactly 0 indicates headless or full-screen kiosk routing, while gaps >150px are highly improbable for standardized displays. |
| **Shield fix** | Reconfigure screen bound generators to reliably produce a 30-50px difference between `height` and `availHeight`. |
| **Mutation** | `mutateFixScreenHeightGap` → toggles `EvadeScreenHeightGap` config. |
| **Fired checks** | `no_taskbar_gap`, `suspicious_taskbar_gap` |

---

### Phase 36: Accept Header vs Sec-Fetch-Dest Consistency
| Property | Details |
|---|---|
| **Context** | Navigation vs XHR have different Accept headers. A real browser sends `text/html,...` for document navigation, but generic headers like `*/*` or `application/json` for API data fetches. |
| **Sword check** | `accept_dest_mismatch_missing_html`, `accept_dest_mismatch_static_document` |
| **Detection logic** | Flags requests explicitly claiming `Sec-Fetch-Dest` target type but possessing incongruent HTTP `Accept` profiles (typically due to naive static request templates across all HTTP sessions). |
| **Shield fix** | Updates `RequestGeneratorConfig` to dynamically bind `*/*` if target is API (e.g. `empty` or `cors`). |
| **Mutation** | `mutateFixAcceptDest` → toggles `EvadeAcceptDestConsistency` config. |
| **Fired checks** | `accept_dest_mismatch_missing_html`, `accept_dest_mismatch_static_document` |

---

### Future Vectors to Explore

When identifying new detection gaps, consider these not-yet-implemented vectors:

| Category | Vector | Detection Idea |
|---|---|---|
| **TLS** | JA4 hash allowlist | Maintain allowlist of known Chrome JA4 hashes; flag unknown hashes |
| **TLS** | Post-quantum extensions | Chrome 124+ sends X25519Kyber768 — absence on modern Chrome UA is suspicious |
| **HTTP** | Header ordering | Real Chrome sends headers in specific order; Go's `net/http` alphabetizes them |
| **Canvas** | IDAT entropy threshold | Noise-injected canvas has higher entropy than real GPU-rendered canvas |
| **Canvas** | Deterministic hash | Same canvas hash across sessions indicates no GPU variation |
| **WebGL** | Extension count ranges | Chrome on Win typically has 30-40 WebGL extensions; < 20 is suspicious |
| **Behavioral** | Mouse velocity autocorrelation | Real humans have autocorrelation ~0.3-0.7; bots are 0.0 or 1.0 |
| **Behavioral** | Scroll momentum decay | Real scrolling has exponential decay; linear or instant stop is bot-like |
| **Behavioral** | Click dwell time | Time between mousedown→mouseup: humans 80-200ms, bots 0-10ms |
| **Screen** | Available height gap | `screen.height - screen.availHeight` should be 30-50px (taskbar) |
| **Isomorphic** | TLS version vs HTTP/2 SETTINGS | Chrome's HTTP/2 SETTINGS have specific values that vary by version |
| **Isomorphic** | `Sec-Ch-Ua` version vs UA version | Major version in Client Hints must match major version in UA string |

