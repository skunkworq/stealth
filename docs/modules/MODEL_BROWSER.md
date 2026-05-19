# Model: Browser Engine Module

> **Purpose:** Unified browser automation and HTTP request execution layer with stealth-enhanced anti-detection capabilities.

---

## Architecture Overview

```
┌─────────────────────────────────────────┐
│         engine.Engine (interface)       │
│    Do(ctx, *Request) → (*Response, err) │
└─────────────────────────────────────────┘
                    │
    ┌───────────────┼───────────────┬───────────────┐
    ▼               ▼               ▼               ▼
┌────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
│ native │   │ chromium │   │ firefox  │   │  webkit  │
│(net/http│   │(chromedp)│   │(playwright)│  │(playwright)│
└────────┘   └────┬─────┘   └──────────┘   └──────────┘
                  │
           ┌──────┴──────┐
           ▼             ▼
    ┌─────────────┐  ┌─────────────────┐
    │   Basic     │  │  StealthEngine  │
    │  Chromium   │  │ (chromium-stealth)│
    └─────────────┘  └─────────────────┘
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
        ┌──────────┐  ┌──────────┐  ┌──────────┐
        │ Stealth  │  │ Stealth  │  │   Pool   │
        │  Script  │  │   Plus   │  │          │
        │ (JS inj) │  │(CDP adv) │  │          │
        └──────────┘  └──────────┘  └──────────┘
```

---

## Engine Interface

All request executors implement:

```go
type Engine interface {
    Name() string
    Capabilities() Capabilities
    Do(ctx context.Context, req *Request) (*Response, error)
    Close() error
}
```

**Available engines:**
| Engine | Backend | Use Case |
|---|---|---|
| `"native"` | Go `net/http` + uTLS | Fast, simple requests with TLS spoofing |
| `"chromium"` | chromedp | Basic headless browser |
| `"chromium-stealth"` | chromedp + stealth patches | Anti-detection scraping |
| `"firefox"` | Playwright | Firefox automation |
| `"webkit"` | Playwright | Safari automation |

---

## Basic Chromium Engine (`engine/chromium/chromium.go`)

- Launches Chrome with `disable-blink-features=AutomationControlled`
- Captures network events into HAR-like trace entries
- Supports extra headers, viewport, JS execution, selector waiting
- Always headless by default

---

## Stealth Engine (`stealth/chromium/engine.go`)

The advanced anti-detection engine.

### Features

- **FSM-driven lifecycle**: `Start` → `Prepared` → `Navigate` → `ChallengeDetected` → `Complete`/`Fail`
- **Instrumentation**: structured logging, distributed tracing, hooks
- **Random delays** before navigation and after page load
- **WAF challenge detection**: scans page content post-load; triggers adaptive retry on detection
- **Human-like interactions**: `Mouse()`, `Click()`, `Type()`, `Scroll()` via `brws/stealth/behavior`
- **Fingerprint-bound identity**: couples to `CompleteFingerprint` for consistent headers, UA, pacing

### Launch-Time Flags

- `disable-blink-features=AutomationControlled`
- `use-gl=angle`, `use-angle=default` (real GPU, not SwiftShader)
- `disable-infobars`, `disable-dev-shm-usage`, `no-sandbox`
- Randomized window size (±50px jitter around 1920×1080)

### Runtime JS Injection (`stealth_script.go`)

Injects an IIFE patching ~25 browser APIs:

| # | API | Patch |
|---|---|---|
| 1 | `navigator.deviceMemory` | Spoofed RAM (e.g., 8 GB) |
| 2 | `navigator.hardwareConcurrency` | Spoofed CPU cores |
| 3 | `navigator.platform` | Spoofed OS |
| 4 | `screen.*` / `window.*` | Spoofed dimensions, pixel ratio |
| 5 | `Date.prototype.getTimezoneOffset` | Spoofed timezone |
| 6 | `navigator.userAgentData` | Client Hints spoofing |
| 7 | `navigator.connection` | Network Information API |
| 8 | `navigator.webdriver` | Deleted → `false` |
| 9 | Video `canPlayType` | Realistic codec support |
| 10 | WebGL | Proxy on real context; vendor/renderer spoofed |
| 11 | Canvas | Optional deterministic noise (disabled by default) |
| 12 | `HTMLElement.offsetHeight` | Modernizr bypass |
| 13 | `navigator.plugins` | Realistic plugin list |
| 14 | `navigator.languages` | `['en-US', 'en']` |
| 15 | `window.chrome.runtime` | Full enum spoofing |
| 16 | Dynamic RL mutations | NetworkSync, VideoSync, PluginsSync, etc. |
| 17 | AudioContext | Sample rate, latency spoofing |
| 18 | Headless mitigations | `outerHeight` gap, `Notification.permission` |
| 19 | WebRTC | Disabled or relay-only |
| 20 | Permissions API | Optionally returns `prompt` |

### StealthPlus (`stealth_plus.go`)

Advanced mode adding:
- `GrantAllPermissions()` — grants 18+ permissions via CDP
- `EvaluateWithGesture()` — runs JS with `userGesture=true`
- `EnableFetchIntercept()` — network interception via CDP Fetch domain
- **Navigation Profiles** — `NavigateWithProfile()` injects referrer, history, sessionStorage
- **Shadow DOM Expert Mode** — forces shadow roots to `mode: 'open'`

---

## Browser Pool (`pool/pool.go`)

- Pre-creates `MinSize` instances, max `MaxSize`
- Recycles after `MaxUses`, `MaxAge`, or `IdleTimeout`
- `PooledEngine` wrapper for acquire/release

---

## Waterfall Engine (`waterfall/waterfall.go`)

Races multiple engines with tiered launch delays:
- Tier 0 fires immediately
- Later tiers launch after `LaunchAfter`
- First success wins; losers cancelled
- Supports runtime tier promotion (`PromoteTier`)

---

## Test Server (`testserver/server.go`)

Mock HTTP/TLS server for testing:
- Endpoints: `/`, `/detect`, `/fingerprint`, `/headers`, `/tls`
- Captures TLS info (version, cipher, JA3, JA4)
- Captures HTTP headers and runs detection heuristics
- `DetectionResult` scores bot indicators

---

## Key Design Decisions

1. **ANGLE over SwiftShader**: Uses real GPU to avoid detectable software-rendered WebGL/canvas fingerprints
2. **Canvas noise OFF by default**: ANGLE produces natural fingerprints; noise can be detected
3. **Fingerprint-bound pacing**: Reads `fingerprint.Behavior.RequestPattern.RequestPacing` for human-like delays
4. **FSM + WAF detection**: State machine tracks request lifecycle; WAF detection triggers upstream retry
5. **RL-configurable mutations**: `StealthConfigRaw` allows external RL agents to mutate stealth parameters

---

## Files

| File | Description |
|---|---|
| `engine/engine.go` | Core `Engine` interface, `Request`/`Response` types, registry |
| `engine/request_advanced.go` | `FormRequest`, `JsonRequest`, `RequestWithCallback`; `FlattenHeaders(map[string][]string) map[string]string` shared utility |
| `engine/chromium/chromium.go` | Basic CDP-based Chromium engine |
| `stealth/chromium/engine.go` | Advanced stealth engine with FSM, WAF detection, human-like interactions |
| `engine/chromium/stealth_script.go` | JS injection patches (~25 API patches) |
| `engine/chromium/stealth_plus.go` | StealthPlus advanced CDP features |
| `engine/response_types.go` | `TextResponse`/`HtmlResponse` with CSS/XPath parsing |
| `pool/pool.go` | Browser instance pooling |
| `waterfall/waterfall.go` | Multi-engine racing |
| `testserver/server.go` | Mock detection/fingerprinting server |
