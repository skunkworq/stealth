# Model: Stealth / Anti-Detection Module

> **Purpose:** Bot detection evasion, challenge solving (CAPTCHA, Cloudflare), behavioral mimicry, and adaptive escalation against WAFs and anti-bot systems.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Stealth Layer                            │
├─────────────┬─────────────┬─────────────┬───────────────────┤
│  Challenge  │  Behavior   │   Client    │     Policy        │
│  Solving    │  Evasion    │   Engine    │   Engine          │
└──────┬──────┴──────┬──────┴──────┬──────┴────────┬──────────┘
       │             │             │               │
       ▼             ▼             ▼               ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│ CAPTCHA     │ │ Timing Gen  │ │ Escalation  │ │ FSM-driven  │
│ Cloudflare  │ │ Fingerprint │ │ Retry/Backoff│ │ decision    │
│ reCAPTCHA   │ │ Generator   │ │ Circuit     │ │ making      │
└─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘
```

---

## Challenge Solving

### CAPTCHA Solver (`captcha_solver.go`)

Orchestrates multiple solving backends:
- **Template-based**: pattern matching for simple image CAPTCHAs
- **Segmentation**: splits CAPTCHA images into characters
- **ML model**: trained PyTorch model (`captcha/model.go`)
- **External services**: Capsolver integration (`captcha/solver/capsolver.go`)
- **Manual fallback**: human-in-the-loop solving

### Cloudflare Solver (`cloudflare_solver.go`)

Handles Cloudflare challenges:
- **Turnstile**: detects and solves Turnstile widgets
- **JS challenge**: executes challenge JavaScript in sandboxed environment
- **Managed challenge**: automatic retry with escalating delays
- **IUAM (Under Attack Mode)**: waits for 5-second delay page

### Challenge Classifier (`challenge/challenge_classifier.go`)

Identifies challenge type from page content:
- Cloudflare (Turnstile, JS, Managed)
- DataDome
- reCAPTCHA v2/v3
- hCaptcha
- PerimeterX
- Custom WAF pages

### External Solver Config (`captcha/external_service/capsolver.go`)

`SolverConfig` governs both the external service constructor and the FSM solver:

```go
type SolverConfig struct {
    Provider   string
    APIKey     string
    AutoSolve  bool
    MaxRetries int
    Timeout    time.Duration // total solve wait; 0 → constants.SolverTimeout (120s)
    PollRate   time.Duration // result-check interval; 0 → constants.SolverPollRate (5s)
}
```

`NewCapSolverWithConfig(cfg SolverConfig)` applies zero-value fallbacks from `core/constants`.
`NewCapSolver(apiKey)` is a convenience wrapper calling `NewCapSolverWithConfig`.

---

## Behavioral Evasion (`behavior/`)

### Timing Generator (`behavior/timing_gen.go`)

Produces human-like interaction timing:
- **Keystroke delays**: normally distributed with jitter
- **Mouse movement**: Bézier curves with variable speed
- **Scroll patterns**: scroll-then-pause, scroll-then-read
- **Page load waiting**: random delays based on content size

### Fingerprint Generator (`behavior/fingerprint_gen.go`)

Generates realistic browser fingerprints for behavioral layers:
- Screen resolution distributions per OS/browser
- Plugin list randomization
- Font list randomization
- Canvas/WebGL consistency checks

### Evasion Strategy (`behavior/evasion_strategy.go`)

Implements request-shaping strategies to bypass detection:
- **FirefoxInitNavStrategy**: models Firefox initial page navigation (`dest=document + mode=navigate + site=none`)
- **RealBrowserStrategy**: Firefox telemetry POST with 0 X-* headers
- **Document Navigation**: exploits `dest=document + mode=navigate` gate bypasses
- **POST-based strategies**: compound JSON keys to evade body checks

### Adaptive Generator (`behavior/adaptive_generator.go`)

RL-driven behavior adaptation:
- Observes detection outcomes
- Mutates timing, header order, request shape
- Rewards successful evasions, penalizes detection

---

## Client (`client.go`)

Top-level stealth client coordinating all subsystems:
- **Session management**: cookie jars, localStorage, session persistence
- **Fingerprint binding**: ties browser instance to `CompleteFingerprint`
- **Escalation**: automatic retry with increasing sophistication
- **Health tracking**: per-domain success/failure rates

### Escalation Levels

1. **Level 0**: Basic request with TLS spoofing
2. **Level 1**: Add proxy rotation
3. **Level 2**: Add browser automation with stealth patches
4. **Level 3**: Add behavioral mimicry (mouse, scroll, timing)
5. **Level 4**: Add CAPTCHA solving
6. **Level 5**: Full human-in-the-loop fallback

---

## Policy Engine (`policy.go`)

Rules-based decision making for stealth actions:
- **Domain policies**: custom rules per target domain
- **Rate limiting**: adaptive throttling based on response patterns
- **Fingerprint rotation**: when to rotate TLS/browser fingerprints
- **Challenge response**: which solver to use for which challenge type

---

## FSM Orchestrator (`challenge/fsm/orchestrator.go`)

Finite state machine managing the full stealth lifecycle:

```
Idle → Prepare → Navigate → Detect → (Challenge → Solve) → Extract → Complete
              ↓
            Fail → Escalate → Retry
```

States:
- `Idle`: waiting for request
- `Prepare`: loading fingerprint, configuring proxy
- `Navigate`: loading target page
- `Detect`: scanning for challenges/WAF
- `Challenge`: challenge detected, selecting solver
- `Solve`: executing solver
- `Extract`: extracting desired data
- `Complete`: success
- `Fail`: failure, trigger escalation

`SolverConfig` (`challenge/fsm/types.go`) holds per-solve configuration. Use `DefaultSolverConfig()` to get defaults from `core/constants` (`MaxRetries: 1`, `Timeout: constants.DefaultTimeout`, `HumanDelay: true`) rather than constructing a zero-value struct. When `Timeout == 0` the orchestrator falls back to the caller-supplied deadline.

---

## Detection Vectors (`challenge/vectors.go`)

Catalog of anti-bot detection signals:
- TLS fingerprint mismatch
- Missing/inconsistent headers
- JavaScript environment anomalies
- Behavioral pattern detection (too fast, too linear)
- Canvas/WebGL fingerprinting
- WebRTC leak detection

---

## Key Files

| File | Description |
|---|---|
| `client.go` | Top-level stealth client, session management, escalation |
| `escalation.go` | Escalation logic, retry with increasing sophistication |
| `policy.go` | Rules engine for stealth decisions |
| `captcha_solver.go` | CAPTCHA solving orchestrator |
| `captcha/external_service/capsolver.go` | CapSolver API client; `SolverConfig`, `NewCapSolverWithConfig` |
| `cloudflare_solver.go` | Cloudflare-specific challenge solver |
| `turnstile_verifier.go` | Cloudflare Turnstile verification |
| `recaptcha_integration_test.go` | reCAPTCHA integration tests |
| `challenge/challenge_classifier.go` | Challenge type identification |
| `challenge/fsm/orchestrator.go` | FSM lifecycle management |
| `challenge/fsm/types.go` | `SolverConfig`, `DefaultSolverConfig()`, `ChallengeSolver` interface |
| `challenge/vectors.go` | Detection signal catalog |
| `challenge/stealth_detector.go` | Stealth detection analyzer |
| `challenge/cloudflare_detector.go` | Cloudflare-specific detection |
| `challenge/navigator_analyzer.go` | Navigator object analysis |
| `challenge/webgl_analyzer.go` | WebGL fingerprint analysis |
| `challenge/graphics_analyzer.go` | Canvas/graphics analysis |
| `behavior/timing_gen.go` | Human-like timing generation |
| `behavior/fingerprint_gen.go` | Behavioral fingerprint generation |
| `behavior/evasion_strategy.go` | Request-shaping evasion strategies |
| `behavior/adaptive_generator.go` | RL-driven adaptive behavior |
| `profile/session/session.go` | Session persistence, cookies, health |
| `profile/profiles.go` | Profile management |
