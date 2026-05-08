# Model: Machine Learning & Core Infrastructure

> **Purpose:** ML-driven adaptive fingerprint selection, RL-based evasion policies, shield-vs-sword training, and shared core infrastructure (types, config, telemetry, resilience).

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    ML & Core Layer                           │
├─────────────┬─────────────┬─────────────┬───────────────────┤
│   ML Models │   Core      │ Observability│   Resilience     │
│  (PyTorch)  │  (Types)    │  (Metrics)   │  (Circuit Breaker│
└──────┬──────┴──────┬──────┴──────┬──────┴────────┬──────────┘
       │             │             │               │
       ▼             ▼             ▼               ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│ FSM Policy  │ │ Fingerprint │ │ Health      │ │ Retry       │
│ Shield/Sword│ │ Types       │ │ Metrics     │ │ Circuit     │
│ RL Agent    │ │ Config      │ │ Telemetry   │ │ Breaker     │
└─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘
```

---

## Machine Learning

### Models

Stored in `models/`:

| Model | File | Purpose |
|---|---|---|
| **FSM RL Policy** | `fsm_rl_policy.pt` | Reinforcement learning policy for FSM state transitions |
| **Shield/Sword Policy** | `shield_sword_policy.pt` | Adversarial training: shield (detector) vs sword (evader) |

### Python Training Scripts (`brws/ml/`)

| Script | Purpose |
|---|---|
| `train_rl_agent.py` | Trains RL agent for stealth decision-making |
| `train_shield_sword.py` | Adversarial training between detection and evasion |

### Go ML Integration (`brws/ml/`)

| File | Purpose |
|---|---|
| `policy_loader.go` | Loads PyTorch models into Go for inference |
| `adaptive/storage.go` | SQLite storage for ML training episodes |
| `adaptive/tracker.go` | Tracks adaptive behavior outcomes |

### Adaptive Spoofer (`fingerprint/tls/signatures.go`)

- `AdaptiveSpoofer` — selects fingerprints based on ML predictions
- `FeatureExtractor` — converts `FingerprintSignature` into 20-element float64 feature vector
- `SignatureGenerator` — generates custom variations from base signatures
- `SignatureRegistry` — JSON-serializable registry

### Training Data Generation (`fingerprint/train/datagen/`)

- `Collector` — SQLite-backed storage for `TrainingEpisode`
- Schema: stealth config, detection snapshot, FSM state, captcha data, outcome, bot score, reward, model version, feature vector

---

## Core Infrastructure (`core/`)

### Types (`core/types/`)

Canonical data structures used across the entire project:

| Type | File | Description |
|---|---|---|
| `CompleteFingerprint` | `fingerprint.go` | Top-level fingerprint container |
| `TLSFingerprint` | `fingerprint.go` | TLS layer data |
| `HTTP2Fingerprint` | `fingerprint.go` | HTTP/2 settings and frames |
| `HTTPFingerprint` | `fingerprint.go` | HTTP request fingerprint |
| `ClientHello` | `clienthello.go` | Parsed TLS ClientHello |
| `BehaviorFingerprint` | `fingerprint.go` | Timing and behavior patterns |

### Config (`core/config/`)

| File | Description |
|---|---|
| `stealth.go` | Central stealth configuration (timeouts, proxy, TLS, browser, crawl settings) |

Key config sections:
- `TLSConfig`: spoofing mode, browser, version, JA3 rotation
- `BrowserConfig`: headless, stealth level, profile directory
- `ProxyConfig`: proxy URL, rotation strategy, tier settings
- `CrawlConfig`: rate limiting, robots.txt respect, concurrency
- `CloudflareConfig`: challenge solver settings

### Constants (`core/constants/`)

| File | Description |
|---|---|
| `defaults.go` | Default values for timeouts, delays, thresholds |
| `headers.go` | Known header names used in fingerprinting |

### Telemetry (`core/telemetry/`)

| File | Description |
|---|---|
| `telemetry.go` | Distributed tracing and metrics collection |

### Observability (`core/observability/`)

| Component | Purpose |
|---|---|
| **Health** | Health check endpoints and scoring |
| **Metrics** | Prometheus-compatible metrics export |
| **HTTP** | HTTP middleware for request logging |

### Signals (`core/signals/`)

| Component | Purpose |
|---|---|
| **Manager** | OS signal handling for graceful shutdown |
| **Types** | Signal event types |

---

## Resilience (`core/resilience/`)

### Circuit Breaker (`circuitbreaker.go`)

Prevents cascading failures:
- **Closed**: requests pass through
- **Open**: requests fail fast after threshold
- **Half-Open**: allows probe requests to test recovery

```go
type CircuitBreaker struct {
    FailureThreshold int
    SuccessThreshold int
    Timeout          time.Duration
    State            State // Closed, Open, HalfOpen
}
```

### Retry (`retry.go`)

Configurable retry logic:
- Exponential backoff with jitter
- Max attempts and max duration
- Per-error-type retry policies

---

## Instrumentation (`core/instrumentation/`)

### FSM (`fsm.go`)

Finite state machine for request lifecycle tracking:
- States: `Idle`, `Prepared`, `Navigate`, `ChallengeDetected`, `Complete`, `Fail`
- Transitions logged with timestamps
- Enables distributed tracing spans

### Hooks (`hooks.go`)

Plugin system for custom instrumentation:
- Pre-request hooks
- Post-response hooks
- Challenge detection hooks
- Error hooks

---

## Key Files

| File | Description |
|---|---|
| `models/fsm_rl_policy.pt` | FSM RL policy model |
| `models/shield_sword_policy.pt` | Shield vs Sword adversarial model |
| `brws/ml/train_rl_agent.py` | RL agent training script |
| `brws/ml/train_shield_sword.py` | Adversarial training script |
| `brws/ml/policy_loader.go` | Model loader for Go inference |
| `brws/core/types/fingerprint.go` | Canonical fingerprint types |
| `brws/core/config/stealth.go` | Central configuration |
| `brws/core/constants/defaults.go` | Default constants |
| `brws/core/telemetry/telemetry.go` | Telemetry system |
| `brws/core/observability/health.go` | Health checks |
| `brws/core/observability/metrics.go` | Metrics export |
| `brws/core/resilience/circuitbreaker.go` | Circuit breaker |
| `brws/core/resilience/retry.go` | Retry logic |
| `brws/core/instrumentation/fsm.go` | FSM lifecycle |
| `brws/core/instrumentation/hooks.go` | Hook registry |
