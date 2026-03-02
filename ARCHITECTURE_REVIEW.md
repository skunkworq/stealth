# Architecture Review & Improvement Plan

## Current State Analysis

### Strengths
1. **Clean Engine Interface**: Well-designed abstraction with registry pattern
2. **Context Propagation**: Proper use of `context.Context` throughout
3. **Session Management**: Persistent sessions with cookie jar support
4. **TLS Fingerprinting**: Comprehensive fingerprint capture and spoofing
5. **Test Coverage**: 48 test files across packages
6. **Modular Design**: Good package separation of concerns

### Critical Issues

#### 1. Interface Duplication (HIGH PRIORITY)
Three conflicting `Engine` interfaces exist:
- `brws/engine/engine.go` - Main interface (correct)
- `brws/interfaces/interfaces.go` - Outdated/duplicate
- `brws/engine/spoof/spoof.go` - Different purpose (SpoofEngine struct)

**Impact**: Confusion, import cycling risk, maintenance burden

#### 2. Inconsistent Logging (MEDIUM PRIORITY)
- `brws/instrumentation/logger.go` uses zap
- Other packages use `log.Printf` or `slog`
- No standardized logging interface

**Impact**: Difficult to correlate logs, inconsistent formatting

#### 3. Empty/Unnecessary Packages (MEDIUM PRIORITY)
- `brws/client/` - Empty directory
- `brws/trace/` - Empty directory
- `brws/interfaces/` - Redundant with `brws/engine`

**Impact**: Clutter, confusion about where to add code

#### 4. Missing Resilience Patterns (HIGH PRIORITY)
- No circuit breaker implementation
- No standardized retry logic
- No rate limiting
- No timeout enforcement at call sites

**Impact**: Cascading failures, resource exhaustion

#### 5. Configuration Management (MEDIUM PRIORITY)
- No centralized config structure
- Flags scattered across cmd packages
- No config file support
- No environment variable integration

**Impact**: Difficult to deploy, inconsistent defaults

#### 6. Observability Gaps (MEDIUM PRIORITY)
- No metrics collection (Prometheus/OpenTelemetry)
- No health check endpoints
- No distributed tracing
- Limited structured logging

**Impact**: Difficult to debug production issues

## Improvement Plan

### Phase 1: Foundation (Critical)

#### 1.1 Consolidate Interfaces
- Remove `brws/interfaces` package
- Move mocks to `brws/engine/mocks`
- Ensure single source of truth for Engine interface

#### 1.2 Standardize Logging
- Create `brws/log` package with interface
- Support pluggable backends (zap, slog)
- Migrate all packages to use structured logging

#### 1.3 Clean Up Packages
- Remove empty `brws/client` and `brws/trace`
- Document package purposes in README

### Phase 2: Resilience & Performance

#### 2.1 Add Retry Logic
```go
// brws/resilience/retry.go
type RetryConfig struct {
    MaxAttempts     int
    InitialBackoff  time.Duration
    MaxBackoff      time.Duration
    BackoffMultiplier float64
    RetryableErrors []error
}

func WithRetry(config *RetryConfig, fn func() error) error
```

#### 2.2 Add Circuit Breaker
```go
// brws/resilience/circuitbreaker.go
type CircuitBreaker struct {
    name           string
    failureThreshold int
    successThreshold int
    timeout        time.Duration
    state          State // Closed, Open, HalfOpen
}
```

#### 2.3 Add Rate Limiting
```go
// brws/resilience/ratelimit.go
type RateLimiter interface {
    Allow() bool
    Wait(ctx context.Context) error
}
```

### Phase 3: Observability

#### 3.1 Metrics Collection
```go
// brws/observability/metrics.go
type MetricsCollector interface {
    RecordRequestDuration(engine string, duration time.Duration)
    RecordRequestResult(engine string, success bool)
    RecordChallengeEncountered(challengeType string)
    RecordCaptchaSolved(solver string, duration time.Duration)
}
```

#### 3.2 Health Checks
```go
// brws/observability/health.go
type HealthChecker interface {
    Check(ctx context.Context) HealthStatus
    Name() string
}
```

#### 3.3 Distributed Tracing
- OpenTelemetry integration
- Trace propagation through engine calls

### Phase 4: Configuration

#### 4.1 Unified Config
```go
// brws/config/config.go
type Config struct {
    Engines     EngineConfig
    Session     SessionConfig
    Resilience  ResilienceConfig
    Observability ObservabilityConfig
}
```

#### 4.2 Config Sources
- YAML/JSON file support
- Environment variable mapping
- Command-line flag override

## Implementation Order

1. **Consolidate interfaces** - Remove duplication, reduce confusion
2. **Standardize logging** - Enable proper observability
3. **Add resilience patterns** - Circuit breaker, retry, rate limiting
4. **Add metrics** - Prometheus-style metrics
5. **Configuration management** - Unified config system
6. **Health checks** - Production readiness

## Testing Strategy

- Unit tests for all new packages
- Integration tests for resilience patterns
- Benchmarks for performance-critical paths
- Chaos testing for circuit breakers
