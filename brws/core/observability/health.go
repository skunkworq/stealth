package observability

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Status represents the health status
type Status int

const (
	// StatusHealthy - all checks passing
	StatusHealthy Status = iota
	// StatusDegraded - some checks failing but service operational
	StatusDegraded
	// StatusUnhealthy - critical checks failing
	StatusUnhealthy
)

func (s Status) String() string {
	switch s {
	case StatusHealthy:
		return "healthy"
	case StatusDegraded:
		return "degraded"
	case StatusUnhealthy:
		return "unhealthy"
	default:
		return "unknown"
	}
}

// CheckResult is the result of a single health check
type CheckResult struct {
	Name      string
	Status    Status
	Message   string
	Error     error
	Timestamp time.Time
	Duration  time.Duration
}

// HealthReport aggregates all check results
type HealthReport struct {
	Status    Status
	Checks    []CheckResult
	Timestamp time.Time
}

// Checker performs a health check
type Checker interface {
	Name() string
	Check(ctx context.Context) CheckResult
}

// CheckerFunc allows using a function as a checker
type CheckerFunc struct {
	name  string
	check func(ctx context.Context) CheckResult
}

// NewCheckerFunc creates a checker from a function
func NewCheckerFunc(name string, check func(ctx context.Context) CheckResult) *CheckerFunc {
	return &CheckerFunc{name: name, check: check}
}

// Name returns the checker name
func (c *CheckerFunc) Name() string {
	return c.name
}

// Check performs the health check
func (c *CheckerFunc) Check(ctx context.Context) CheckResult {
	return c.check(ctx)
}

// HealthMonitor manages health checks
type HealthMonitor struct {
	checkers []Checker
	mu       sync.RWMutex
}

// NewHealthMonitor creates a new health monitor
func NewHealthMonitor() *HealthMonitor {
	return &HealthMonitor{
		checkers: make([]Checker, 0),
	}
}

// Register adds a health checker
func (h *HealthMonitor) Register(checker Checker) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checkers = append(h.checkers, checker)
}

// RegisterFunc adds a health check function
func (h *HealthMonitor) RegisterFunc(name string, check func(ctx context.Context) CheckResult) {
	h.Register(NewCheckerFunc(name, check))
}

// Check runs all health checks
func (h *HealthMonitor) Check(ctx context.Context) HealthReport {
	h.mu.RLock()
	checkers := make([]Checker, len(h.checkers))
	copy(checkers, h.checkers)
	h.mu.RUnlock()

	report := HealthReport{
		Status:    StatusHealthy,
		Checks:    make([]CheckResult, 0, len(checkers)),
		Timestamp: time.Now(),
	}

	for _, checker := range checkers {
		start := time.Now()
		result := checker.Check(ctx)
		result.Duration = time.Since(start)
		result.Name = checker.Name()
		result.Timestamp = time.Now()

		report.Checks = append(report.Checks, result)

		// Aggregate status - worst wins
		if result.Status > report.Status {
			report.Status = result.Status
		}
	}

	return report
}

// CheckAsync runs checks concurrently
func (h *HealthMonitor) CheckAsync(ctx context.Context) HealthReport {
	h.mu.RLock()
	checkers := make([]Checker, len(h.checkers))
	copy(checkers, h.checkers)
	h.mu.RUnlock()

	results := make(chan CheckResult, len(checkers))

	for _, checker := range checkers {
		go func(c Checker) {
			start := time.Now()
			result := c.Check(ctx)
			result.Duration = time.Since(start)
			result.Name = c.Name()
			result.Timestamp = time.Now()
			results <- result
		}(checker)
	}

	report := HealthReport{
		Status:    StatusHealthy,
		Checks:    make([]CheckResult, 0, len(checkers)),
		Timestamp: time.Now(),
	}

	for i := 0; i < len(checkers); i++ {
		select {
		case result := <-results:
			report.Checks = append(report.Checks, result)
			if result.Status > report.Status {
				report.Status = result.Status
			}
		case <-ctx.Done():
			report.Checks = append(report.Checks, CheckResult{
				Status:  StatusUnhealthy,
				Message: "check timed out",
			})
			report.Status = StatusUnhealthy
		}
	}

	return report
}

// ReadyChecker is a simple checker that can be marked ready/unready
type ReadyChecker struct {
	name  string
	ready bool
	mu    sync.RWMutex
}

// NewReadyChecker creates a new ready checker
func NewReadyChecker(name string) *ReadyChecker {
	return &ReadyChecker{name: name}
}

// Name returns the checker name
func (r *ReadyChecker) Name() string {
	return r.name
}

// SetReady sets the ready state
func (r *ReadyChecker) SetReady(ready bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ready = ready
}

// IsReady returns the ready state
func (r *ReadyChecker) IsReady() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.ready
}

// Check performs the health check
func (r *ReadyChecker) Check(ctx context.Context) CheckResult {
	if r.IsReady() {
		return CheckResult{
			Status:  StatusHealthy,
			Message: "ready",
		}
	}
	return CheckResult{
		Status:  StatusUnhealthy,
		Message: "not ready",
	}
}

// CompositeChecker checks multiple components
type CompositeChecker struct {
	name     string
	checkers []Checker
	mu       sync.RWMutex
}

// NewCompositeChecker creates a composite checker
func NewCompositeChecker(name string) *CompositeChecker {
	return &CompositeChecker{
		name:     name,
		checkers: make([]Checker, 0),
	}
}

// Name returns the checker name
func (c *CompositeChecker) Name() string {
	return c.name
}

// Add adds a sub-checker
func (c *CompositeChecker) Add(checker Checker) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checkers = append(c.checkers, checker)
}

// Check performs all sub-checks
func (c *CompositeChecker) Check(ctx context.Context) CheckResult {
	c.mu.RLock()
	checkers := make([]Checker, len(c.checkers))
	copy(checkers, c.checkers)
	c.mu.RUnlock()

	worstStatus := StatusHealthy
	var messages []string

	for _, checker := range checkers {
		result := checker.Check(ctx)
		if result.Status > worstStatus {
			worstStatus = result.Status
		}
		if result.Status != StatusHealthy {
			messages = append(messages, fmt.Sprintf("%s: %s", checker.Name(), result.Message))
		}
	}

	message := "all checks passed"
	if len(messages) > 0 {
		message = fmt.Sprintf("issues: %v", messages)
	}

	return CheckResult{
		Status:  worstStatus,
		Message: message,
	}
}

// Common checkers

// TimeoutChecker wraps a checker with a timeout
func TimeoutChecker(checker Checker, timeout time.Duration) Checker {
	return NewCheckerFunc(
		checker.Name(),
		func(ctx context.Context) CheckResult {
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			done := make(chan CheckResult, 1)
			go func() {
				done <- checker.Check(ctx)
			}()

			select {
			case result := <-done:
				return result
			case <-ctx.Done():
				return CheckResult{
					Status:  StatusUnhealthy,
					Message: fmt.Sprintf("check timed out after %v", timeout),
					Error:   ctx.Err(),
				}
			}
		},
	)
}

// Result creates a check result
func Result(status Status, message string) CheckResult {
	return CheckResult{
		Status:    status,
		Message:   message,
		Timestamp: time.Now(),
	}
}

// Healthy creates a healthy result
func Healthy(message string) CheckResult {
	return Result(StatusHealthy, message)
}

// Unhealthy creates an unhealthy result
func Unhealthy(message string, err error) CheckResult {
	return CheckResult{
		Status:    StatusUnhealthy,
		Message:   message,
		Error:     err,
		Timestamp: time.Now(),
	}
}

// Degraded creates a degraded result
func Degraded(message string) CheckResult {
	return Result(StatusDegraded, message)
}

// String returns a formatted report
func (r HealthReport) String() string {
	return fmt.Sprintf("Health[%s, %d checks]", r.Status, len(r.Checks))
}
