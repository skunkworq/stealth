package resilience

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCircuitBreakerStateTransitions(t *testing.T) {
	config := &CircuitBreakerConfig{
		FailureThreshold: 3,
		SuccessThreshold: 2,
		Timeout:          100 * time.Millisecond,
	}

	cb := NewCircuitBreaker(config)

	// Initial state should be closed
	if cb.State() != StateClosed {
		t.Errorf("expected initial state Closed, got %v", cb.State())
	}

	// Fail 3 times to open the circuit
	for i := 0; i < 3; i++ {
		err := cb.Execute(func() error {
			return errors.New("failure")
		})
		if err == nil {
			t.Error("expected error")
		}
	}

	if cb.State() != StateOpen {
		t.Errorf("expected state Open after failures, got %v", cb.State())
	}

	// Next request should fail fast
	err := cb.Execute(func() error {
		return nil // Would succeed but circuit is open
	})
	if !errors.Is(err, ErrCircuitOpen) {
		t.Errorf("expected ErrCircuitOpen, got %v", err)
	}

	// Wait for timeout to transition to half-open
	time.Sleep(150 * time.Millisecond)

	// First success in half-open
	err = cb.Execute(func() error {
		return nil
	})
	if err != nil {
		t.Errorf("expected success in half-open, got %v", err)
	}

	if cb.State() != StateHalfOpen {
		t.Errorf("expected state HalfOpen, got %v", cb.State())
	}

	// Second success should close the circuit
	err = cb.Execute(func() error {
		return nil
	})
	if err != nil {
		t.Errorf("expected success, got %v", err)
	}

	if cb.State() != StateClosed {
		t.Errorf("expected state Closed after successes, got %v", cb.State())
	}
}

func TestCircuitBreakerHalfOpenFailure(t *testing.T) {
	config := &CircuitBreakerConfig{
		FailureThreshold: 3,
		SuccessThreshold: 2,
		Timeout:          100 * time.Millisecond,
	}

	cb := NewCircuitBreaker(config)

	// Open the circuit
	for i := 0; i < 3; i++ {
		_ = cb.Execute(func() error {
			return errors.New("failure")
		})
	}

	if cb.State() != StateOpen {
		t.Fatal("expected state Open")
	}

	// Wait for timeout
	time.Sleep(150 * time.Millisecond)

	// Fail in half-open should reopen
	err := cb.Execute(func() error {
		return errors.New("failure in half-open")
	})
	if err == nil {
		t.Error("expected error")
	}

	if cb.State() != StateOpen {
		t.Errorf("expected state Open after failure in half-open, got %v", cb.State())
	}
}

func TestCircuitBreakerReset(t *testing.T) {
	config := &CircuitBreakerConfig{
		FailureThreshold: 2,
		Timeout:          time.Hour, // Long timeout
	}

	cb := NewCircuitBreaker(config)

	// Open the circuit
	for i := 0; i < 2; i++ {
		_ = cb.Execute(func() error {
			return errors.New("failure")
		})
	}

	if cb.State() != StateOpen {
		t.Fatal("expected state Open")
	}

	// Manual reset
	cb.Reset()

	if cb.State() != StateClosed {
		t.Errorf("expected state Closed after reset, got %v", cb.State())
	}

	// Should allow requests again
	err := cb.Execute(func() error {
		return nil
	})
	if err != nil {
		t.Errorf("expected success after reset, got %v", err)
	}
}

func TestCircuitBreakerStats(t *testing.T) {
	config := &CircuitBreakerConfig{
		FailureThreshold: 3,
	}

	cb := NewCircuitBreaker(config)

	// Initial stats
	stats := cb.Stats()
	if stats.State != StateClosed {
		t.Errorf("expected initial state Closed in stats, got %v", stats.State)
	}
	if stats.Failures != 0 {
		t.Errorf("expected 0 initial failures, got %d", stats.Failures)
	}

	// Record some failures
	for i := 0; i < 2; i++ {
		_ = cb.Execute(func() error {
			return errors.New("failure")
		})
	}

	stats = cb.Stats()
	if stats.Failures != 2 {
		t.Errorf("expected 2 failures, got %d", stats.Failures)
	}
	if stats.State != StateClosed {
		t.Errorf("expected state Closed (not yet at threshold), got %v", stats.State)
	}
}

func TestCircuitBreakerExecuteContext(t *testing.T) {
	config := &CircuitBreakerConfig{
		FailureThreshold: 3,
		RequestTimeout:   50 * time.Millisecond,
	}

	cb := NewCircuitBreaker(config)

	// Successful execution with context
	ctx := context.Background()
	err := cb.ExecuteContext(ctx, func(ctx context.Context) error {
		return nil
	})
	if err != nil {
		t.Errorf("expected success, got %v", err)
	}

	// Test that timeout is applied
	start := time.Now()
	err = cb.ExecuteContext(ctx, func(ctx context.Context) error {
		select {
		case <-time.After(200 * time.Millisecond):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	elapsed := time.Since(start)

	if elapsed > 100*time.Millisecond {
		t.Errorf("expected timeout around 50ms, but took %v", elapsed)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context deadline exceeded, got %v", err)
	}
}

func TestCircuitBreakerManager(t *testing.T) {
	manager := NewManager()

	// Create a circuit breaker
	cb1 := manager.GetOrCreate("service1", nil)
	if cb1 == nil {
		t.Fatal("expected circuit breaker")
	}

	// Get the same one
	cb2 := manager.GetOrCreate("service1", nil)
	if cb1 != cb2 {
		t.Error("expected same circuit breaker instance")
	}

	// Get a different one
	cb3 := manager.GetOrCreate("service2", nil)
	if cb1 == cb3 {
		t.Error("expected different circuit breaker instance")
	}

	// Get existing
	cb4, exists := manager.Get("service1")
	if !exists {
		t.Error("expected circuit breaker to exist")
	}
	if cb4 != cb1 {
		t.Error("expected same instance")
	}

	// Get non-existent
	_, exists = manager.Get("nonexistent")
	if exists {
		t.Error("expected circuit breaker to not exist")
	}

	// Get all
	all := manager.All()
	if len(all) != 2 {
		t.Errorf("expected 2 circuit breakers, got %d", len(all))
	}

	// Remove
	manager.Remove("service1")
	_, exists = manager.Get("service1")
	if exists {
		t.Error("expected circuit breaker to be removed")
	}
}

func TestStateString(t *testing.T) {
	tests := []struct {
		state    State
		expected string
	}{
		{StateClosed, "closed"},
		{StateOpen, "open"},
		{StateHalfOpen, "half-open"},
		{State(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.expected {
			t.Errorf("State(%d).String() = %s, expected %s", tt.state, got, tt.expected)
		}
	}
}

func TestDefaultCircuitBreakerConfig(t *testing.T) {
	config := DefaultCircuitBreakerConfig()

	if config.FailureThreshold != 5 {
		t.Errorf("expected FailureThreshold=5, got %d", config.FailureThreshold)
	}
	if config.SuccessThreshold != 3 {
		t.Errorf("expected SuccessThreshold=3, got %d", config.SuccessThreshold)
	}
	if config.Timeout != 30*time.Second {
		t.Errorf("expected Timeout=30s, got %v", config.Timeout)
	}
}

func TestCircuitBreakerStatsString(t *testing.T) {
	stats := CircuitBreakerStats{
		State:            StateClosed,
		Failures:         2,
		Successes:        5,
		HalfOpenInFlight: 0,
	}

	s := stats.String()
	expected := "CircuitBreaker[state=closed, failures=2, successes=5, half_open_in_flight=0]"
	if s != expected {
		t.Errorf("expected %q, got %q", expected, s)
	}
}
