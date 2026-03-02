package resilience

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// State represents the circuit breaker state
type State int

const (
	// StateClosed - circuit is closed, requests flow through
	StateClosed State = iota
	// StateOpen - circuit is open, requests fail fast
	StateOpen
	// StateHalfOpen - circuit is testing if the service recovered
	StateHalfOpen
)

func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// StateChangeHandler is called when the circuit breaker changes state
type StateChangeHandler func(from, to State)

// CircuitBreaker prevents cascading failures by stopping requests to failing services
type CircuitBreaker struct {
	name string

	// Config
	failureThreshold       int
	successThreshold       int
	timeout                time.Duration
	requestTimeout         time.Duration
	maxHalfOpenRequests    int // Max concurrent requests in half-open state (default: 1)

	// State
	state            State
	failures         int
	successes        int
	lastFailure      time.Time
	stateChanged     time.Time
	halfOpenInFlight int // Current requests in half-open state

	// Hooks
	onStateChange StateChangeHandler

	mu sync.RWMutex
}

// CircuitBreakerConfig configures the circuit breaker
type CircuitBreakerConfig struct {
	Name                string
	FailureThreshold    int           // Number of failures before opening
	SuccessThreshold    int           // Number of successes in half-open to close
	Timeout             time.Duration // Duration to wait before trying half-open
	RequestTimeout      time.Duration // Timeout for individual requests
	MaxHalfOpenRequests int           // Max concurrent requests in half-open (default: 1)
	OnStateChange       StateChangeHandler // Called on state transitions
}

// DefaultCircuitBreakerConfig returns sensible defaults
func DefaultCircuitBreakerConfig() *CircuitBreakerConfig {
	return &CircuitBreakerConfig{
		FailureThreshold:    5,
		SuccessThreshold:    3,
		Timeout:             30 * time.Second,
		RequestTimeout:      10 * time.Second,
		MaxHalfOpenRequests: 1,
	}
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(config *CircuitBreakerConfig) *CircuitBreaker {
	if config == nil {
		config = DefaultCircuitBreakerConfig()
	}

	cb := &CircuitBreaker{
		name:                config.Name,
		failureThreshold:    config.FailureThreshold,
		successThreshold:    config.SuccessThreshold,
		timeout:             config.Timeout,
		requestTimeout:      config.RequestTimeout,
		maxHalfOpenRequests: config.MaxHalfOpenRequests,
		onStateChange:       config.OnStateChange,
		state:               StateClosed,
		stateChanged:        time.Now(),
	}
	
	if cb.maxHalfOpenRequests <= 0 {
		cb.maxHalfOpenRequests = 1
	}
	
	return cb
}

// Execute runs a function with circuit breaker protection
func (cb *CircuitBreaker) Execute(fn func() error) error {
	if err := cb.canExecute(); err != nil {
		return err
	}
	
	// Ensure half-open slot is released even on panic
	defer cb.releaseHalfOpenSlot()

	err := fn()
	cb.recordResult(err)
	return err
}

// ExecuteContext runs a function with circuit breaker protection and context
func (cb *CircuitBreaker) ExecuteContext(ctx context.Context, fn func(ctx context.Context) error) error {
	if err := cb.canExecute(); err != nil {
		return err
	}

	// Ensure half-open slot is released even on panic
	defer cb.releaseHalfOpenSlot()

	// Apply request timeout if not already set
	if cb.requestTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cb.requestTimeout)
		defer cancel()
	}

	err := fn(ctx)
	cb.recordResult(err)
	return err
}

// canExecute checks if the request can proceed
func (cb *CircuitBreaker) canExecute() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		return nil

	case StateOpen:
		// Check if timeout has passed to transition to half-open
		if time.Since(cb.stateChanged) > cb.timeout {
			cb.transitionTo(StateHalfOpen)
			cb.halfOpenInFlight++
			return nil
		}
		return ErrCircuitOpen

	case StateHalfOpen:
		// Allow limited requests through in half-open state
		if cb.halfOpenInFlight >= cb.maxHalfOpenRequests {
			return ErrCircuitOpen
		}
		cb.halfOpenInFlight++
		return nil

	default:
		return nil
	}
}

// releaseHalfOpenSlot decrements the half-open in-flight counter
func (cb *CircuitBreaker) releaseHalfOpenSlot() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.halfOpenInFlight > 0 {
		cb.halfOpenInFlight--
	}
}

// recordResult updates state based on success/failure
func (cb *CircuitBreaker) recordResult(err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		if err != nil {
			cb.failures++
			cb.lastFailure = time.Now()
			if cb.failures >= cb.failureThreshold {
				cb.transitionTo(StateOpen)
			}
		} else {
			// Reset failures on success
			cb.failures = 0
		}

	case StateHalfOpen:
		if err != nil {
			cb.transitionTo(StateOpen)
		} else {
			cb.successes++
			if cb.successes >= cb.successThreshold {
				cb.transitionTo(StateClosed)
			}
		}

	case StateOpen:
		// Should not happen
	}
}

// transitionTo changes the circuit breaker state
func (cb *CircuitBreaker) transitionTo(newState State) {
	oldState := cb.state
	if oldState == newState {
		return
	}
	
	cb.state = newState
	cb.stateChanged = time.Now()

	switch newState {
	case StateClosed:
		cb.failures = 0
		cb.successes = 0
		cb.halfOpenInFlight = 0
	case StateOpen:
		cb.successes = 0
		cb.halfOpenInFlight = 0
	case StateHalfOpen:
		cb.failures = 0
		cb.successes = 0
	}
	
	// Call state change hook outside of lock to avoid deadlock
	if cb.onStateChange != nil {
		cb.onStateChange(oldState, newState)
	}
}

// State returns the current state
func (cb *CircuitBreaker) State() State {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// Stats returns current statistics
func (cb *CircuitBreaker) Stats() CircuitBreakerStats {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	return CircuitBreakerStats{
		State:            cb.state,
		Failures:         cb.failures,
		Successes:        cb.successes,
		LastFailure:      cb.lastFailure,
		StateChanged:     cb.stateChanged,
		HalfOpenInFlight: cb.halfOpenInFlight,
	}
}

// Reset manually resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.transitionTo(StateClosed)
}

// CircuitBreakerStats contains circuit breaker statistics
type CircuitBreakerStats struct {
	State            State
	Failures         int
	Successes        int
	LastFailure      time.Time
	StateChanged     time.Time
	HalfOpenInFlight int // Current requests in half-open state
}

// Errors
var (
	ErrCircuitOpen = errors.New("circuit breaker is open")
)

// String returns a formatted string representation of stats
func (s CircuitBreakerStats) String() string {
	return fmt.Sprintf("CircuitBreaker[state=%s, failures=%d, successes=%d, half_open_in_flight=%d]",
		s.State, s.Failures, s.Successes, s.HalfOpenInFlight)
}

// Manager manages multiple circuit breakers
type Manager struct {
	breakers map[string]*CircuitBreaker
	mu       sync.RWMutex
}

// NewManager creates a new circuit breaker manager
func NewManager() *Manager {
	return &Manager{
		breakers: make(map[string]*CircuitBreaker),
	}
}

// GetOrCreate gets or creates a circuit breaker
func (m *Manager) GetOrCreate(name string, config *CircuitBreakerConfig) *CircuitBreaker {
	m.mu.Lock()
	defer m.mu.Unlock()

	if cb, exists := m.breakers[name]; exists {
		return cb
	}

	if config == nil {
		config = DefaultCircuitBreakerConfig()
	}
	config.Name = name

	cb := NewCircuitBreaker(config)
	m.breakers[name] = cb
	return cb
}

// Get gets a circuit breaker by name
func (m *Manager) Get(name string) (*CircuitBreaker, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cb, exists := m.breakers[name]
	return cb, exists
}

// Remove removes a circuit breaker
func (m *Manager) Remove(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.breakers, name)
}

// All returns all circuit breakers
func (m *Manager) All() map[string]*CircuitBreaker {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*CircuitBreaker, len(m.breakers))
	for k, v := range m.breakers {
		result[k] = v
	}
	return result
}
