// Package resilience provides patterns for building resilient systems:
// retry, circuit breaker, and rate limiting.
package resilience

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"
)

// retryRand is a thread-safe random source for jitter
var (
	retryRand     *rand.Rand
	retryRandOnce sync.Once
	retryRandMu   sync.Mutex
)

func getRetryRand() *rand.Rand {
	retryRandOnce.Do(func() {
		retryRand = rand.New(rand.NewSource(time.Now().UnixNano()))
	})
	return retryRand
}

// RetryableFunc is a function that can be retried
type RetryableFunc func() error

// RetryableFuncCtx is a context-aware function that can be retried
type RetryableFuncCtx func(ctx context.Context) error

// Config configures retry behavior
type Config struct {
	MaxAttempts       int
	InitialBackoff    time.Duration
	MaxBackoff        time.Duration
	BackoffMultiplier float64
	Jitter            float64 // 0.0 to 1.0, adds randomness to backoff
	RetryableErrors   []error // Specific errors to retry on; empty = retry all
	NonRetryableErrors []error // Errors that should not be retried
}

// DefaultConfig returns sensible defaults
func DefaultConfig() *Config {
	return &Config{
		MaxAttempts:       3,
		InitialBackoff:    100 * time.Millisecond,
		MaxBackoff:        30 * time.Second,
		BackoffMultiplier: 2.0,
		Jitter:            0.1,
	}
}

// Retry executes a function with retry logic
func Retry(config *Config, fn RetryableFunc) error {
	if config == nil {
		config = DefaultConfig()
	}

	var lastErr error
	backoff := config.InitialBackoff

	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		err := fn()
		if err == nil {
			return nil
		}

		lastErr = err

		// Check if we should retry this error
		if !shouldRetry(err, config) {
			return err
		}

		// Don't sleep after the last attempt
		if attempt < config.MaxAttempts {
			sleepDuration := calculateBackoff(backoff, config.Jitter)
			time.Sleep(sleepDuration)
			backoff = minDuration(
				time.Duration(float64(backoff)*config.BackoffMultiplier),
				config.MaxBackoff,
			)
		}
	}

	return fmt.Errorf("retry exhausted after %d attempts: %w", config.MaxAttempts, lastErr)
}

// RetryContext executes a function with retry logic and context cancellation support
func RetryContext(ctx context.Context, config *Config, fn RetryableFuncCtx) error {
	if config == nil {
		config = DefaultConfig()
	}

	var lastErr error
	backoff := config.InitialBackoff

	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		// Check context before attempting
		select {
		case <-ctx.Done():
			return fmt.Errorf("retry cancelled: %w", ctx.Err())
		default:
		}

		err := fn(ctx)
		if err == nil {
			return nil
		}

		lastErr = err

		// Check if we should retry this error
		if !shouldRetry(err, config) {
			return err
		}

		// Don't sleep after the last attempt
		if attempt < config.MaxAttempts {
			sleepDuration := calculateBackoff(backoff, config.Jitter)

			timer := time.NewTimer(sleepDuration)
			select {
			case <-ctx.Done():
				timer.Stop()
				return fmt.Errorf("retry cancelled during backoff: %w", ctx.Err())
			case <-timer.C:
			}

			backoff = minDuration(
				time.Duration(float64(backoff)*config.BackoffMultiplier),
				config.MaxBackoff,
			)
		}
	}

	return fmt.Errorf("retry exhausted after %d attempts: %w", config.MaxAttempts, lastErr)
}

// shouldRetry determines if an error should be retried
func shouldRetry(err error, config *Config) bool {
	// Check non-retryable errors first
	for _, nonRetryable := range config.NonRetryableErrors {
		if errors.Is(err, nonRetryable) {
			return false
		}
	}

	// If specific retryable errors are defined, only retry those
	if len(config.RetryableErrors) > 0 {
		for _, retryable := range config.RetryableErrors {
			if errors.Is(err, retryable) {
				return true
			}
		}
		return false
	}

	// Retry all errors by default
	return true
}

// calculateBackoff calculates sleep duration with jitter
// jitter should be between 0.0 and 1.0 (values > 1.0 are clamped to 1.0)
func calculateBackoff(base time.Duration, jitter float64) time.Duration {
	if jitter <= 0 || base <= 0 {
		return base
	}

	// Clamp jitter to valid range [0, 1]
	if jitter > 1.0 {
		jitter = 1.0
	}

	jitterAmount := float64(base) * jitter
	
	retryRandMu.Lock()
	r := getRetryRand()
	jitterValue := (r.Float64()*2 - 1) * jitterAmount // Random between -jitter and +jitter
	retryRandMu.Unlock()
	
	result := float64(base) + jitterValue
	
	// Ensure result is non-negative and within reasonable bounds
	if result < 0 {
		result = 0
	}
	
	return time.Duration(result)
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// Common errors
var (
	ErrMaxRetriesExceeded = errors.New("max retries exceeded")
	ErrRetryCancelled     = errors.New("retry cancelled")
)

// RetryIfError wraps a function to retry only if it returns an error
func RetryIfError(config *Config, fn func() error) error {
	return Retry(config, fn)
}

// WithPermanentError marks an error as non-retryable
func WithPermanentError(err error) error {
	return &permanentError{err: err}
}

// IsPermanentError checks if an error is marked as permanent
func IsPermanentError(err error) bool {
	var pe *permanentError
	return errors.As(err, &pe)
}

type permanentError struct {
	err error
}

func (e *permanentError) Error() string {
	return e.err.Error()
}

func (e *permanentError) Unwrap() error {
	return e.err
}
