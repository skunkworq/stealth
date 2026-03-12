package resilience

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRetrySuccess(t *testing.T) {
	config := &Config{
		MaxAttempts:    3,
		InitialBackoff: 10 * time.Millisecond,
	}

	callCount := 0
	err := Retry(config, func() error {
		callCount++
		return nil
	})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if callCount != 1 {
		t.Errorf("expected 1 call, got %d", callCount)
	}
}

func TestRetryEventuallySucceeds(t *testing.T) {
	config := &Config{
		MaxAttempts:    3,
		InitialBackoff: 10 * time.Millisecond,
	}

	callCount := 0
	err := Retry(config, func() error {
		callCount++
		if callCount < 2 {
			return errors.New("temporary error")
		}
		return nil
	})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if callCount != 2 {
		t.Errorf("expected 2 calls, got %d", callCount)
	}
}

func TestRetryExhausted(t *testing.T) {
	config := &Config{
		MaxAttempts:    3,
		InitialBackoff: 10 * time.Millisecond,
	}

	callCount := 0
	expectedErr := errors.New("persistent error")
	err := Retry(config, func() error {
		callCount++
		return expectedErr
	})

	if err == nil {
		t.Error("expected error, got nil")
	}
	if callCount != 3 {
		t.Errorf("expected 3 calls, got %d", callCount)
	}
}

func TestRetryContextCancellation(t *testing.T) {
	config := &Config{
		MaxAttempts:    5,
		InitialBackoff: 100 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	callCount := 0
	err := RetryContext(ctx, config, func(ctx context.Context) error {
		callCount++
		return errors.New("error")
	})

	if err == nil {
		t.Error("expected error, got nil")
	}
	if callCount < 1 {
		t.Error("expected at least 1 call")
	}
}

func TestRetryNonRetryableError(t *testing.T) {
	permanentErr := errors.New("permanent error")
	config := &Config{
		MaxAttempts:        3,
		InitialBackoff:     10 * time.Millisecond,
		NonRetryableErrors: []error{permanentErr},
	}

	callCount := 0
	err := Retry(config, func() error {
		callCount++
		return permanentErr
	})

	if err == nil {
		t.Error("expected error, got nil")
	}
	if callCount != 1 {
		t.Errorf("expected 1 call (non-retryable), got %d", callCount)
	}
}

func TestRetryOnlyRetryableErrors(t *testing.T) {
	retryableErr := errors.New("retryable error")
	nonRetryableErr := errors.New("non-retryable error")
	config := &Config{
		MaxAttempts:     3,
		InitialBackoff:  10 * time.Millisecond,
		RetryableErrors: []error{retryableErr},
	}

	// Should not retry non-retryable error
	callCount := 0
	err := Retry(config, func() error {
		callCount++
		return nonRetryableErr
	})

	if err == nil {
		t.Error("expected error, got nil")
	}
	if callCount != 1 {
		t.Errorf("expected 1 call (not in retryable list), got %d", callCount)
	}

	// Should retry retryable error
	callCount = 0
	_ = Retry(config, func() error {
		callCount++
		return retryableErr
	})

	if callCount != 3 {
		t.Errorf("expected 3 calls (retryable), got %d", callCount)
	}
}

func TestCalculateBackoff(t *testing.T) {
	base := 100 * time.Millisecond
	jitter := 0.2

	// Run multiple times to account for randomness
	for i := 0; i < 100; i++ {
		backoff := calculateBackoff(base, jitter)

		// Should be within jitter range
		minBackoff := time.Duration(float64(base) * (1 - jitter))
		maxBackoff := time.Duration(float64(base) * (1 + jitter))

		if backoff < minBackoff || backoff > maxBackoff {
			t.Errorf("backoff %v outside expected range [%v, %v]", backoff, minBackoff, maxBackoff)
		}
	}
}

func TestPermanentError(t *testing.T) {
	originalErr := errors.New("original error")
	permanent := WithPermanentError(originalErr)

	if !IsPermanentError(permanent) {
		t.Error("expected permanent error")
	}

	if IsPermanentError(originalErr) {
		t.Error("original error should not be permanent")
	}

	if !errors.Is(permanent, originalErr) {
		t.Error("permanent error should wrap original")
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.MaxAttempts != 3 {
		t.Errorf("expected MaxAttempts=3, got %d", config.MaxAttempts)
	}
	if config.InitialBackoff != 100*time.Millisecond {
		t.Errorf("expected InitialBackoff=100ms, got %v", config.InitialBackoff)
	}
	if config.BackoffMultiplier != 2.0 {
		t.Errorf("expected BackoffMultiplier=2.0, got %f", config.BackoffMultiplier)
	}
}

func TestNilConfig(t *testing.T) {
	callCount := 0
	err := Retry(nil, func() error {
		callCount++
		return nil
	})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if callCount != 1 {
		t.Errorf("expected 1 call, got %d", callCount)
	}
}
