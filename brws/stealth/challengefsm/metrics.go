package challengefsm

import (
	"sync"
	"time"
)

// SolveMetrics tracks per-provider success rates and timing for challenge solves.
type SolveMetrics struct {
	mu        sync.RWMutex
	providers map[string]*ProviderMetrics
}

// ProviderMetrics holds metrics for a single provider.
type ProviderMetrics struct {
	TotalAttempts   int
	SuccessCount    int
	FailureCount    int
	TotalDuration   time.Duration
	LastAttemptTime time.Time
}

// NewSolveMetrics creates a new metrics tracker.
func NewSolveMetrics() *SolveMetrics {
	return &SolveMetrics{
		providers: make(map[string]*ProviderMetrics),
	}
}

// Record records the result of a solve attempt.
func (m *SolveMetrics) Record(provider string, success bool, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	pm, ok := m.providers[provider]
	if !ok {
		pm = &ProviderMetrics{}
		m.providers[provider] = pm
	}

	pm.TotalAttempts++
	pm.TotalDuration += duration
	pm.LastAttemptTime = time.Now()
	if success {
		pm.SuccessCount++
	} else {
		pm.FailureCount++
	}
}

// SuccessRate returns the success rate for a provider (0.0-1.0).
// Returns 0.0 if the provider has no recorded attempts.
func (m *SolveMetrics) SuccessRate(provider string) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pm, ok := m.providers[provider]
	if !ok || pm.TotalAttempts == 0 {
		return 0.0
	}
	return float64(pm.SuccessCount) / float64(pm.TotalAttempts)
}

// AverageDuration returns the average solve duration for a provider.
func (m *SolveMetrics) AverageDuration(provider string) time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pm, ok := m.providers[provider]
	if !ok || pm.TotalAttempts == 0 {
		return 0
	}
	return pm.TotalDuration / time.Duration(pm.TotalAttempts)
}

// GetProviderMetrics returns a copy of metrics for a specific provider.
func (m *SolveMetrics) GetProviderMetrics(provider string) *ProviderMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pm, ok := m.providers[provider]
	if !ok {
		return &ProviderMetrics{}
	}
	// Return a copy
	return &ProviderMetrics{
		TotalAttempts:   pm.TotalAttempts,
		SuccessCount:    pm.SuccessCount,
		FailureCount:    pm.FailureCount,
		TotalDuration:   pm.TotalDuration,
		LastAttemptTime: pm.LastAttemptTime,
	}
}

// AllProviders returns metrics for all providers.
func (m *SolveMetrics) AllProviders() map[string]*ProviderMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*ProviderMetrics, len(m.providers))
	for k, v := range m.providers {
		result[k] = &ProviderMetrics{
			TotalAttempts:   v.TotalAttempts,
			SuccessCount:    v.SuccessCount,
			FailureCount:    v.FailureCount,
			TotalDuration:   v.TotalDuration,
			LastAttemptTime: v.LastAttemptTime,
		}
	}
	return result
}
