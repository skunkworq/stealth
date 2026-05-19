// Package trust provides session and domain trust tracking primitives.
// It is imported by the stealth and crawl layers to share a common model
// of how healthy/trustworthy a given session or domain currently is.
package trust

import (
	"sync"
	"time"
)

// HealthConfig configures session health scoring thresholds.
type HealthConfig struct {
	BlockThreshold   float64 // errorScore >= this → blocked (default 3.0)
	RetireThreshold  float64 // errorScore >= this → soft-retire warning (default 1.5)
	ErrorIncrement   float64 // per bad response (default 1.0)
	SuccessDecrement float64 // per good response (default 0.5)
	MaxSignals       int     // max ban signals to retain (default 20)
}

// DefaultHealthConfig returns Crawlee-compatible defaults.
func DefaultHealthConfig() *HealthConfig {
	return &HealthConfig{
		BlockThreshold:   3.0,
		RetireThreshold:  1.5,
		ErrorIncrement:   1.0,
		SuccessDecrement: 0.5,
		MaxSignals:       20,
	}
}

// BanSignal records what triggered a health score increment.
type BanSignal struct {
	StatusCode int       `json:"status_code"`
	Domain     string    `json:"domain"`
	At         time.Time `json:"at"`
	Reason     string    `json:"reason"` // "status_403", "status_429", "waf_challenge", etc.
}

// HealthScore tracks soft-retirement state for a session.
// Score increments on bad responses and decrements on good ones,
// allowing sessions to heal from transient errors.
type HealthScore struct {
	mu         sync.Mutex
	score      float64
	cfg        *HealthConfig
	banSignals []BanSignal
}

// NewHealthScore creates a health scorer with the given config.
func NewHealthScore(cfg *HealthConfig) *HealthScore {
	if cfg == nil {
		cfg = DefaultHealthConfig()
	}
	return &HealthScore{cfg: cfg}
}

// RecordGood decrements score (floor 0).
func (h *HealthScore) RecordGood() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.score -= h.cfg.SuccessDecrement
	if h.score < 0 {
		h.score = 0
	}
}

// RecordBad increments score and appends a BanSignal.
func (h *HealthScore) RecordBad(sig BanSignal) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.score += h.cfg.ErrorIncrement
	h.banSignals = append(h.banSignals, sig)
	if len(h.banSignals) > h.cfg.MaxSignals {
		h.banSignals = h.banSignals[len(h.banSignals)-h.cfg.MaxSignals:]
	}
}

// Score returns the current raw score.
func (h *HealthScore) Score() float64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.score
}

// NormalizedScore returns score / BlockThreshold, clamped to [0, 1].
// Useful for computing trust penalties without exposing config internals.
func (h *HealthScore) NormalizedScore() float64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	v := h.score / h.cfg.BlockThreshold
	if v > 1.0 {
		return 1.0
	}
	return v
}

// IsBlocked returns true if score >= BlockThreshold.
func (h *HealthScore) IsBlocked() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.score >= h.cfg.BlockThreshold
}

// IsRetirable returns true if score >= RetireThreshold (warn, not hard-stop).
func (h *HealthScore) IsRetirable() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.score >= h.cfg.RetireThreshold
}

// Reset clears the score (call after session rotation).
func (h *HealthScore) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.score = 0
	h.banSignals = nil
}

// RecentSignals returns the last n ban signals.
func (h *HealthScore) RecentSignals(n int) []BanSignal {
	h.mu.Lock()
	defer h.mu.Unlock()
	if n > len(h.banSignals) {
		n = len(h.banSignals)
	}
	out := make([]BanSignal, n)
	copy(out, h.banSignals[len(h.banSignals)-n:])
	return out
}

// DomainStats tracks request outcomes for a single domain within a session.
type DomainStats struct {
	Domain        string    `json:"domain"`
	SuccessCount  int       `json:"success_count"`
	FailureCount  int       `json:"failure_count"`
	LastSuccess   time.Time `json:"last_success"`
	LastFailure   time.Time `json:"last_failure"`
	AvgResponseMs int64     `json:"avg_response_ms"`
}
