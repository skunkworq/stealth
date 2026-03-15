// Package waterfall provides multi-engine racing with timeout-based tier promotion.
// Inspired by Firecrawl's waterfall pattern: start a fast engine, launch slower
// engines after delays, race all in-flight, cancel losers when a winner arrives.
package waterfall

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/skunkworq/stealth/brws/engine"
)

// Tier defines one engine level in the waterfall.
type Tier struct {
	Engine      engine.Engine
	LaunchAfter time.Duration // delay before launching this tier (0 = immediate)
	Name        string        // for logging/tracing
}

// result is the internal return type from a tier goroutine.
type result struct {
	resp *engine.Response
	err  error
	tier string
}

// Waterfall implements engine.Engine by racing multiple engines.
// Tier 0 fires immediately; subsequent tiers fire after their LaunchAfter delay.
// The first successful response wins and cancels all remaining tiers.
type Waterfall struct {
	tiers   []Tier
	mu      sync.RWMutex
	metrics WaterfallMetrics
}

// WaterfallMetrics tracks outcomes per tier.
type WaterfallMetrics struct {
	mu     sync.Mutex
	Wins   map[string]int64
	Errors map[string]int64
}

func (m *WaterfallMetrics) recordWin(tier string) {
	m.mu.Lock()
	m.Wins[tier]++
	m.mu.Unlock()
}

func (m *WaterfallMetrics) recordError(tier string) {
	m.mu.Lock()
	m.Errors[tier]++
	m.mu.Unlock()
}

// New creates a Waterfall from an ordered slice of Tiers.
// At least one tier is required.
func New(tiers ...Tier) (*Waterfall, error) {
	if len(tiers) == 0 {
		return nil, fmt.Errorf("waterfall requires at least one tier")
	}
	return &Waterfall{
		tiers: tiers,
		metrics: WaterfallMetrics{
			Wins:   make(map[string]int64),
			Errors: make(map[string]int64),
		},
	}, nil
}

// Name implements engine.Engine.
func (w *Waterfall) Name() string { return "waterfall" }

// Capabilities returns the union of all tier capabilities.
func (w *Waterfall) Capabilities() engine.Capabilities {
	w.mu.RLock()
	defer w.mu.RUnlock()
	var caps engine.Capabilities
	for _, t := range w.tiers {
		tc := t.Engine.Capabilities()
		caps.JavaScript = caps.JavaScript || tc.JavaScript
		caps.HTTP2 = caps.HTTP2 || tc.HTTP2
		caps.HTTP3 = caps.HTTP3 || tc.HTTP3
		caps.PersistentProfile = caps.PersistentProfile || tc.PersistentProfile
		caps.NetLogExport = caps.NetLogExport || tc.NetLogExport
		caps.WebSocket = caps.WebSocket || tc.WebSocket
		caps.Intercept = caps.Intercept || tc.Intercept
	}
	return caps
}

// Do races all tiers, returning the first successful response.
// Tiers are launched according to their LaunchAfter delay.
// If all tiers fail, the last error is returned.
func (w *Waterfall) Do(ctx context.Context, req *engine.Request) (*engine.Response, error) {
	w.mu.RLock()
	tiers := make([]Tier, len(w.tiers))
	copy(tiers, w.tiers)
	w.mu.RUnlock()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Buffered channel prevents goroutine leaks on early success
	ch := make(chan result, len(tiers))
	var launched atomic.Int32

	for i, tier := range tiers {
		t := tier
		if i == 0 {
			// Tier 0 fires immediately
			launched.Add(1)
			go func() {
				resp, err := t.Engine.Do(ctx, req)
				ch <- result{resp: resp, err: err, tier: t.Name}
			}()
		} else {
			// Deferred tiers wait then launch
			go func(delay time.Duration) {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
					if ctx.Err() != nil {
						return
					}
					launched.Add(1)
					resp, err := t.Engine.Do(ctx, req)
					ch <- result{resp: resp, err: err, tier: t.Name}
				case <-ctx.Done():
					return
				}
			}(t.LaunchAfter)
		}
	}

	// Wait for the maximum possible launch delay + a buffer to ensure all
	// tiers have had a chance to launch before we give up.
	maxDelay := time.Duration(0)
	for _, t := range tiers {
		if t.LaunchAfter > maxDelay {
			maxDelay = t.LaunchAfter
		}
	}

	var lastErr error
	received := 0
	deadline := time.NewTimer(maxDelay + 30*time.Second)
	defer deadline.Stop()

	for received < len(tiers) {
		select {
		case r := <-ch:
			received++
			if r.err == nil && r.resp != nil {
				cancel() // stop remaining tiers
				w.metrics.recordWin(r.tier)
				return r.resp, nil
			}
			lastErr = r.err
			w.metrics.recordError(r.tier)
		case <-ctx.Done():
			if lastErr != nil {
				return nil, fmt.Errorf("waterfall cancelled: %w", lastErr)
			}
			return nil, ctx.Err()
		case <-deadline.C:
			// Safety: don't wait forever for tiers that were cancelled
			if lastErr != nil {
				return nil, fmt.Errorf("waterfall timed out: %w", lastErr)
			}
			return nil, fmt.Errorf("waterfall timed out waiting for tiers")
		}
	}

	return nil, fmt.Errorf("all waterfall tiers failed: %w", lastErr)
}

// Close closes all underlying engines.
func (w *Waterfall) Close() error {
	w.mu.RLock()
	defer w.mu.RUnlock()
	var firstErr error
	for _, t := range w.tiers {
		if err := t.Engine.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// MetricsSnapshot is a copy-safe view of waterfall metrics.
type MetricsSnapshot struct {
	Wins   map[string]int64
	Errors map[string]int64
}

// Metrics returns a snapshot of win/error counts per tier.
func (w *Waterfall) Metrics() MetricsSnapshot {
	w.metrics.mu.Lock()
	defer w.metrics.mu.Unlock()
	snap := MetricsSnapshot{
		Wins:   make(map[string]int64, len(w.metrics.Wins)),
		Errors: make(map[string]int64, len(w.metrics.Errors)),
	}
	for k, v := range w.metrics.Wins {
		snap.Wins[k] = v
	}
	for k, v := range w.metrics.Errors {
		snap.Errors[k] = v
	}
	return snap
}

// PromoteTier moves a tier to a lower index (making it launch sooner).
// Used by anti-bot escalation to reorder tiers at runtime.
func (w *Waterfall) PromoteTier(name string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i, t := range w.tiers {
		if t.Name == name && i > 0 {
			// Swap with position 0, preserving original delays
			w.tiers[0], w.tiers[i] = w.tiers[i], w.tiers[0]
			w.tiers[0].LaunchAfter = 0
			break
		}
	}
}
