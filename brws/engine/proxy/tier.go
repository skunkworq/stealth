package proxy

import (
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// TieredProxy groups a pool with its tier level.
type TieredProxy struct {
	Level int // 0 = cheapest, ascending = more premium
	Pool  *Pool
	Label string // e.g., "datacenter", "residential", "mobile"
}

// domainTierState holds per-domain tier tracking.
type domainTierState struct {
	mu           sync.Mutex
	currentTier  int
	errorScore   int
	totalErrors  int
	totalSuccess int
}

// TierTracker manages per-domain proxy tier escalation.
// Inspired by Crawlee's ProxyTierTracker: +ErrorWeight on error, -SuccessWeight
// on success, escalate when score >= EscalateThreshold.
type TierTracker struct {
	tiers  []TieredProxy // ordered by Level ascending
	states sync.Map      // map[string]*domainTierState (keyed by eTLD+1)

	EscalateThreshold int // default 30: escalate when score >= threshold
	DeescalateAt      int // default -10: drop tier when score falls below this
	ErrorWeight       int // default 10: score increment per error
	SuccessWeight     int // default 1: score decrement per success
}

// NewTierTracker creates a tracker with the given ordered tier pools.
func NewTierTracker(tiers []TieredProxy) *TierTracker {
	return &TierTracker{
		tiers:             tiers,
		EscalateThreshold: 30,
		DeescalateAt:      -10,
		ErrorWeight:       10,
		SuccessWeight:     1,
	}
}

func (t *TierTracker) getState(domain string) *domainTierState {
	v, _ := t.states.LoadOrStore(domain, &domainTierState{})
	return v.(*domainTierState)
}

// Get returns a proxy for the given request URL, respecting current tier.
func (t *TierTracker) Get(rawURL string) *Proxy {
	domain := etldPlusOne(rawURL)
	state := t.getState(domain)

	state.mu.Lock()
	tier := state.currentTier
	state.mu.Unlock()

	if tier >= len(t.tiers) {
		tier = len(t.tiers) - 1
	}

	return t.tiers[tier].Pool.Get()
}

// RecordSuccess decrements the error score for the domain.
func (t *TierTracker) RecordSuccess(rawURL string, latency time.Duration) {
	domain := etldPlusOne(rawURL)
	state := t.getState(domain)

	state.mu.Lock()
	defer state.mu.Unlock()

	state.totalSuccess++
	state.errorScore -= t.SuccessWeight
	if state.errorScore < 0 {
		state.errorScore = 0
	}

	// De-escalate if score has decayed enough and we're not on tier 0
	if state.currentTier > 0 && state.errorScore <= t.DeescalateAt {
		state.currentTier--
		state.errorScore = 0 // reset after de-escalation
	}

	// Also record on the proxy pool
	proxy := t.tiers[state.currentTier].Pool.Get()
	if proxy != nil {
		t.tiers[state.currentTier].Pool.RecordSuccess(proxy.URL, latency)
	}
}

// RecordError increments the error score and potentially escalates tier.
func (t *TierTracker) RecordError(rawURL string) {
	domain := etldPlusOne(rawURL)
	state := t.getState(domain)

	state.mu.Lock()
	defer state.mu.Unlock()

	state.totalErrors++
	state.errorScore += t.ErrorWeight

	// Escalate if score exceeds threshold and we have higher tiers
	if state.errorScore >= t.EscalateThreshold && state.currentTier < len(t.tiers)-1 {
		state.currentTier++
		state.errorScore = 0 // reset after escalation
	}
}

// TierFor returns the current tier index for a domain.
func (t *TierTracker) TierFor(rawURL string) int {
	domain := etldPlusOne(rawURL)
	state := t.getState(domain)
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.currentTier
}

// DomainTierSnapshot is a read-only view of per-domain tier state.
type DomainTierSnapshot struct {
	Domain       string
	CurrentTier  int
	ErrorScore   int
	TotalErrors  int
	TotalSuccess int
}

// Stats returns a snapshot of all domain tier states.
func (t *TierTracker) Stats() map[string]DomainTierSnapshot {
	out := make(map[string]DomainTierSnapshot)
	t.states.Range(func(key, value any) bool {
		domain := key.(string)
		state := value.(*domainTierState)
		state.mu.Lock()
		out[domain] = DomainTierSnapshot{
			Domain:       domain,
			CurrentTier:  state.currentTier,
			ErrorScore:   state.errorScore,
			TotalErrors:  state.totalErrors,
			TotalSuccess: state.totalSuccess,
		}
		state.mu.Unlock()
		return true
	})
	return out
}

// etldPlusOne extracts the eTLD+1 from a raw URL.
// Falls back to raw hostname on parse errors.
func etldPlusOne(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return rawURL
	}
	host := u.Hostname()
	etld, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return host
	}
	return etld
}
