package proxy

import (
	"testing"
	"time"
)

func newTestTierTracker() *TierTracker {
	return NewTierTracker([]TieredProxy{
		{Level: 0, Pool: NewPool([]string{"http://dc-1:8080", "http://dc-2:8080"}, StrategyRoundRobin), Label: "datacenter"},
		{Level: 1, Pool: NewPool([]string{"http://res-1:8080"}, StrategyRoundRobin), Label: "residential"},
		{Level: 2, Pool: NewPool([]string{"http://mobile-1:8080"}, StrategyRoundRobin), Label: "mobile"},
	})
}

func TestTierTracker_StartsAtTier0(t *testing.T) {
	tt := newTestTierTracker()
	tier := tt.TierFor("https://example.com/page")
	if tier != 0 {
		t.Errorf("initial tier = %d, want 0", tier)
	}
}

func TestTierTracker_EscalatesOnErrors(t *testing.T) {
	tt := newTestTierTracker()
	url := "https://example.com/api"

	// Default threshold is 30, error weight is 10 → 3 errors to escalate
	tt.RecordError(url)
	tt.RecordError(url)
	if tt.TierFor(url) != 0 {
		t.Errorf("should still be tier 0 after 2 errors")
	}
	tt.RecordError(url)
	if tt.TierFor(url) != 1 {
		t.Errorf("should escalate to tier 1 after 3 errors, got %d", tt.TierFor(url))
	}
}

func TestTierTracker_DoubleEscalation(t *testing.T) {
	tt := newTestTierTracker()
	url := "https://example.com/api"

	// Escalate to tier 1
	for i := 0; i < 3; i++ {
		tt.RecordError(url)
	}
	if tt.TierFor(url) != 1 {
		t.Fatalf("expected tier 1, got %d", tt.TierFor(url))
	}

	// Escalate to tier 2
	for i := 0; i < 3; i++ {
		tt.RecordError(url)
	}
	if tt.TierFor(url) != 2 {
		t.Errorf("expected tier 2, got %d", tt.TierFor(url))
	}
}

func TestTierTracker_CapsAtMaxTier(t *testing.T) {
	tt := newTestTierTracker()
	url := "https://example.com/api"

	// Max out at tier 2 (3 tiers total)
	for i := 0; i < 20; i++ {
		tt.RecordError(url)
	}
	if tt.TierFor(url) != 2 {
		t.Errorf("should cap at max tier 2, got %d", tt.TierFor(url))
	}
}

func TestTierTracker_SuccessDecaysScore(t *testing.T) {
	tt := newTestTierTracker()
	url := "https://example.com/api"

	// Add some errors but not enough to escalate
	tt.RecordError(url)
	tt.RecordError(url)
	// Score is now 20, threshold is 30

	// 20 successes should decay score to 0
	for i := 0; i < 20; i++ {
		tt.RecordSuccess(url, 100*time.Millisecond)
	}
	// Score should be 0 (floor)
	if tt.TierFor(url) != 0 {
		t.Errorf("should remain at tier 0 after decay")
	}
}

func TestTierTracker_DomainIsolation(t *testing.T) {
	tt := newTestTierTracker()

	// Escalate domain A (different eTLD+1)
	for i := 0; i < 3; i++ {
		tt.RecordError("https://bad.badsite.com/api")
	}

	// Domain B should be unaffected (different eTLD+1)
	if tt.TierFor("https://good.example.com/page") != 0 {
		t.Error("different eTLD+1 should have independent tier state")
	}
}

func TestTierTracker_ETLDPlusOne(t *testing.T) {
	tt := newTestTierTracker()

	// Subdomains of the same eTLD+1 should share tier state
	for i := 0; i < 3; i++ {
		tt.RecordError("https://api.shop.example.com/v1")
	}
	// Same eTLD+1
	tier := tt.TierFor("https://www.example.com/home")
	if tier != 1 {
		t.Errorf("same eTLD+1 should share tier state, got tier %d", tier)
	}
}

func TestTierTracker_Get(t *testing.T) {
	tt := newTestTierTracker()
	proxy := tt.Get("https://example.com/page")
	if proxy == nil {
		t.Fatal("expected proxy from tier 0")
	}
	// Should be from datacenter pool
	if proxy.URL != "http://dc-1:8080" && proxy.URL != "http://dc-2:8080" {
		t.Errorf("unexpected proxy URL: %s", proxy.URL)
	}
}

func TestTierTracker_Stats(t *testing.T) {
	tt := newTestTierTracker()
	tt.RecordError("https://a.com/x")
	tt.RecordSuccess("https://b.com/y", 50*time.Millisecond)

	stats := tt.Stats()
	if len(stats) != 2 {
		t.Errorf("expected 2 domains in stats, got %d", len(stats))
	}
	if stats["a.com"].TotalErrors != 1 {
		t.Errorf("a.com errors = %d, want 1", stats["a.com"].TotalErrors)
	}
	if stats["b.com"].TotalSuccess != 1 {
		t.Errorf("b.com success = %d, want 1", stats["b.com"].TotalSuccess)
	}
}
