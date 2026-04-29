package session

import (
	"testing"
	"time"
)

func TestHealthScore_Defaults(t *testing.T) {
	h := NewHealthScore(nil)
	if h.Score() != 0 {
		t.Errorf("initial score should be 0, got %f", h.Score())
	}
	if h.IsBlocked() {
		t.Error("fresh health should not be blocked")
	}
	if h.IsRetirable() {
		t.Error("fresh health should not be retirable")
	}
}

func TestHealthScore_BadIncrementsScore(t *testing.T) {
	h := NewHealthScore(nil)
	h.RecordBad(BanSignal{StatusCode: 403, Reason: "test"})
	if h.Score() != 1.0 {
		t.Errorf("score after 1 bad = %f, want 1.0", h.Score())
	}
}

func TestHealthScore_GoodDecrementsScore(t *testing.T) {
	h := NewHealthScore(nil)
	h.RecordBad(BanSignal{StatusCode: 403, Reason: "test"})
	h.RecordBad(BanSignal{StatusCode: 403, Reason: "test"})
	h.RecordGood()
	if h.Score() != 1.5 {
		t.Errorf("score after 2 bad + 1 good = %f, want 1.5", h.Score())
	}
}

func TestHealthScore_FloorAtZero(t *testing.T) {
	h := NewHealthScore(nil)
	h.RecordGood()
	h.RecordGood()
	if h.Score() != 0 {
		t.Errorf("score should not go below 0, got %f", h.Score())
	}
}

func TestHealthScore_BlockedAt3(t *testing.T) {
	h := NewHealthScore(nil)
	h.RecordBad(BanSignal{StatusCode: 429, Reason: "test"})
	h.RecordBad(BanSignal{StatusCode: 429, Reason: "test"})
	if h.IsBlocked() {
		t.Error("should not be blocked at score 2")
	}
	h.RecordBad(BanSignal{StatusCode: 429, Reason: "test"})
	if !h.IsBlocked() {
		t.Error("should be blocked at score 3")
	}
}

func TestHealthScore_RetirableAt1_5(t *testing.T) {
	h := NewHealthScore(nil)
	h.RecordBad(BanSignal{StatusCode: 403, Reason: "test"})
	if h.IsRetirable() {
		t.Error("should not be retirable at score 1")
	}
	h.RecordBad(BanSignal{StatusCode: 403, Reason: "test"})
	if !h.IsRetirable() {
		t.Error("should be retirable at score 2")
	}
}

func TestHealthScore_HealFromBlocked(t *testing.T) {
	h := NewHealthScore(nil)
	// Block it
	h.RecordBad(BanSignal{StatusCode: 429, Reason: "test"})
	h.RecordBad(BanSignal{StatusCode: 429, Reason: "test"})
	h.RecordBad(BanSignal{StatusCode: 429, Reason: "test"})
	if !h.IsBlocked() {
		t.Fatal("should be blocked")
	}
	// Heal with 6 good responses (3.0 - 6*0.5 = 0)
	for i := 0; i < 6; i++ {
		h.RecordGood()
	}
	if h.IsBlocked() {
		t.Errorf("should have healed, score = %f", h.Score())
	}
}

func TestHealthScore_Reset(t *testing.T) {
	h := NewHealthScore(nil)
	h.RecordBad(BanSignal{StatusCode: 403, Reason: "test"})
	h.RecordBad(BanSignal{StatusCode: 403, Reason: "test"})
	h.Reset()
	if h.Score() != 0 {
		t.Errorf("score after reset should be 0, got %f", h.Score())
	}
	if len(h.RecentSignals(10)) != 0 {
		t.Error("signals should be cleared after reset")
	}
}

func TestHealthScore_RecentSignals(t *testing.T) {
	h := NewHealthScore(nil)
	h.RecordBad(BanSignal{StatusCode: 403, Domain: "a.com", At: time.Now(), Reason: "test1"})
	h.RecordBad(BanSignal{StatusCode: 429, Domain: "b.com", At: time.Now(), Reason: "test2"})

	signals := h.RecentSignals(5)
	if len(signals) != 2 {
		t.Fatalf("expected 2 signals, got %d", len(signals))
	}
	if signals[0].Reason != "test1" {
		t.Errorf("first signal reason = %s, want test1", signals[0].Reason)
	}
}
