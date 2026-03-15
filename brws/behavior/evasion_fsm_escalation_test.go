package behavior

import (
	"net/http"
	"testing"
)

// TestFSM_Exhausted_AllStrategiesFail verifies that when all 12 strategies
// are detected at >50%, the FSM signals exhaustion.
func TestFSM_Exhausted_AllStrategiesFail(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM()
	strategies := DefaultStrategies()

	// Run 3 detected trials per strategy to advance through all of them
	for i := 0; i < len(strategies)*3; i++ {
		fsm.RecordResult(0.8, true)
	}

	if !fsm.Exhausted() {
		t.Error("expected FSM to be exhausted after all strategies failed")
	}
	if !fsm.ShouldEscalate() {
		t.Error("expected ShouldEscalate() to be true when exhausted")
	}

	// Verify the browser_escalation transition was recorded
	transitions := fsm.Transitions()
	lastTransition := transitions[len(transitions)-1]
	if lastTransition.To != "browser_escalation" {
		t.Errorf("expected last transition to browser_escalation, got %q", lastTransition.To)
	}

	t.Logf("\n%s", fsm.Summary())
}

// TestFSM_BanSignalEscalation verifies that 3 ban signals trigger escalation.
func TestFSM_BanSignalEscalation(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM()

	// Not exhausted, but accumulate ban signals
	fsm.RecordBanSignal(403)
	fsm.RecordBanSignal(429)
	fsm.RecordBanSignal(403)

	if !fsm.ShouldEscalate() {
		t.Error("expected ShouldEscalate() after 3 ban signals")
	}
	if fsm.EscalationReason() != "ban_signals" {
		t.Errorf("expected reason 'ban_signals', got %q", fsm.EscalationReason())
	}
}

// TestFSM_BanSignalBelowThreshold verifies that fewer than 3 signals don't trigger.
func TestFSM_BanSignalBelowThreshold(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM()

	fsm.RecordBanSignal(403)
	fsm.RecordBanSignal(429)

	if fsm.ShouldEscalate() {
		t.Error("ShouldEscalate() should be false with only 2 ban signals")
	}
	if fsm.EscalationReason() != "" {
		t.Errorf("expected empty reason, got %q", fsm.EscalationReason())
	}
}

// TestFSM_ResetBanSignals verifies that resetting clears escalation from ban signals.
func TestFSM_ResetBanSignals(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM()

	fsm.RecordBanSignal(403)
	fsm.RecordBanSignal(429)
	fsm.RecordBanSignal(403)

	if !fsm.ShouldEscalate() {
		t.Fatal("expected escalation before reset")
	}

	fsm.ResetBanSignals()

	if fsm.ShouldEscalate() {
		t.Error("ShouldEscalate() should be false after ResetBanSignals()")
	}
}

// TestFSM_EscalationReason verifies the correct reason for each escalation path.
func TestFSM_EscalationReason(t *testing.T) {
	t.Run("exhaustion", func(t *testing.T) {
		fsm := NewAdaptiveEvasionFSM()
		strategies := DefaultStrategies()

		for i := 0; i < len(strategies)*3; i++ {
			fsm.RecordResult(0.8, true)
		}

		if reason := fsm.EscalationReason(); reason != "fsm_exhausted" {
			t.Errorf("expected 'fsm_exhausted', got %q", reason)
		}
	})

	t.Run("ban_signals", func(t *testing.T) {
		fsm := NewAdaptiveEvasionFSM()

		for i := 0; i < 3; i++ {
			fsm.RecordBanSignal(403)
		}

		if reason := fsm.EscalationReason(); reason != "ban_signals" {
			t.Errorf("expected 'ban_signals', got %q", reason)
		}
	})

	t.Run("both_exhaustion_wins", func(t *testing.T) {
		fsm := NewAdaptiveEvasionFSM()
		strategies := DefaultStrategies()

		for i := 0; i < len(strategies)*3; i++ {
			fsm.RecordResult(0.8, true)
		}
		for i := 0; i < 5; i++ {
			fsm.RecordBanSignal(403)
		}

		// Exhaustion takes precedence
		if reason := fsm.EscalationReason(); reason != "fsm_exhausted" {
			t.Errorf("expected 'fsm_exhausted' (precedence), got %q", reason)
		}
	})

	t.Run("no_escalation", func(t *testing.T) {
		fsm := NewAdaptiveEvasionFSM()

		if reason := fsm.EscalationReason(); reason != "" {
			t.Errorf("expected empty reason, got %q", reason)
		}
	})
}

// TestFSM_GenerateAdaptiveRequest_AllCaught verifies the self-analysis loop
// walks through all strategies and signals exhaustion when all are caught.
func TestFSM_GenerateAdaptiveRequest_AllCaught(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM()
	profile := ChromeWindowsProfile()

	calls := 0
	alwaysCaught := DetectionAnalyzer(func(req *http.Request) DetectionResult {
		calls++
		return DetectionResult{IsBot: true, Score: 0.90, Indicators: []string{"test_always_caught"}}
	})

	req := fsm.GenerateAdaptiveRequest(profile, "https://example.com/api/telemetry", alwaysCaught)
	if req == nil {
		t.Fatal("should return last request even when all caught")
	}

	if !fsm.Exhausted() {
		t.Fatal("FSM should be exhausted after all strategies caught by self-analysis")
	}
	if !fsm.ShouldEscalate() {
		t.Fatal("FSM should recommend escalation")
	}

	// Should have been called once per strategy
	numStrategies := len(DefaultStrategies())
	if calls != numStrategies {
		t.Fatalf("expected %d analyzer calls (one per strategy), got %d", numStrategies, calls)
	}

	// Should have transitions for advancing through strategies.
	// 12 strategy-to-strategy transitions (the terminal strategy just sets exhausted=true).
	transitions := fsm.Transitions()
	expectedTransitions := numStrategies - 1 // N-1 transitions between N strategies
	if len(transitions) != expectedTransitions {
		t.Fatalf("expected %d transitions, got %d", expectedTransitions, len(transitions))
	}

	t.Logf("\n%s", fsm.Summary())
}

// TestFSM_GenerateAdaptiveRequest_EarlySuccess verifies the self-analysis loop
// stops at the first strategy that evades detection.
func TestFSM_GenerateAdaptiveRequest_EarlySuccess(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM()
	profile := ChromeWindowsProfile()

	strategies := DefaultStrategies()
	targetIdx := 2
	targetStrategy := strategies[targetIdx].Name()

	calls := 0
	analyzer := DetectionAnalyzer(func(req *http.Request) DetectionResult {
		calls++
		if calls <= targetIdx {
			return DetectionResult{IsBot: true, Score: 0.80, Indicators: []string{"caught"}}
		}
		return DetectionResult{IsBot: false, Score: 0.10}
	})

	req := fsm.GenerateAdaptiveRequest(profile, "https://example.com/page", analyzer)
	if req == nil {
		t.Fatal("should return request")
	}
	if calls != targetIdx+1 {
		t.Fatalf("expected %d analyzer calls, got %d", targetIdx+1, calls)
	}
	if fsm.Exhausted() {
		t.Fatal("FSM should NOT be exhausted — found a passing strategy")
	}

	current := fsm.CurrentStrategy()
	if current.Name() != targetStrategy {
		t.Fatalf("expected current strategy %q, got %q", targetStrategy, current.Name())
	}
}

// TestFSM_GenerateAdaptiveRequest_NilAnalyzer verifies nil analyzer returns
// the first strategy's request immediately without self-analysis.
func TestFSM_GenerateAdaptiveRequest_NilAnalyzer(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM()
	profile := ChromeWindowsProfile()

	req := fsm.GenerateAdaptiveRequest(profile, "https://example.com/page", nil)
	if req == nil {
		t.Fatal("should return request with nil analyzer")
	}
	if fsm.StateIndex() != 0 {
		t.Fatal("FSM should stay at first strategy with nil analyzer")
	}
	if fsm.Exhausted() {
		t.Fatal("FSM should not be exhausted with nil analyzer")
	}
}
