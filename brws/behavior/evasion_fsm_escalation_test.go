package behavior

import "testing"

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
