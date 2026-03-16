package behavior

import "testing"

func TestFSM_CaptchaDetected_TracksCount(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM()

	fsm.RecordCaptchaDetected()
	fsm.RecordCaptchaDetected()

	det, solves, failures := fsm.CaptchaStats()
	if det != 2 {
		t.Errorf("detections = %d, want 2", det)
	}
	if solves != 0 || failures != 0 {
		t.Errorf("solves=%d failures=%d, want 0/0", solves, failures)
	}
}

func TestFSM_CaptchaSolveSuccess_NoEscalation(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM()

	fsm.RecordCaptchaDetected()
	fsm.RecordCaptchaSolveResult(true)

	if fsm.ShouldEscalate() {
		t.Error("should not escalate after successful captcha solve")
	}

	_, solves, failures := fsm.CaptchaStats()
	if solves != 1 {
		t.Errorf("solves = %d, want 1", solves)
	}
	if failures != 0 {
		t.Errorf("failures = %d, want 0", failures)
	}
}

func TestFSM_CaptchaSolveExhaustion_Escalates(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM()

	// Two failures should exhaust captcha solving (default captchaMaxRetries=2)
	fsm.RecordCaptchaDetected()
	fsm.RecordCaptchaSolveResult(false)
	if fsm.ShouldEscalate() {
		t.Error("should not escalate after 1 failure")
	}

	fsm.RecordCaptchaDetected()
	fsm.RecordCaptchaSolveResult(false)
	if !fsm.ShouldEscalate() {
		t.Error("should escalate after 2 failures")
	}

	if reason := fsm.EscalationReason(); reason != "captcha_solve_exhausted" {
		t.Errorf("reason = %s, want captcha_solve_exhausted", reason)
	}
}

func TestFSM_CaptchaFailure_IncrementsbanSignals(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM()

	fsm.RecordCaptchaSolveResult(false)

	// Failed captcha also counts as a ban signal
	fsm.mu.Lock()
	bans := fsm.banSignals
	fsm.mu.Unlock()

	if bans != 1 {
		t.Errorf("banSignals = %d, want 1 (captcha failure should count as ban)", bans)
	}
}

func TestFSM_ShouldAttemptCaptcha_FalseAfterExhaustion(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM()

	if !fsm.ShouldAttemptCaptcha() {
		t.Error("should attempt captcha initially")
	}

	fsm.RecordCaptchaSolveResult(false)
	if !fsm.ShouldAttemptCaptcha() {
		t.Error("should still attempt after 1 failure")
	}

	fsm.RecordCaptchaSolveResult(false)
	if fsm.ShouldAttemptCaptcha() {
		t.Error("should not attempt after 2 failures")
	}
}

func TestFSM_CaptchaSummary_IncludesStats(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM()
	fsm.RecordCaptchaDetected()
	fsm.RecordCaptchaSolveResult(true)
	fsm.RecordCaptchaDetected()
	fsm.RecordCaptchaSolveResult(false)

	summary := fsm.Summary()
	if !contains(summary, "captcha=2/1/1") {
		t.Errorf("summary missing captcha stats: %s", summary)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestFSM_MixedEscalation_CaptchaTakesPriority(t *testing.T) {
	fsm := NewAdaptiveEvasionFSM()

	// Exhaust captcha first, then check reason priority
	fsm.RecordCaptchaSolveResult(false)
	fsm.RecordCaptchaSolveResult(false)

	// Also add a ban signal
	fsm.RecordBanSignal(403)

	reason := fsm.EscalationReason()
	if reason != "captcha_solve_exhausted" {
		t.Errorf("reason = %s, want captcha_solve_exhausted (should take priority)", reason)
	}
}
