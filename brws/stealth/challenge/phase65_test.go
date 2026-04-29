package challenge_test

import (
	"testing"

	"github.com/skunkworq/stealth/brws/stealth/challenge"
	"github.com/skunkworq/stealth/brws/stealth/behavior"
)

func TestPhase65Integration(t *testing.T) {
	// 1. Setup Detector and Adaptive Generator
	t.Logf("Creating detector and generator")
	detector := challenge.NewStealthDetector()

	// Start with a broken generator that triggers Phase 65 checks
	ag := behavior.NewAdaptiveFromBroken(nil)
	ag.GetConfig().ForceDetections = true

	// First round: Should detect missing vibrate/onLine
	t.Logf("Round 1: Generating broken request")
	req := ag.GenerateRequest("https://example.com")

	t.Logf("Round 1: Analyzing request")
	detection := detector.AnalyzeRequest(req, nil)

	t.Logf("Round 1: Converting to report")
	report := detection.ToDetectionReport()

	fired := report.FiredCheckNames()
	t.Logf("Round 1: Fired checks: %v", fired)

	foundVibrate := false
	foundOnLine := false
	for _, name := range fired {
		if name == "missing_navigator_vibrate" {
			foundVibrate = true
		}
		if name == "missing_navigator_onLine" {
			foundOnLine = true
		}
	}

	if !foundVibrate {
		t.Errorf("Expected missing_navigator_vibrate detection in round 1")
	}
	if !foundOnLine {
		t.Errorf("Expected missing_navigator_onLine detection in round 1")
	}

	// 2. Apply Feedback (Mutation)
	t.Logf("Applying feedback")
	ag.ApplyFeedback(report)

	// Second round: Should be clean
	t.Logf("Round 2: Generating fixed request")
	req2 := ag.GenerateRequest("https://example.com")

	t.Logf("Round 2: Analyzing request")
	detection2 := detector.AnalyzeRequest(req2, nil)

	fired2 := detection2.ToDetectionReport().FiredCheckNames()
	t.Logf("Round 2: Fired checks: %v", fired2)

	for _, ind := range fired2 {
		if ind == "missing_navigator_vibrate" || ind == "missing_navigator_onLine" {
			t.Errorf("Detection leakage in round 2: %s", ind)
		}
	}
}
