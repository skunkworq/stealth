package challenge_test

import (
	"testing"

	"github.com/skunkworq/stealth/brws/stealth/challenge"
	"github.com/skunkworq/stealth/brws/stealth/behavior"
)

func TestPhase68Integration(t *testing.T) {
	// 1. Setup Detector and Adaptive Generator
	detector := challenge.NewStealthDetector()

	// Start with a broken generator that triggers Phase 68 checks
	ag := behavior.NewAdaptiveFromBroken(nil)
	ag.GetConfig().ForceDetections = true

	// First round: Should detect missing mediaCapabilities/mediaSession
	req := ag.GenerateRequest("https://example.com")
	detection := detector.AnalyzeRequest(req, nil)
	report := detection.ToDetectionReport()

	fired := report.FiredCheckNames()
	t.Logf("Round 1: Fired checks: %v", fired)

	foundCapabilities := false
	foundSession := false
	for _, name := range fired {
		if name == "missing_navigator_mediaCapabilities" {
			foundCapabilities = true
		}
		if name == "missing_navigator_mediaSession" {
			foundSession = true
		}
	}

	if !foundCapabilities {
		t.Errorf("Expected missing_navigator_mediaCapabilities detection in round 1")
	}
	if !foundSession {
		t.Errorf("Expected missing_navigator_mediaSession detection in round 1")
	}

	// 2. Apply Feedback (Mutation)
	ag.ApplyFeedback(report)

	// Second round: Should be clean
	req2 := ag.GenerateRequest("https://example.com")
	detection2 := detector.AnalyzeRequest(req2, nil)

	fired2 := detection2.ToDetectionReport().FiredCheckNames()
	t.Logf("Round 2: Fired checks: %v", fired2)

	for _, ind := range fired2 {
		if ind == "missing_navigator_mediaCapabilities" || ind == "missing_navigator_mediaSession" {
			t.Errorf("Detection leakage in round 2: %s", ind)
		}
	}
}
