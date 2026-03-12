package adversarial_test

import (
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
)

func TestPhase67Integration(t *testing.T) {
	// 1. Setup Detector and Adaptive Generator
	detector := adversarial.NewStealthDetector()
	
	// Start with a broken generator that triggers Phase 67 checks
	ag := behavior.NewAdaptiveFromBroken(nil)
	ag.GetConfig().ForceDetections = true
	
	// First round: Should detect missing clipboard/credentials
	req := ag.GenerateRequest("https://example.com")
	detection := detector.AnalyzeRequest(req, nil)
	report := detection.ToDetectionReport()
	
	fired := report.FiredCheckNames()
	t.Logf("Round 1: Fired checks: %v", fired)
	
	foundClipboard := false
	foundCredentials := false
	for _, name := range fired {
		if name == "missing_navigator_clipboard" {
			foundClipboard = true
		}
		if name == "missing_navigator_credentials" {
			foundCredentials = true
		}
	}
	
	if !foundClipboard {
		t.Errorf("Expected missing_navigator_clipboard detection in round 1")
	}
	if !foundCredentials {
		t.Errorf("Expected missing_navigator_credentials detection in round 1")
	}
	
	// 2. Apply Feedback (Mutation)
	ag.ApplyFeedback(report)
	
	// Second round: Should be clean
	req2 := ag.GenerateRequest("https://example.com")
	detection2 := detector.AnalyzeRequest(req2, nil)
	
	fired2 := detection2.ToDetectionReport().FiredCheckNames()
	t.Logf("Round 2: Fired checks: %v", fired2)
	
	for _, ind := range fired2 {
		if ind == "missing_navigator_clipboard" || ind == "missing_navigator_credentials" {
			t.Errorf("Detection leakage in round 2: %s", ind)
		}
	}
}
