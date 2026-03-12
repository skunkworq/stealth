package adversarial_test

import (
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
)

func TestPhase70Integration(t *testing.T) {
	// 1. Setup Detector and Adaptive Generator
	detector := adversarial.NewStealthDetector()
	
	// Start with a broken generator that triggers Phase 70 checks
	// We'll use NewAdaptiveFromBroken if it exists, or just a default one and force detections
	config := &behavior.RequestGeneratorConfig{
		Profile:         behavior.ChromeWindowsProfile(),
		ForceDetections: true,
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)
	
	// Ensure we are in a "broken" state for Phase 70 (no evasion yet)
	ag.GetConfig().EvadeNavigatorWorkers = false
	
	// First round: Should detect missing serviceWorker/sharedWorker
	req1 := ag.GenerateRequest("https://example.com")
	det1 := detector.AnalyzeRequest(req1, nil)
	report1 := det1.ToDetectionReport()
	
	fired1 := report1.FiredCheckNames()
	t.Logf("Round 1: Fired checks: %v", fired1)
	
	foundServiceWorker := false
	foundSharedWorker := false
	for _, name := range fired1 {
		if name == "missing_navigator_serviceWorker" {
			foundServiceWorker = true
		}
		if name == "missing_navigator_sharedWorker" {
			foundSharedWorker = true
		}
	}
	
	if !foundServiceWorker {
		t.Errorf("Expected missing_navigator_serviceWorker detection in round 1")
	}
	if !foundSharedWorker {
		t.Errorf("Expected missing_navigator_sharedWorker detection in round 1")
	}
	
	// 2. Apply Feedback (Mutation)
	ag.ApplyFeedback(report1)
	
	// Second round: Should be clean
	req2 := ag.GenerateRequest("https://example.com")
	det2 := detector.AnalyzeRequest(req2, nil)
	report2 := det2.ToDetectionReport()
	
	fired2 := report2.FiredCheckNames()
	t.Logf("Round 2: Fired checks: %v", fired2)
	
	for _, ind := range fired2 {
		if ind == "missing_navigator_serviceWorker" || ind == "missing_navigator_sharedWorker" {
			t.Errorf("Detection leakage in round 2: %s", ind)
		}
	}
}
