package adversarial_test

import (
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
)

func TestPhase73Integration(t *testing.T) {
	// 1. Setup Detector and Adaptive Generator
	detector := adversarial.NewStealthDetector()

	// Start with a Chrome profile but force detections (which triggers empty plugins)
	config := &behavior.RequestGeneratorConfig{
		Profile:         behavior.ChromeWindowsProfile(),
		ForceDetections: true,
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)

	// Ensure we are in a "broken" state for Phase 73 (no evasion yet)
	ag.GetConfig().EvadePlugins = false

	// First round: Should detect missing plugins on Chrome
	req1 := ag.GenerateRequest("https://example.com")
	det1 := detector.AnalyzeRequest(req1, nil)
	report1 := det1.ToDetectionReport()

	fired1 := report1.FiredCheckNames()
	t.Logf("Round 1: Fired checks: %v", fired1)

	foundEmptyPlugins := false
	for _, name := range fired1 {
		if name == "empty_plugins" {
			foundEmptyPlugins = true
			break
		}
	}

	if !foundEmptyPlugins {
		t.Errorf("Expected empty_plugins in round 1")
	}

	// 2. Apply Feedback (Mutation)
	ag.ApplyFeedback(report1)

	// Second round: Should be clean
	req2 := ag.GenerateRequest("https://example.com")
	det2 := detector.AnalyzeRequest(req2, nil)
	report2 := det2.ToDetectionReport()

	fired2 := report2.FiredCheckNames()
	t.Logf("Round 2: Fired checks: %v", fired2)

	for _, name := range fired2 {
		if name == "empty_plugins" || name == "plugin_missing_mime_types" {
			t.Errorf("Detection leakage in round 2: %s", name)
		}
	}
}
