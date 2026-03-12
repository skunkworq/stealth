package behavior_test

import (
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
)

func TestPhases89_90Integration(t *testing.T) {
	detector := adversarial.NewStealthDetector()

	// Round 1: Force detections without evasion
	config := &behavior.RequestGeneratorConfig{
		Profile:         behavior.ChromeWindowsProfile(),
		ForceDetections: true,
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)

	req1 := ag.GenerateRequest("https://example.com")
	req1.Header.Del("X-Canvas-Fingerprint")
	det1 := detector.AnalyzeRequest(req1, nil)
	report1 := det1.ToDetectionReport()

	t.Logf("Round 1 Score: %f", report1.TotalScore)
	fired1 := report1.FiredCheckNames()
	t.Logf("Round 1 fired: %v", fired1)

	// We expect WebGL and Timing paint checks to fire
	hasWebGLAttrs := false
	hasPaintTiming := false
	for _, name := range fired1 {
		if name == "webgl_context_attributes_mismatch" {
			hasWebGLAttrs = true
		}
		if name == "timing_paint_mismatch" {
			hasPaintTiming = true
		}
	}

	if !hasWebGLAttrs {
		t.Errorf("Expected webgl_context_attributes_mismatch in Round 1, got %v", fired1)
	}
	if !hasPaintTiming {
		t.Errorf("Expected timing_paint_mismatch in Round 1, got %v", fired1)
	}

	// Round 2: Apply feedback (should trigger mutations)
	t.Logf("Round 2: Applying feedback...")
	ag.ApplyFeedback(report1)

	t.Logf("Round 2: Generating request...")
	req2 := ag.GenerateRequest("https://example.com")
	req2.Header.Del("X-Canvas-Fingerprint")

	t.Logf("Round 2: Analyzing request...")
	det2 := detector.AnalyzeRequest(req2, nil)
	report2 := det2.ToDetectionReport()

	t.Logf("Round 2 Score: %f", report2.TotalScore)
	fired2 := report2.FiredCheckNames()
	t.Logf("Round 2 fired: %v", fired2)

	// Verify that Phase 89/90 specific checks are gone
	foundMismatch := false
	for _, name := range fired2 {
		if name == "webgl_context_attributes_mismatch" || name == "timing_paint_mismatch" {
			t.Errorf("Check %s still fired after adaptive mutation in Round 2", name)
			foundMismatch = true
		}
	}

	if !foundMismatch {
		t.Logf("Verified: Phase 89/90 specific checks resolved in Round 2")
	}

	// Only check score improvement if Round 1 wasn't already at max/saturated
	if report1.TotalScore < 1.0 && report2.TotalScore >= report1.TotalScore {
		t.Errorf("Score did not improve in Round 2: %f -> %f", report1.TotalScore, report2.TotalScore)
	}

	t.Logf("Successfully verified Phases 89 & 90 with adaptive feedback")
}
