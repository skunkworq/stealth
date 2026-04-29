package behavior_test

import (
	"testing"

	"github.com/skunkworq/stealth/brws/stealth/challenge"
	"github.com/skunkworq/stealth/brws/stealth/behavior"
)

func TestPhases93_94Integration(t *testing.T) {
	detector := challenge.NewStealthDetector()

	// Round 1: Force detections without evasion
	config := &behavior.RequestGeneratorConfig{
		Profile:         behavior.ChromeWindowsProfile(),
		ForceDetections: true,
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)

	req1 := ag.GenerateRequest("https://example.com")
	t.Logf("X-Navigator-Data: %s", req1.Header.Get("X-Navigator-Data"))
	t.Logf("X-Audio-Data: %s", req1.Header.Get("X-Audio-Data"))
	// Strip canvas to speed up test
	req1.Header.Del("X-Canvas-Fingerprint")

	det1 := detector.AnalyzeRequest(req1, nil)
	report1 := det1.ToDetectionReport()

	t.Logf("Round 1 Score: %f", report1.TotalScore)
	fired1 := report1.FiredCheckNames()
	t.Logf("Round 1 fired: %v", fired1)

	// We expect Audio graph and Canvas geometry checks to fire
	hasOfflineContext := false
	hasCompressor := false
	hasCanvasMeasureText := false
	for _, name := range fired1 {
		if name == "missing_offline_audio_context" {
			hasOfflineContext = true
		}
		if name == "suspicious_audio_compressor_params" {
			hasCompressor = true
		}
		if name == "canvas_measureText_fixed_width_stub" {
			hasCanvasMeasureText = true
		}
	}

	if !hasOfflineContext {
		t.Errorf("Expected missing_offline_audio_context in Round 1")
	}
	if !hasCompressor {
		t.Errorf("Expected suspicious_audio_compressor_params in Round 1")
	}
	if !hasCanvasMeasureText {
		t.Errorf("Expected canvas_measureText_fixed_width_stub in Round 1")
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

	// Verify that Phase 93/94 specific checks are gone
	foundMismatch := false
	for _, name := range fired2 {
		if name == "missing_offline_audio_context" || name == "suspicious_audio_compressor_params" || name == "canvas_measureText_fixed_width_stub" {
			t.Errorf("Check %s still fired after adaptive mutation in Round 2", name)
			foundMismatch = true
		}
	}

	if !foundMismatch {
		t.Logf("Verified: Phase 93/94 specific checks resolved in Round 2")
	}

	// Only check score improvement if Round 1 wasn't already at max/saturated
	if report1.TotalScore < 1.0 && report2.TotalScore >= report1.TotalScore {
		t.Errorf("Score did not improve in Round 2: %f -> %f", report1.TotalScore, report2.TotalScore)
	}

	t.Logf("Successfully verified Phases 93 & 94 with adaptive feedback")
}
