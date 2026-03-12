package behavior_test

import (
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
)

func TestPhases91_92Integration(t *testing.T) {
	detector := adversarial.NewStealthDetector()
	
	// Round 1: Force detections without evasion
	config := &behavior.RequestGeneratorConfig{
		Profile:         behavior.ChromeWindowsProfile(),
		ForceDetections: true,
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)
	
	req1 := ag.GenerateRequest("https://example.com")
	// Strip canvas to speed up test
	req1.Header.Del("X-Canvas-Fingerprint")
	
	det1 := detector.AnalyzeRequest(req1, nil)
	report1 := det1.ToDetectionReport()
	
	t.Logf("Round 1 Score: %f", report1.TotalScore)
	fired1 := report1.FiredCheckNames()
	t.Logf("Round 1 fired: %v", fired1)
	
	// We expect Worker coherence and Introspection checks to fire
	hasWorkerUA := false
	hasProxy := false
	hasToString := false
	for _, name := range fired1 {
		if name == "worker_userAgent_mismatch" {
			hasWorkerUA = true
		}
		if name == "navigator_proxy_detected" {
			hasProxy = true
		}
		if name == "native_function_toString_leak" {
			hasToString = true
		}
	}
	
	if !hasWorkerUA {
		t.Errorf("Expected worker_userAgent_mismatch in Round 1")
	}
	if !hasProxy {
		t.Errorf("Expected navigator_proxy_detected in Round 1")
	}
	if !hasToString {
		t.Errorf("Expected native_function_toString_leak in Round 1")
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
	
	// Verify that Phase 91/92 specific checks are gone
	foundMismatch := false
	for _, name := range fired2 {
		if name == "worker_userAgent_mismatch" || name == "navigator_proxy_detected" || name == "native_function_toString_leak" {
			t.Errorf("Check %s still fired after adaptive mutation in Round 2", name)
			foundMismatch = true
		}
	}
	
	if !foundMismatch {
		t.Logf("Verified: Phase 91/92 specific checks resolved in Round 2")
	}
	
	if report2.TotalScore >= report1.TotalScore && report1.TotalScore > 0 {
		t.Errorf("Score did not improve in Round 2: %f -> %f", report1.TotalScore, report2.TotalScore)
	}
	
	t.Logf("Successfully verified Phases 91 & 92 with adaptive feedback")
}
