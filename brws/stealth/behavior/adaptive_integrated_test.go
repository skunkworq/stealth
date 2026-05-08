package behavior_test

import (
	"testing"
	"github.com/skunkworq/stealth/brws/stealth/behavior"
	"github.com/skunkworq/stealth/brws/stealth/challenge"
)

// From phase85_86_test.go
func TestPhases85_86Integration(t *testing.T) {
	// We'll use an Android profile to test both Touch and Orientation Locking
	profile := behavior.AndroidPixelProfile()

	// 1. Initial State: Forcing detections
	config := &behavior.RequestGeneratorConfig{
		Profile:         profile,
		ForceDetections: true,
	}

	ag := behavior.NewAdaptiveRequestGenerator(config)
	detector := challenge.NewStealthDetector()

	// Round 1: Check that detections fire when they should (simulating "broken" state)
	req1 := ag.GenerateRequest("https://example.com")
	det1 := detector.AnalyzeRequest(req1, nil)
	report1 := det1.ToDetectionReport()

	hasTouchMismatch := false
	hasOrientationMismatch := false
	for _, v := range report1.Vectors {
		for _, c := range v.Checks {
			if c.Fired {
				if c.Name == "touch_pointer_mismatch" {
					hasTouchMismatch = true
				}
				if c.Name == "missing_orientation_lock" {
					hasOrientationMismatch = true
				}
			}
		}
	}

	if !hasTouchMismatch {
		t.Errorf("Phase 85 detection failed: missing touch_pointer_mismatch")
	}
	if !hasOrientationMismatch {
		t.Errorf("Phase 86 detection failed: missing missing_orientation_lock")
	}

	// Round 2: Apply feedback and verify fix
	ag.ApplyFeedback(report1)
	req2 := ag.GenerateRequest("https://example.com")
	det2 := detector.AnalyzeRequest(req2, nil)
	report2 := det2.ToDetectionReport()

	for _, v := range report2.Vectors {
		for _, c := range v.Checks {
			if c.Fired {
				if c.Name == "touch_pointer_mismatch" {
					t.Errorf("Phase 85 hardening failed: touch_pointer_mismatch still fires")
				}
				if c.Name == "missing_orientation_lock" {
					t.Errorf("Phase 86 hardening failed: missing_orientation_lock still fires")
				}
			}
		}
	}

	t.Logf("Successfully verified Phase 85 & 86 with adaptive feedback")
}

// From phase87_88_test.go
func TestPhases87_88Integration(t *testing.T) {
	detector := challenge.NewStealthDetector()

	// Round 1: Force detections without evasion
	// Use a profile that definitely has 8GB+ memory to trigger coherence check
	profile := behavior.ChromeWindowsProfile()
	profile.DeviceMemory = []int{16} // Force 16GB

	config := &behavior.RequestGeneratorConfig{
		Profile:         profile,
		ForceDetections: true,
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)

	req1 := ag.GenerateRequest("https://example.com")
	det1 := detector.AnalyzeRequest(req1, nil)
	report1 := det1.ToDetectionReport()

	t.Logf("Round 1 Score: %f", report1.TotalScore)
	fired1 := report1.FiredCheckNames()
	t.Logf("Round 1 fired: %v", fired1)

	// We expect network and storage checks to fire
	hasNetwork := false
	hasStorage := false
	for _, name := range fired1 {
		if name == "network_high_downlink_low_efftype" || name == "suspicious_desktop_savedata" {
			hasNetwork = true
		}
		if name == "storage_quota_memory_mismatch" || name == "low_storage_quota" {
			hasStorage = true
		}
	}

	if !hasNetwork {
		t.Errorf("Expected network-related detections in Round 1, got %v", fired1)
	}
	if !hasStorage {
		t.Errorf("Expected storage-related detections in Round 1, got %v", fired1)
	}

	// Round 2: Apply feedback (should trigger mutations)
	ag.ApplyFeedback(report1)
	ag.GetConfig().ForceDetections = false

	req2 := ag.GenerateRequest("https://example.com")
	det2 := detector.AnalyzeRequest(req2, nil)
	report2 := det2.ToDetectionReport()

	t.Logf("Round 2 Score: %f", report2.TotalScore)
	fired2 := report2.FiredCheckNames()
	t.Logf("Round 2 fired: %v", fired2)

	// Verify that Phase 87/88 specific checks are gone
	for _, name := range fired2 {
		if name == "network_high_downlink_low_efftype" ||
			name == "suspicious_desktop_savedata" ||
			name == "storage_quota_memory_mismatch" ||
			name == "low_storage_quota" {
			t.Errorf("Check %s still fired after adaptive mutation in Round 2", name)
		}
	}

	// Only check score improvement if Round 1 wasn't already at max/saturated
	if report1.TotalScore < 1.0 && report2.TotalScore >= report1.TotalScore {
		t.Errorf("Score did not improve in Round 2: %f -> %f", report1.TotalScore, report2.TotalScore)
	}

	t.Logf("Successfully verified Phases 87 & 88 with adaptive feedback")
}

// From phase89_90_test.go
func TestPhases89_90Integration(t *testing.T) {
	detector := challenge.NewStealthDetector()

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

// From phase91_92_test.go
func TestPhases91_92Integration(t *testing.T) {
	detector := challenge.NewStealthDetector()

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

	// Only check score improvement if Round 1 wasn't already at max/saturated
	if report1.TotalScore < 1.0 && report2.TotalScore >= report1.TotalScore {
		t.Errorf("Score did not improve in Round 2: %f -> %f", report1.TotalScore, report2.TotalScore)
	}

	t.Logf("Successfully verified Phases 91 & 92 with adaptive feedback")
}

// From phase93_94_test.go
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

// From phase95_96_test.go
func TestPhases95_96Integration(t *testing.T) {
	profiles := behavior.DefaultProfiles()
	var chromeProfile *behavior.BrowserProfile
	for _, p := range profiles {
		if p.Browser == "chrome" && p.Platform == "windows" {
			chromeProfile = p
			break
		}
	}

	config := &behavior.RequestGeneratorConfig{
		Profile:         chromeProfile,
		ForceDetections: true,
	}

	ag := behavior.NewAdaptiveRequestGenerator(config)

	// Round 1: Trigger detections
	req1 := ag.GenerateRequest("https://example.com")

	detector := challenge.NewStealthDetector()
	det1 := detector.AnalyzeRequest(req1, nil)
	report1 := det1.ToDetectionReport()

	t.Logf("Round 1 Score: %f", report1.TotalScore)
	fired1 := report1.FiredCheckNames()
	t.Logf("Round 1 fired: %v", fired1)

	// Verify required detections are present
	required := []string{
		"math_precision_stubbed",
		"inconsistent_userAgentData_arch",
		"inconsistent_userAgentData_bitness",
		"inconsistent_userAgentData_fullVersionList",
	}

	for _, r := range required {
		found := false
		for _, ind := range fired1 {
			if ind == r {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected indicator %s not found in Round 1", r)
		}
	}

	// Round 2: Apply feedback and regenerate
	t.Logf("Round 2: Applying feedback...")
	ag.ApplyFeedback(report1)

	req2 := ag.GenerateRequest("https://example.com")
	det2 := detector.AnalyzeRequest(req2, nil)
	report2 := det2.ToDetectionReport()

	t.Logf("Round 2 Score: %f", report2.TotalScore)
	fired2 := report2.FiredCheckNames()
	t.Logf("Round 2 fired: %v", fired2)
	t.Logf("Sec-CH-UA-Full-Version-List: %s", req2.Header.Get("Sec-CH-UA-Full-Version-List"))

	navDataRaw := req2.Header.Get("X-Navigator-Data")
	t.Logf("X-Navigator-Data: %s", navDataRaw)

	// Verify Phase 95/96 specific checks are resolved
	for _, r := range required {
		found := false
		for _, ind := range fired2 {
			if ind == r {
				found = true
				break
			}
		}
		if found {
			t.Errorf("Indicator %s still present in Round 2 after feedback", r)
		}
	}

	if report1.TotalScore < 1.0 && report2.TotalScore >= report1.TotalScore {
		t.Errorf("Score did not improve in Round 2: %f -> %f", report1.TotalScore, report2.TotalScore)
	}

	t.Logf("Successfully verified Phases 95 & 96 with adaptive feedback")
}
