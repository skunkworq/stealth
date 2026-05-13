package challenge_test

import (
	"encoding/json"
	"strings"
	"testing"
	"github.com/skunkworq/stealth/brws/core/constants"
	"github.com/skunkworq/stealth/brws/stealth/behavior"
	"github.com/skunkworq/stealth/brws/stealth/challenge"
)

// From phase54_test.go
func TestPhase54AdaptiveLoop(t *testing.T) {
	// 1. Setup Adaptive Generator
	config := &behavior.RequestGeneratorConfig{
		Profile:         behavior.ChromeWindowsProfile(),
		ForceDetections: true,
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)
	detector := challenge.NewStealthDetector()

	// 2. Round 1: deterministically trigger the phase checks, then adapt.
	hReq := ag.GenerateRequest("https://example.com/")
	detection := detector.AnalyzeRequest(hReq, nil)

	var batteryFound, storageFound bool
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.Contains(ind, "suspicious_battery_status") {
				batteryFound = true
			}
			if strings.Contains(ind, "low_storage_quota") || strings.Contains(ind, "missing_storage_quota") {
				storageFound = true
			}
		}
	}

	if !batteryFound || !storageFound {
		t.Fatalf("expected forced detections for battery and storage, got battery=%v storage=%v", batteryFound, storageFound)
	}

	ag.ApplyFeedback(detection.ToDetectionReport())
	ag.GetConfig().ForceDetections = false

	// 3. Final Verification: Generate and Verify Evasion
	hReq2 := ag.GenerateRequest("https://example.com/")

	// Check Navigator Data
	navJSON := hReq2.Header.Get(constants.HeaderNavigatorData)
	var navData map[string]interface{}
	json.Unmarshal([]byte(navJSON), &navData)

	battery := navData["battery_status"].(map[string]interface{})
	level := battery["level"].(float64)
	charging := battery["charging"].(bool)
	chargingTime := battery["chargingTime"].(float64)

	if level == 1.0 && charging && chargingTime == 0.0 {
		t.Errorf("Round 2 still has suspicious battery status after mutation")
	}

	quota := navData["storage_quota"].(float64)
	if quota <= 1024*1024 {
		t.Errorf("Round 2 still has low storage quota: %.0f bytes", quota)
	}

	// 4. Final verification via Detector
	detection2 := detector.AnalyzeRequest(hReq2, nil)
	for _, ind := range detection2.Indicators {
		if strings.Contains(ind.Name, "suspicious_battery_status") ||
			strings.Contains(ind.Name, "low_storage_quota") ||
			strings.Contains(ind.Name, "missing_storage_quota") {
			t.Errorf("Round 2 still flagged with indicator: %s", ind.Name)
		}
	}
}

// From phase72_test.go
func TestPhase72Integration(t *testing.T) {
	// 1. Setup Detector and Adaptive Generator
	detector := challenge.NewStealthDetector()

	// Start with a broken generator that triggers Phase 72 checks
	config := &behavior.RequestGeneratorConfig{
		Profile:         behavior.ChromeWindowsProfile(),
		ForceDetections: true,
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)

	// Ensure we are in a "broken" state for Phase 72 (no evasion yet)
	ag.GetConfig().EvadeTimingDeepAnalysis = false

	// First round: Should detect missing byte counts or non-browser protocols
	req1 := ag.GenerateRequest("https://example.com")
	det1 := detector.AnalyzeRequest(req1, nil)
	report1 := det1.ToDetectionReport()

	fired1 := report1.FiredCheckNames()
	t.Logf("Round 1: Fired checks: %v", fired1)

	foundTimingAnomalies := false
	for _, name := range fired1 {
		if name == "timing_missing_byte_counts" || name == "timing_inconsistent_protocols" {
			foundTimingAnomalies = true
			break
		}
	}

	if !foundTimingAnomalies {
		t.Errorf("Expected timing anomalies (byte counts or protocols) in round 1")
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
		if name == "timing_missing_byte_counts" || name == "timing_inconsistent_protocols" {
			t.Errorf("Detection leakage in round 2: %s", name)
		}
	}
}

// From phase74_test.go
func TestPhase74Integration(t *testing.T) {
	// 1. Setup Detector and Adaptive Generator
	detector := challenge.NewStealthDetector()

	config := &behavior.RequestGeneratorConfig{
		Profile:         behavior.ChromeWindowsProfile(),
		ForceDetections: true,
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)

	// Round 1: Force all Phase 74 anomalies
	ag.GetConfig().EvadePermissions = false
	ag.GetConfig().EvadePermissionsDeep = false
	// We want to see:
	// 1. permissions_query_mismatch (Notification_permission=default vs permissions_notifications_state=denied)
	// 2. permissions_media_mismatch (camera/mic granted but no labels? wait, I need to make them granted)

	req1 := ag.GenerateRequest("https://example.com")
	det1 := detector.AnalyzeRequest(req1, nil)
	report1 := det1.ToDetectionReport()

	fired1 := report1.FiredCheckNames()
	t.Logf("Round 1: Fired checks: %v", fired1)

	foundMismatch := false
	for _, name := range fired1 {
		if name == "permissions_query_mismatch" {
			foundMismatch = true
			break
		}
	}

	if !foundMismatch {
		t.Errorf("Expected permissions_query_mismatch in round 1")
	}

	// 2. Apply Feedback (Mutation)
	ag.ApplyFeedback(report1)

	// Second round: Should be clean for permissions
	req2 := ag.GenerateRequest("https://example.com")
	det2 := detector.AnalyzeRequest(req2, nil)
	report2 := det2.ToDetectionReport()

	fired2 := report2.FiredCheckNames()
	t.Logf("Round 2: Fired checks: %v", fired2)

	for _, name := range fired2 {
		if name == "permissions_query_mismatch" || name == "permissions_media_mismatch" || name == "permissions_metadata_leak" {
			t.Errorf("Detection leakage in round 2: %s", name)
		}
	}
}

// From phase83_84_test.go
func TestPhases83_84Integration(t *testing.T) {
	detector := challenge.NewStealthDetector()

	config := &behavior.RequestGeneratorConfig{
		Profile:         behavior.ChromeWindowsProfile(),
		ForceDetections: true,
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)

	// Round 1: No evasion
	ag.GetConfig().EvadePerformanceDeep = false
	ag.GetConfig().EvadeTimingDeep = false

	req1 := ag.GenerateRequest("https://example.com")
	det1 := detector.AnalyzeRequest(req1, nil)
	report1 := det1.ToDetectionReport()
	fired1 := report1.FiredCheckNames()
	t.Logf("Round 1: Fired checks: %v", fired1)

	hasMemoryMismatch := false
	hasNavTypeMismatch := false
	hasNavStartInconsistent := false
	hasLoadEventInconsistent := false

	for _, name := range fired1 {
		if name == "performance_memory_limit_mismatch" {
			hasMemoryMismatch = true
		}
		if name == "performance_navigation_type_mismatch" {
			hasNavTypeMismatch = true
		}
		if name == "timing_navigation_start_inconsistent" {
			hasNavStartInconsistent = true
		}
		if name == "timing_load_event_inconsistent" {
			hasLoadEventInconsistent = true
		}
	}

	if !hasMemoryMismatch {
		t.Errorf("Phase 83 detection failed: missing performance_memory_limit_mismatch")
	}
	if !hasNavTypeMismatch {
		t.Errorf("Phase 83 detection failed: missing performance_navigation_type_mismatch")
	}
	if !hasNavStartInconsistent {
		t.Errorf("Phase 84 detection failed: missing timing_navigation_start_inconsistent")
	}
	if !hasLoadEventInconsistent {
		t.Errorf("Phase 84 detection failed: missing timing_load_event_inconsistent")
	}

	// Round 2: Apply feedback
	ag.ApplyFeedback(report1)

	req2 := ag.GenerateRequest("https://example.com")
	det2 := detector.AnalyzeRequest(req2, nil)
	report2 := det2.ToDetectionReport()
	fired2 := report2.FiredCheckNames()
	t.Logf("Round 2: Fired checks: %v", fired2)

	for _, name := range fired2 {
		if name == "performance_memory_limit_mismatch" ||
			name == "performance_navigation_type_mismatch" ||
			name == "timing_navigation_start_inconsistent" ||
			name == "timing_load_event_inconsistent" {
			t.Errorf("Detection leakage in round 2: %s", name)
		}
	}
}

// From phase98_test.go
// TestPhase98_AcceptDestConsistency verifies the sword's detection of missing HTML Accept for document,
// or static document Accept for XHR/Fetch, and the shield's evasion.
func TestPhase98_AcceptDestConsistency(t *testing.T) {
	detector := challenge.NewStealthDetector()

	t.Run("Sword catches static document Accept on XHR", func(t *testing.T) {
		config := behavior.MaxEvasionConfig(behavior.ChromeWindowsProfile())
		config.EvadeAcceptDestConsistency = false
		config.EvasionStrategy = nil
		config.EvadeRequestProvenance = false
		// Simulate XHR/Fetch
		config.Profile.SecFetchDest = "empty"
		
		generator := behavior.NewRequestGenerator(config)
		req := generator.GenerateRequest("https://example.com/api/data")
		
		result := detector.AnalyzeRequest(req, nil)
		
		fired := false
		for _, vec := range result.Vectors {
			for _, ind := range vec.Indicators {
				if ind == "accept_dest_mismatch_static_document" {
					fired = true
					break
				}
			}
		}

		if !fired {
			t.Errorf("Sword failed to catch static document Accept on XHR. Accept: %s", req.Header.Get("Accept"))
		}
	})

	t.Run("Shield evades Accept Dest Mismatch", func(t *testing.T) {
		config := behavior.MaxEvasionConfig(behavior.ChromeWindowsProfile())
		config.EvadeAcceptDestConsistency = true
		config.EvasionStrategy = nil
		config.EvadeRequestProvenance = false
		config.Profile.SecFetchDest = "empty"
		
		generator := behavior.NewRequestGenerator(config)
		req := generator.GenerateRequest("https://example.com/api/data")
		
		result := detector.AnalyzeRequest(req, nil)
		
		fired := false
		for _, vec := range result.Vectors {
			for _, ind := range vec.Indicators {
				if strings.Contains(ind, "accept_dest_mismatch") {
					fired = true
					break
				}
			}
		}

		if fired {
			t.Errorf("Shield failed to evade Accept Dest Mismatch check. Accept: %s", req.Header.Get("Accept"))
		}
	})

	t.Run("Sword catches missing HTML on document", func(t *testing.T) {
		config := behavior.MaxEvasionConfig(behavior.ChromeWindowsProfile())
		config.EvadeAcceptDestConsistency = false
		config.EvasionStrategy = nil
		config.EvadeRequestProvenance = false
		config.Profile.SecFetchDest = "document"
		// Deliberately break the profile's accept
		config.Profile.Accept = "application/json"
		
		generator := behavior.NewRequestGenerator(config)
		req := generator.GenerateRequest("https://example.com/page")
		
		result := detector.AnalyzeRequest(req, nil)
		
		fired := false
		for _, vec := range result.Vectors {
			for _, ind := range vec.Indicators {
				if ind == "accept_dest_mismatch_missing_html" {
					fired = true
					break
				}
			}
		}

		if !fired {
			t.Errorf("Sword failed to catch missing HTML Accept on document")
		}
	})
}
