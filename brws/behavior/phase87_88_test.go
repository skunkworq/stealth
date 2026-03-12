package behavior_test

import (
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
)

func TestPhases87_88Integration(t *testing.T) {
	detector := adversarial.NewStealthDetector()
	
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
	
	if report2.TotalScore >= report1.TotalScore && report1.TotalScore > 0 {
		t.Errorf("Score did not improve in Round 2: %f -> %f", report1.TotalScore, report2.TotalScore)
	}
	
	t.Logf("Successfully verified Phases 87 & 88 with adaptive feedback")
}
