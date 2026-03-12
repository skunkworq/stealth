package adversarial_test

import (
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
)

func TestPhase74Integration(t *testing.T) {
	// 1. Setup Detector and Adaptive Generator
	detector := adversarial.NewStealthDetector()
	
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
