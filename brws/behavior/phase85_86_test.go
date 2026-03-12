package behavior_test

import (
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
)

func TestPhases85_86Integration(t *testing.T) {
	// We'll use an Android profile to test both Touch and Orientation Locking
	profile := behavior.AndroidPixelProfile()

	// 1. Initial State: Forcing detections
	config := &behavior.RequestGeneratorConfig{
		Profile:         profile,
		ForceDetections: true,
	}

	ag := behavior.NewAdaptiveRequestGenerator(config)
	detector := adversarial.NewStealthDetector()

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
