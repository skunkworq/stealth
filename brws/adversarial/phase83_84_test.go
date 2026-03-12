package adversarial_test

import (
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
)

func TestPhases83_84Integration(t *testing.T) {
	detector := adversarial.NewStealthDetector()

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
