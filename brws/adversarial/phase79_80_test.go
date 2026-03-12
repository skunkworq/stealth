package adversarial_test

import (
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
)

func TestPhases79_80Integration(t *testing.T) {
	detector := adversarial.NewStealthDetector()

	config := &behavior.RequestGeneratorConfig{
		Profile:         behavior.ChromeWindowsProfile(),
		ForceDetections: true,
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)

	// Round 1: No evasion for Screen Geometry or Navigator Prototype
	ag.GetConfig().EvadeScreenGeometryDeep = false
	ag.GetConfig().EvadeNavigatorPrototype = false

	req1 := ag.GenerateRequest("https://example.com")
	det1 := detector.AnalyzeRequest(req1, nil)
	report1 := det1.ToDetectionReport()
	fired1 := report1.FiredCheckNames()
	t.Logf("Round 1: Fired checks: %v", fired1)

	// Verify expected indicators are present
	hasGeometryMismatch := false
	hasPrototypeMismatch := false
	for _, name := range fired1 {
		if name == "screen_avail_geometry_mismatch" {
			hasGeometryMismatch = true
		}
		if name == "navigator_prototype_mismatch" {
			hasPrototypeMismatch = true
		}
	}
	if !hasGeometryMismatch {
		t.Errorf("Phase 79 detection failed: missing screen_avail_geometry_mismatch in %v", fired1)
	}
	if !hasPrototypeMismatch {
		t.Errorf("Phase 80 detection failed: missing navigator_prototype_mismatch in %v", fired1)
	}

	// Round 2: Apply feedback and verify fixes
	ag.ApplyFeedback(report1)

	req2 := ag.GenerateRequest("https://example.com")
	det2 := detector.AnalyzeRequest(req2, nil)
	report2 := det2.ToDetectionReport()
	fired2 := report2.FiredCheckNames()
	t.Logf("Round 2: Fired checks: %v", fired2)

	for _, name := range fired2 {
		if name == "screen_avail_geometry_mismatch" || name == "navigator_prototype_mismatch" {
			t.Errorf("Detection leakage in round 2: %s", name)
		}
	}
}
