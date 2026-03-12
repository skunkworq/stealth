package adversarial_test

import (
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
)

func TestPhases75_76Integration(t *testing.T) {
	detector := adversarial.NewStealthDetector()

	config := &behavior.RequestGeneratorConfig{
		Profile:         behavior.ChromeWindowsProfile(),
		ForceDetections: true,
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)

	// Round 1: No evasion for Client Hints or OffscreenCanvas
	ag.GetConfig().EvadeClientHintsDeep = false
	ag.GetConfig().EvadeOffscreenCanvasDeep = false

	req1 := ag.GenerateRequest("https://example.com")
	// For Phase 75, we need to ensure the header doesn't match the navigator data
	// By default, generateUserAgentData will only have major versions in brands unless EvadeClientHintsDeep is true.
	// But our detector also checks fullVersionList.

	det1 := detector.AnalyzeRequest(req1, nil)
	report1 := det1.ToDetectionReport()
	fired1 := report1.FiredCheckNames()
	t.Logf("Round 1: Fired checks: %v", fired1)

	// Round 2: Apply feedback and verify fixes
	ag.ApplyFeedback(report1)

	req2 := ag.GenerateRequest("https://example.com")
	det2 := detector.AnalyzeRequest(req2, nil)
	report2 := det2.ToDetectionReport()
	fired2 := report2.FiredCheckNames()
	t.Logf("Round 2: Fired checks: %v", fired2)

	for _, name := range fired2 {
		if name == "ua_client_hints_mismatch" || name == "offscreen_canvas_metrics_mismatch" {
			t.Errorf("Detection leakage in round 2: %s", name)
		}
	}
}
