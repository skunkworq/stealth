package adversarial_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
	"github.com/skunkworq/stealth/brws/constants"
)

func TestPhase59Integration(t *testing.T) {
	// 1. Setup Adaptive Generator with a basic profile
	config := &behavior.RequestGeneratorConfig{
		Profile: behavior.ChromeWindowsProfile(),
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)
	detector := adversarial.NewStealthDetector()

	// 2. Round 1: Verification of presence and consistency
	// Since I've already updated the generator, we expect these to be present.
	hReq := ag.GenerateRequest("https://example.com/")

	navJSON := hReq.Header.Get(constants.HeaderNavigatorData)
	var navData map[string]interface{}
	json.Unmarshal([]byte(navJSON), &navData)

	// Verify required Phase 59 fields are present
	if _, ok := navData["scheduling"]; !ok {
		t.Errorf("navigator.scheduling missing from generated data")
	}
	if _, ok := navData["locks"]; !ok {
		t.Errorf("navigator.locks missing from generated data")
	}
	if intlTZ, ok := navData["intl_timezone"].(string); !ok || intlTZ == "" {
		t.Errorf("intl_timezone missing or empty")
	} else if intlTZ != config.Profile.Timezone {
		t.Errorf("intl_timezone mismatch: got %v, want %v", intlTZ, config.Profile.Timezone)
	}

	// 3. Run full detector analysis
	detection := detector.AnalyzeRequest(hReq, nil)

	for _, ind := range detection.Indicators {
		if strings.Contains(ind.Name, "missing_navigator_scheduling") ||
			strings.Contains(ind.Name, "missing_navigator_locks") ||
			strings.Contains(ind.Name, "intl_timezone_mismatch") {
			t.Errorf("Shield flagged with Phase 59 gap: %s", ind.Name)
		}
	}

	// 4. Test "Learning" path
	// We simulate a report with a Phase 59 indicator and ensure feedback works.
	report := detection.ToDetectionReport()
	// Force an indicator to test mutation registration
	for i, v := range report.Vectors {
		if v.Name == "Navigator Properties" {
			report.Vectors[i].Checks = append(report.Vectors[i].Checks, adversarial.CheckReport{
				Name:  "missing_navigator_scheduling",
				Fired: true,
			})
		}
	}

	ag.ApplyFeedback(report)

	// Re-verify after feedback (should pass as before)
	hReq2 := ag.GenerateRequest("https://example.com/")
	detection2 := detector.AnalyzeRequest(hReq2, nil)

	for _, ind := range detection2.Indicators {
		if strings.Contains(ind.Name, "missing_navigator_scheduling") {
			t.Errorf("Shield still flagged after feedback: %s", ind.Name)
		}
	}
}
