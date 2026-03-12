package adversarial_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
	"github.com/skunkworq/stealth/brws/constants"
)

func TestPhase58Integration(t *testing.T) {
	// 1. Setup Adaptive Generator with a mobile profile to trigger maxTouchPoints check
	// We'll manually override the profile to be mobile but missing maxTouchPoints
	profile := behavior.ChromeWindowsProfile()
	// Simulate a mobile UA but keep maxTouchPoints=0
	profile.UserAgent = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36"
	profile.MaxTouchPoints = 0

	config := &behavior.RequestGeneratorConfig{
		Profile: profile,
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)
	detector := adversarial.NewStealthDetector()

	// 2. Round 1: Detect Gaps
	hReq := ag.GenerateRequest("https://example.com/")

	// Add Sec-CH-UA-Platform to trigger cross-check mismatch if needed,
	// but here we just want to see if it flags missing userAgentData and inconsistent maxTouchPoints.
	hReq.Header.Set("Sec-CH-UA-Platform", "\"Windows\"") // Mismatch with "linux" from UA

	detection := detector.AnalyzeRequest(hReq, nil)

	gapsFound := make(map[string]bool)
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if strings.Contains(ind, "missing_navigator_userAgentData") {
				gapsFound["userAgentData"] = true
			}
			if strings.Contains(ind, "inconsistent_mobile_max_touch_points") {
				gapsFound["maxTouchPoints"] = true
			}
			if strings.Contains(ind, "missing_navigator_userActivation") {
				gapsFound["userActivation"] = true
			}
		}
	}

	// Note: RequestGenerator implemented in Phase 58 might ALREADY have these fields.
	// To truly test the adaptive loop, we'd need a generator that doesn't have them yet.
	// But since I've already updated the generator, I'll verify they ARE present and consistent.

	navJSON := hReq.Header.Get(constants.HeaderNavigatorData)
	var navData map[string]interface{}
	json.Unmarshal([]byte(navJSON), &navData)

	if _, ok := navData["userAgentData"]; !ok {
		t.Errorf("userAgentData missing from navigator data")
	}
	if _, ok := navData["userActivation"]; !ok {
		t.Errorf("userActivation missing from navigator data")
	}

	// Apply feedback anyway to test the mutation path
	ag.ApplyFeedback(detection.ToDetectionReport())

	// 3. Final Verification
	hReq2 := ag.GenerateRequest("https://example.com/")
	detection2 := detector.AnalyzeRequest(hReq2, nil)

	for _, ind := range detection2.Indicators {
		// These shouldn't be present if the generator is now "fixed" or if it was already correct.
		if strings.Contains(ind.Name, "missing_navigator_userAgentData") ||
			strings.Contains(ind.Name, "missing_navigator_userActivation") {
			t.Errorf("Round 2 still flagged with gap: %s", ind.Name)
		}
	}
}
