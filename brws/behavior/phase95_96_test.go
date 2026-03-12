package behavior_test

import (
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
)

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
	
	detector := adversarial.NewStealthDetector()
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
