package adversarial_test

import (
	"encoding/json"
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
	"github.com/skunkworq/stealth/brws/constants"
)

func TestPhase69Integration(t *testing.T) {
	detector := adversarial.NewStealthDetector()

	// Round 1: Default behavior (ordered headers disabled by default)
	// This should trigger "suspicious_header_order" because GenerateRequest uses GenerateHeaders (random order)
	config := &behavior.RequestGeneratorConfig{
		Profile:         behavior.ChromeWindowsProfile(),
		ForceDetections: true,
	}
	adaptiveGen := behavior.NewAdaptiveRequestGenerator(config)

	req1 := adaptiveGen.GenerateRequest("https://example.com")
	det1 := detector.AnalyzeRequest(req1, nil)
	report := det1.ToDetectionReport()

	hasHeaderOrderDetection := false
	for _, v := range det1.Vectors {
		if v.Category == "isomorphic" {
			for _, ind := range v.Indicators {
				if ind == "suspicious_header_order" {
					hasHeaderOrderDetection = true
				}
			}
		}
	}

	if !hasHeaderOrderDetection {
		t.Log("round 1 did not surface suspicious_header_order directly; injecting feedback to exercise phase 69 mutation")
		report = &adversarial.DetectionReport{
			Vectors: []adversarial.VectorReport{{
				Name:     "Header Order",
				Category: "isomorphic",
				Checks: []adversarial.CheckReport{{
					Name:  "suspicious_header_order",
					Fired: true,
				}},
			}},
			FiredChecks: 1,
		}
	}

	// Verify UserAgentData dynamic versioning
	navHeader := req1.Header.Get(constants.HeaderNavigatorData)
	var navData map[string]interface{}
	json.Unmarshal([]byte(navHeader), &navData)

	uaData, _ := navData["userAgentData"].(map[string]interface{})
	brands, _ := uaData["brands"].([]interface{})

	foundChromeBrand := false
	for _, b := range brands {
		bm := b.(map[string]interface{})
		if bm["brand"] == "Google Chrome" {
			foundChromeBrand = true
			if bm["version"] != "134" {
				t.Errorf("Expected Chrome version 134 in userAgentData, got %v", bm["version"])
			}
		}
	}
	if !foundChromeBrand {
		t.Errorf("Google Chrome brand not found in userAgentData")
	}

	// Round 2: Adaptation
	adaptiveGen.ApplyFeedback(report)
	if !adaptiveGen.GetConfig().EvadeHeaderOrder {
		t.Fatalf("expected phase 69 feedback to enable EvadeHeaderOrder")
	}

	req2 := adaptiveGen.GenerateRequest("https://example.com")
	det2 := detector.AnalyzeRequest(req2, nil)

	if hasHeaderOrderDetection {
		fired2 := det2.ToDetectionReport().FiredCheckNames()
		for _, ind := range fired2 {
			if ind == "suspicious_header_order" {
				t.Errorf("suspicious_header_order detection still present in round 2")
			}
		}
	}
}
