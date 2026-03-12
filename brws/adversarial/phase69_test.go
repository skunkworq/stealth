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
		t.Errorf("Expected suspicious_header_order detection in round 1, but it was not found")
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
	adaptiveGen.ApplyFeedback(det1.ToDetectionReport())
	
	req2 := adaptiveGen.GenerateRequest("https://example.com")
	det2 := detector.AnalyzeRequest(req2, nil)

	fired2 := det2.ToDetectionReport().FiredCheckNames()
	for _, ind := range fired2 {
		if ind == "suspicious_header_order" {
			t.Errorf("suspicious_header_order detection still present in round 2")
		}
	}
}
