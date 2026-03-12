package adversarial_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
	"github.com/skunkworq/stealth/brws/constants"
)

func TestPhase55AdaptiveLoop(t *testing.T) {
	// 1. Setup Adaptive Generator
	config := &behavior.RequestGeneratorConfig{
		Profile: behavior.ChromeWindowsProfile(),
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)
	detector := adversarial.NewStealthDetector()

	// 2. Round 1: Generate and Detect (Empty Media Devices)
	var mediaFound bool
	for i := 0; i < 100; i++ {
		hReq := ag.GenerateRequest("https://example.com/")
		
		detection := detector.AnalyzeRequest(hReq, nil)
		foundThisRound := false
		for _, vec := range detection.Vectors {
			for _, ind := range vec.Indicators {
				if strings.Contains(ind, "empty_media_devices") || 
				   strings.Contains(ind, "suspicious_media_device_id") {
					mediaFound = true
					foundThisRound = true
				}
			}
		}
		if foundThisRound {
			ag.ApplyFeedback(detection.ToDetectionReport())
		}
		if mediaFound {
			break
		}
	}

	if !mediaFound {
		t.Fatalf("Could not trigger MediaDevices detection in 100 attempts")
	}

	// 3. Final Verification: Generate and Verify Evasion
	hReq2 := ag.GenerateRequest("https://example.com/")
	
	// Check Navigator Data
	navJSON := hReq2.Header.Get(constants.HeaderNavigatorData)
	var navData map[string]interface{}
	json.Unmarshal([]byte(navJSON), &navData)
	
	devices, ok := navData["media_devices"].([]interface{})
	if !ok || len(devices) == 0 {
		t.Errorf("Round 2 still has empty or missing media devices after mutation")
	}

	// 4. Final verification via Detector
	detection2 := detector.AnalyzeRequest(hReq2, nil)
	for _, ind := range detection2.Indicators {
		if strings.Contains(ind.Name, "empty_media_devices") || 
		   strings.Contains(ind.Name, "suspicious_media_device_id") ||
		   strings.Contains(ind.Name, "non_standard_media_device_id_format") {
			t.Errorf("Round 2 still flagged with indicator: %s", ind.Name)
		}
	}
}
