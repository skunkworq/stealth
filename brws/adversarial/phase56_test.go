package adversarial_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
	"github.com/skunkworq/stealth/brws/constants"
)

func TestPhase56AdaptiveLoop(t *testing.T) {
	// 1. Setup Adaptive Generator
	config := &behavior.RequestGeneratorConfig{
		Profile:         behavior.ChromeWindowsProfile(),
		ForceDetections: true,
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)
	detector := adversarial.NewStealthDetector()

	// 2. Round 1: Generate and Detect (simulated failure via RNG)
	// Phase 55 and 56 simulation
	var webrtcFound bool
	for i := 0; i < 100; i++ {
		hReq := ag.GenerateRequest("https://example.com/")

		detection := detector.AnalyzeRequest(hReq, nil)
		foundThisRound := false
		for _, vec := range detection.Vectors {
			for _, ind := range vec.Indicators {
				if strings.Contains(ind, "missing_webrtc") ||
					strings.Contains(ind, "empty_ice_candidates") {
					webrtcFound = true
					foundThisRound = true
				}
			}
		}
		if foundThisRound {
			ag.ApplyFeedback(detection.ToDetectionReport())
			ag.GetConfig().ForceDetections = false
		}
		if webrtcFound {
			break
		}
	}

	if !webrtcFound {
		t.Fatalf("Could not trigger WebRTC detection in 100 attempts")
	}

	// 3. Final Verification: Generate and Verify Evasion
	hReq2 := ag.GenerateRequest("https://example.com/")

	// Check Navigator Data
	navJSON := hReq2.Header.Get(constants.HeaderNavigatorData)
	var navData map[string]interface{}
	json.Unmarshal([]byte(navJSON), &navData)

	webrtc, ok := navData["webrtc_data"].(map[string]interface{})
	if !ok {
		t.Errorf("Round 2 has missing WebRTC data after mutation")
	} else {
		candidates, _ := webrtc["ice_candidates"].([]interface{})
		if len(candidates) == 0 {
			t.Errorf("Round 2 has empty ICE candidates after mutation")
		}
	}

	// 4. Final verification via Detector
	detection2 := detector.AnalyzeRequest(hReq2, nil)
	for _, ind := range detection2.Indicators {
		if strings.Contains(ind.Name, "missing_webrtc") ||
			strings.Contains(ind.Name, "empty_ice_candidates") ||
			strings.Contains(ind.Name, "suspicious_ice_format") {
			t.Errorf("Round 2 still flagged with indicator: %s", ind.Name)
		}
	}
}
