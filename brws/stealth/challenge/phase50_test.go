package challenge_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/skunkworq/stealth/brws/stealth/challenge"
	"github.com/skunkworq/stealth/brws/stealth/behavior"
	"github.com/skunkworq/stealth/brws/core/constants"
)

func TestPhase50AdaptiveLoop(t *testing.T) {
	// 1. Setup Adaptive Generator with Mac profile (Apple M2)
	// ChromeMacOSProfile pickers include cores < 8 by default in generateHardwareSpecsWithRenderer
	config := &behavior.RequestGeneratorConfig{
		Profile: behavior.ChromeMacOSProfile(),
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)
	detector := challenge.NewStealthDetector()

	// 2. Round 1: Generate and Detect
	var mismatchFound bool
	for i := 0; i < 50; i++ {
		hReq := ag.GenerateRequest("https://example.com/")

		detection := detector.AnalyzeRequest(hReq, nil)
		foundThisRound := false
		for _, vec := range detection.Vectors {
			for _, ind := range vec.Indicators {
				if strings.HasPrefix(ind, "hardware_core_mismatch") {
					mismatchFound = true
					foundThisRound = true
					ag.ApplyFeedback(detection.ToDetectionReport())
					break
				}
			}
		}
		if foundThisRound {
			break
		}
	}

	if !mismatchFound {
		t.Skip("Could not trigger hardware_core_mismatch randomly in 50 attempts")
	}

	// 3. Round 2: Generate and Verify Evasion
	// Once the mutation is applied, EvadeHardwareCoherence is true.
	// For Apple M-series, generateHardwareSpecsWithRenderer should now only pick >= 8 cores.
	hReq2 := ag.GenerateRequest("https://example.com/")
	headers2 := hReq2.Header

	navJSON := headers2.Get(constants.HeaderNavigatorData)
	var navData map[string]interface{}
	json.Unmarshal([]byte(navJSON), &navData)
	cores := int(navData["hardwareConcurrency"].(float64))

	if cores < 8 {
		t.Errorf("Round 2 still has %d cores for Apple M-series GPU after mutation", cores)
	}

	// 4. Final verification via Detector
	detection2 := detector.AnalyzeRequest(hReq2, nil)
	for _, vec := range detection2.Vectors {
		for _, ind := range vec.Indicators {
			if strings.HasPrefix(ind, "hardware_core_mismatch") {
				t.Errorf("Round 2 still flagged with indicator: %s", ind)
			}
		}
	}
}
