package challenge_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/skunkworq/stealth/brws/stealth/challenge"
	"github.com/skunkworq/stealth/brws/stealth/behavior"
	"github.com/skunkworq/stealth/brws/core/constants"
)

func TestPhase52AdaptiveLoop(t *testing.T) {
	// 1. Setup Adaptive Generator with Chrome profile
	config := &behavior.RequestGeneratorConfig{
		Profile: behavior.ChromeWindowsProfile(),
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)
	detector := challenge.NewStealthDetector()

	// 2. Round 1: Generate and Detect
	var webgpuFound, permissionsFound bool
	for i := 0; i < 100; i++ {
		hReq := ag.GenerateRequest("https://example.com/")

		detection := detector.AnalyzeRequest(hReq, nil)
		foundThisRound := false
		for _, vec := range detection.Vectors {
			for _, ind := range vec.Indicators {
				if strings.Contains(ind, "missing_webgpu") {
					webgpuFound = true
					foundThisRound = true
				}
				if strings.Contains(ind, "permissions_query_mismatch") {
					permissionsFound = true
					foundThisRound = true
				}
			}
		}
		if foundThisRound {
			ag.ApplyFeedback(detection.ToDetectionReport())
		}
		if webgpuFound && permissionsFound {
			break
		}
	}

	if !webgpuFound || !permissionsFound {
		t.Fatalf("Could not trigger all detections in 100 attempts: webgpu=%v, permissions=%v", webgpuFound, permissionsFound)
	}

	// 3. Final Verification: Generate and Verify Evasion
	hReq2 := ag.GenerateRequest("https://example.com/")
	headers2 := hReq2.Header

	navJSON := headers2.Get(constants.HeaderNavigatorData)
	var navData map[string]interface{}
	json.Unmarshal([]byte(navJSON), &navData)

	gpu := navData["gpu_present"].(bool)
	if !gpu {
		t.Errorf("Round 2 still missing WebGPU after mutation")
	}

	notif := navData["Notification_permission"].(string)
	permState := navData["permissions_notifications_state"].(string)
	if notif != permState {
		t.Errorf("Round 2 still has permissions mismatch: notif=%s, permState=%s", notif, permState)
	}

	// 4. Final verification via Detector
	detection2 := detector.AnalyzeRequest(hReq2, nil)
	for _, ind := range detection2.Indicators {
		if strings.Contains(ind.Name, "missing_webgpu") || strings.Contains(ind.Name, "permissions_query_mismatch") {
			t.Errorf("Round 2 still flagged with indicator: %s", ind.Name)
		}
	}
}
