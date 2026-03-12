package adversarial_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
	"github.com/skunkworq/stealth/brws/constants"
)

func TestPhase54AdaptiveLoop(t *testing.T) {
	// 1. Setup Adaptive Generator
	config := &behavior.RequestGeneratorConfig{
		Profile: behavior.ChromeWindowsProfile(),
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)
	detector := adversarial.NewStealthDetector()

	// 2. Round 1: Generate and Detect
	var batteryFound, storageFound bool
	for i := 0; i < 100; i++ {
		hReq := ag.GenerateRequest("https://example.com/")
		
		detection := detector.AnalyzeRequest(hReq, nil)
		foundThisRound := false
		for _, vec := range detection.Vectors {
			for _, ind := range vec.Indicators {
				if strings.Contains(ind, "suspicious_battery_status") {
					batteryFound = true
					foundThisRound = true
				}
				if strings.Contains(ind, "low_storage_quota") || strings.Contains(ind, "missing_storage_quota") {
					storageFound = true
					foundThisRound = true
				}
			}
		}
		if foundThisRound {
			ag.ApplyFeedback(detection.ToDetectionReport())
		}
		if batteryFound && storageFound {
			break
		}
	}

	if !batteryFound || !storageFound {
		t.Fatalf("Could not trigger all detections in 100 attempts: battery=%v, storage=%v", batteryFound, storageFound)
	}

	// 3. Final Verification: Generate and Verify Evasion
	hReq2 := ag.GenerateRequest("https://example.com/")
	
	// Check Navigator Data
	navJSON := hReq2.Header.Get(constants.HeaderNavigatorData)
	var navData map[string]interface{}
	json.Unmarshal([]byte(navJSON), &navData)
	
	battery := navData["battery_status"].(map[string]interface{})
	level := battery["level"].(float64)
	charging := battery["charging"].(bool)
	chargingTime := battery["chargingTime"].(float64)
	
	if level == 1.0 && charging && chargingTime == 0.0 {
		t.Errorf("Round 2 still has suspicious battery status after mutation")
	}

	quota := navData["storage_quota"].(float64)
	if quota <= 1024*1024 {
		t.Errorf("Round 2 still has low storage quota: %.0f bytes", quota)
	}

	// 4. Final verification via Detector
	detection2 := detector.AnalyzeRequest(hReq2, nil)
	for _, ind := range detection2.Indicators {
		if strings.Contains(ind.Name, "suspicious_battery_status") || 
		   strings.Contains(ind.Name, "low_storage_quota") ||
		   strings.Contains(ind.Name, "missing_storage_quota") {
			t.Errorf("Round 2 still flagged with indicator: %s", ind.Name)
		}
	}
}
