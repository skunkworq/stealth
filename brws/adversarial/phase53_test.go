package adversarial_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
	"github.com/skunkworq/stealth/brws/constants"
)

func TestPhase53AdaptiveLoop(t *testing.T) {
	// 1. Setup Adaptive Generator
	config := &behavior.RequestGeneratorConfig{
		Profile: behavior.ChromeWindowsProfile(),
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)
	detector := adversarial.NewStealthDetector()

	// 2. Round 1: Generate and Detect
	var latencyFound, orientationFound bool
	for i := 0; i < 100; i++ {
		hReq := ag.GenerateRequest("https://example.com/")
		
		detection := detector.AnalyzeRequest(hReq, nil)
		foundThisRound := false
		for _, vec := range detection.Vectors {
			for _, ind := range vec.Indicators {
				if strings.Contains(ind, "audio_zero_base_latency") || strings.Contains(ind, "missing_audio_base_latency") {
					latencyFound = true
					foundThisRound = true
				}
				if strings.Contains(ind, "screen_orientation_mismatch") {
					orientationFound = true
					foundThisRound = true
				}
			}
		}
		if foundThisRound {
			ag.ApplyFeedback(detection.ToDetectionReport())
		}
		if latencyFound && orientationFound {
			break
		}
	}

	if !latencyFound || !orientationFound {
		t.Fatalf("Could not trigger all detections in 100 attempts: latency=%v, orientation=%v", latencyFound, orientationFound)
	}

	// 3. Final Verification: Generate and Verify Evasion
	hReq2 := ag.GenerateRequest("https://example.com/")
	
	// Check Audio Data
	audioJSON := hReq2.Header.Get(constants.HeaderAudioData)
	var audioData map[string]interface{}
	json.Unmarshal([]byte(audioJSON), &audioData)
	
	baseLatency := audioData["base_latency"].(float64)
	if baseLatency == 0.0 {
		t.Errorf("Round 2 still has zero base latency after mutation")
	}

	// Check Navigator Data
	navJSON := hReq2.Header.Get(constants.HeaderNavigatorData)
	var navData map[string]interface{}
	json.Unmarshal([]byte(navJSON), &navData)
	
	orientation := navData["screen_orientation"].(string)
	width := navData["screen_inner_width"].(float64)
	height := navData["screen_inner_height"].(float64)
	
	if width > height && strings.Contains(orientation, "portrait") {
		t.Errorf("Round 2 still has orientation mismatch (landscape dims, portrait orientation)")
	}

	// 4. Final verification via Detector
	detection2 := detector.AnalyzeRequest(hReq2, nil)
	for _, ind := range detection2.Indicators {
		if strings.Contains(ind.Name, "audio_zero_base_latency") || 
		   strings.Contains(ind.Name, "missing_audio_base_latency") ||
		   strings.Contains(ind.Name, "screen_orientation_mismatch") {
			t.Errorf("Round 2 still flagged with indicator: %s", ind.Name)
		}
	}
}
