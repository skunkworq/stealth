package challenge_test

import (
	"encoding/json"
	"strings"
	"testing"
	"github.com/skunkworq/stealth/brws/core/constants"
	"github.com/skunkworq/stealth/brws/stealth/behavior"
	"github.com/skunkworq/stealth/brws/stealth/challenge"
)

// From phase52_test.go
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

// From phase53_test.go
func TestPhase53AdaptiveLoop(t *testing.T) {
	// 1. Setup Adaptive Generator
	config := &behavior.RequestGeneratorConfig{
		Profile: behavior.ChromeWindowsProfile(),
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)
	detector := challenge.NewStealthDetector()

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

// From phase55_test.go
func TestPhase55AdaptiveLoop(t *testing.T) {
	// 1. Setup Adaptive Generator
	config := &behavior.RequestGeneratorConfig{
		Profile: behavior.ChromeWindowsProfile(),
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)
	detector := challenge.NewStealthDetector()

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

// From phase56_test.go
func TestPhase56AdaptiveLoop(t *testing.T) {
	// 1. Setup Adaptive Generator
	config := &behavior.RequestGeneratorConfig{
		Profile:         behavior.ChromeWindowsProfile(),
		ForceDetections: true,
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)
	detector := challenge.NewStealthDetector()

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

// From phase61_test.go
func TestPhase61Integration(t *testing.T) {
	// 1. Setup Adaptive Generator
	config := &behavior.RequestGeneratorConfig{
		Profile: behavior.ChromeWindowsProfile(),
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)
	detector := challenge.NewStealthDetector()

	// 2. Round 1: Verification of AudioWorklet and maxChannelCount
	hReq := ag.GenerateRequest("https://example.com/")

	// Check Navigator Data for audio_worklet_available
	navJSON := hReq.Header.Get(constants.HeaderNavigatorData)
	var navData map[string]interface{}
	json.Unmarshal([]byte(navJSON), &navData)

	if aw, ok := navData["audio_worklet_available"].(bool); !ok || !aw {
		t.Errorf("audio_worklet_available missing or false in navigator data")
	}

	// Check Audio Data for max_channel_count and audio_worklet_available
	audioJSON := hReq.Header.Get(constants.HeaderAudioData)
	var audioData map[string]interface{}
	json.Unmarshal([]byte(audioJSON), &audioData)

	maxChannels, ok := audioData["max_channel_count"].(float64)
	if !ok || maxChannels < 2 {
		t.Errorf("max_channel_count missing or too low: %v", maxChannels)
	}

	if aw, ok := audioData["audio_worklet_available"].(bool); !ok || !aw {
		t.Errorf("audio_worklet_available missing or false in audio data")
	}

	// 3. Run full detector analysis (should pass)
	detection := detector.AnalyzeRequest(hReq, nil)
	for _, ind := range detection.Indicators {
		if strings.Contains(ind.Name, "missing_audio_worklet") ||
			strings.Contains(ind.Name, "audio_max_channel_count_anomaly") {
			t.Errorf("Shield flagged with Phase 61 gap: %s", ind.Name)
		}
	}

	// 4. Test "Learning" path for missing AudioWorklet
	// We simulate a detection of missing AudioWorklet
	report := detection.ToDetectionReport()
	report.Vectors = append(report.Vectors, challenge.VectorReport{
		Name: "Audio Analysis",
		Checks: []challenge.CheckReport{
			{
				Name:  "missing_audio_worklet",
				Fired: true,
			},
		},
	})

	ag.ApplyFeedback(report)

	// Re-verify after feedback
	hReq2 := ag.GenerateRequest("https://example.com/")
	detection2 := detector.AnalyzeRequest(hReq2, nil)

	for _, ind := range detection2.Indicators {
		if strings.Contains(ind.Name, "missing_audio_worklet") {
			t.Errorf("Shield still flagged with missing audio worklet after feedback: %s", ind.Name)
		}
	}
}
