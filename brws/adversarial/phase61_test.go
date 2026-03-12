package adversarial_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
	"github.com/skunkworq/stealth/brws/constants"
)

func TestPhase61Integration(t *testing.T) {
	// 1. Setup Adaptive Generator
	config := &behavior.RequestGeneratorConfig{
		Profile: behavior.ChromeWindowsProfile(),
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)
	detector := adversarial.NewStealthDetector()

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
	report.Vectors = append(report.Vectors, adversarial.VectorReport{
		Name: "Audio Analysis",
		Checks: []adversarial.CheckReport{
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
