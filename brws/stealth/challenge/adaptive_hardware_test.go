package challenge_test

import (
	"encoding/json"
	"strings"
	"testing"
	"github.com/skunkworq/stealth/brws/core/constants"
	"github.com/skunkworq/stealth/brws/stealth/behavior"
	"github.com/skunkworq/stealth/brws/stealth/challenge"
)

// From phase50_test.go
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

// From phase51_test.go
func TestPhase51AdaptiveLoop(t *testing.T) {
	// 1. Setup Adaptive Generator with a modified profile to trigger plugin mismatch
	prof := behavior.ChromeWindowsProfile()
	if len(prof.Plugins) > 0 {
		// Induce a failure by using a non-standard filename
		prof.Plugins[0].Filename = "spoofed-viewer.dll"
	}
	config := &behavior.RequestGeneratorConfig{
		Profile: prof,
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)
	detector := challenge.NewStealthDetector()

	// 2. Round 1: Generate and Detect
	var pointerFound, pluginFound bool
	for i := 0; i < 100; i++ {
		hReq := ag.GenerateRequest("https://example.com/")

		detection := detector.AnalyzeRequest(hReq, nil)
		foundThisRound := false
		for _, vec := range detection.Vectors {
			for _, ind := range vec.Indicators {
				if strings.Contains(ind, "pointer_mismatch") || strings.Contains(ind, "any_pointer_mismatch") {
					pointerFound = true
					foundThisRound = true
				}
				if strings.Contains(ind, "suspicious_plugin_filename") {
					pluginFound = true
					foundThisRound = true
				}
			}
		}
		if foundThisRound {
			ag.ApplyFeedback(detection.ToDetectionReport())
		}
		if pointerFound && pluginFound {
			break
		}
	}

	if !pointerFound {
		t.Log("Could not trigger pointer_mismatch randomly in 100 attempts (30% chance per request if not evading)")
	}
	if !pluginFound {
		t.Errorf("Could not trigger suspicious_plugin_filename (forced in initial profile)")
	}

	// 3. Final Verification: Generate and Verify Evasion
	// Once mutations are applied, EvadePointerInteraction and EvadePluginFilenames are true.
	hReq2 := ag.GenerateRequest("https://example.com/")
	headers2 := hReq2.Header

	navJSON := headers2.Get(constants.HeaderNavigatorData)
	var navData map[string]interface{}
	json.Unmarshal([]byte(navJSON), &navData)

	pointer := navData["media_query_pointer"].(string)
	if pointer != "fine" {
		t.Errorf("Round 2 still has %s pointer after mutation", pointer)
	}

	pluginJSON := headers2.Get(constants.HeaderPluginData)
	var pluginData map[string]interface{}
	json.Unmarshal([]byte(pluginJSON), &pluginData)
	plugins := pluginData["plugins"].([]interface{})
	foundPDF := false
	for _, p := range plugins {
		pMap := p.(map[string]interface{})
		name := pMap["name"].(string)
		filename := pMap["filename"].(string)
		if strings.Contains(strings.ToLower(name), "pdf") {
			foundPDF = true
			if filename != "internal-pdf-viewer" {
				t.Errorf("Round 2 still has %s for plugin %s after mutation", filename, name)
			}
		}
	}
	if !foundPDF {
		t.Errorf("No PDF plugins found in generated output")
	}

	// 4. Final verification via Detector
	detection2 := detector.AnalyzeRequest(hReq2, nil)
	for _, vec := range detection2.Vectors {
		for _, ind := range vec.Indicators {
			if strings.Contains(ind, "pointer_mismatch") || strings.Contains(ind, "suspicious_plugin_filename") {
				t.Errorf("Round 2 still flagged with indicator: %s", ind)
			}
		}
	}
}
