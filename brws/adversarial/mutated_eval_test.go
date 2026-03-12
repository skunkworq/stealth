package adversarial_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
)

func TestMutatedShield(t *testing.T) {
	profiles := behavior.DefaultProfiles()

	for _, profile := range profiles {
		detector := adversarial.NewStealthDetector()

		// Naked generator
		genConfig := &behavior.RequestGeneratorConfig{
			Profile:              profile,
			EvadeWebGLCount:      false,
			EvadeScreenHeightGap: false,
			EvadeWebGLViewport:   false,
			EvadeDeviceMemoryClamp: false,
			EvadeConnectionSaveData: false,
			EvadeScreenOrientation: false,
			EvadeNavigatorKeyboard: false,
			EvadeHardwareConcurrency: false,
			EvadeNetworkQuantization: false,
		}
		gen := behavior.NewRequestGenerator(genConfig)
		req := gen.GenerateRequest("http://test/")
		res := detector.AnalyzeRequest(req, nil)

		fmt.Printf("Naked %s -> Score: %.3f\n", profile.Name, res.Score)
		for _, v := range res.Vectors {
			for _, ind := range v.Indicators {
				if strings.HasPrefix(ind, "insufficient_webgl_extensions") || 
				   strings.HasPrefix(ind, "suspicious_taskbar_gap") || 
				   strings.HasPrefix(ind, "missing_webgl_viewport_dims") || 
				   strings.HasPrefix(ind, "mouse_abrupt_start") || 
				   strings.HasPrefix(ind, "improbable_device_memory") || 
				   strings.HasPrefix(ind, "missing_navigator_keyboard") ||
				   strings.HasPrefix(ind, "improbable_hardware_concurrency") ||
				   strings.HasPrefix(ind, "non_quantized_network_rtt") ||
				   strings.HasPrefix(ind, "non_quantized_network_downlink") {
					fmt.Printf("  Caught: %s\n", ind)
				}
			}
		}

		// Mutated generator
		genConfigMutated := &behavior.RequestGeneratorConfig{
			Profile:              profile,
			EvadeWebGLCount:      true,
			EvadeScreenHeightGap: true,
			EvadeWebGLViewport:      true,
			EvadeDeviceMemoryClamp:  true,
			EvadeConnectionSaveData: true,
			EvadeScreenOrientation:  true,
			EvadeNavigatorKeyboard:  true,
			EvadeHardwareConcurrency: true,
			EvadeNetworkQuantization: true,
			EvadeCanvasEntropy:       true,
			EvadeDPRQuantization:     true,
			EventConfig:             behavior.DefaultGeneratorConfig(),
		}
		genConfigMutated.EventConfig.EvadeMouseEaseIn = true
		genConfigMutated.EventConfig.EvadeMouseClustering = true
		genConfigMutated.EventConfig.EvadeScrollMomentum = true
		genConfigMutated.EventConfig.EvadeClickDeceleration = true
		genConfigMutated.EventConfig.EvadeFittsLaw = true
		genConfigMutated.EventConfig.EvadeMouseVelocityLag3 = true
		genConfigMutated.EventConfig.EvadeScrollSpearman = true
		genConfigMutated.EventConfig.EvadeMouseTypingDensity = true
		genConfigMutated.EventConfig.EvadeClickDwellTime = true
		genMutated := behavior.NewRequestGenerator(genConfigMutated)
		reqMutated := genMutated.GenerateRequest("http://test/")
		resMutated := detector.AnalyzeRequest(reqMutated, nil)

		fmt.Printf("Mutated %s -> Score: %.3f\n", profile.Name, resMutated.Score)
		caught := false
		for _, v := range resMutated.Vectors {
			for _, ind := range v.Indicators {
				// Print ALL indicators if we are still being caught
				if resMutated.Score > 0.1 {
					fmt.Printf("  Still Caught: %s\n", ind)
				}
				if strings.HasPrefix(ind, "insufficient_webgl_extensions") || 
				   strings.HasPrefix(ind, "suspicious_taskbar_gap") || 
				   strings.HasPrefix(ind, "missing_webgl_viewport_dims") || 
				   strings.HasPrefix(ind, "mouse_abrupt_start") || 
				   strings.HasPrefix(ind, "improbable_device_memory") || 
				   strings.HasPrefix(ind, "missing_connection_saveData") {
					caught = true
				}
			}
		}
		if caught {
			t.Errorf("Mutated generator was still caught for %s", profile.Name)
		}
	}
}
