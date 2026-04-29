package challenge_test

import (
	"testing"

	"github.com/skunkworq/stealth/brws/stealth/challenge"
	"github.com/skunkworq/stealth/brws/stealth/behavior"
)

func TestPhases77_78Integration(t *testing.T) {
	detector := challenge.NewStealthDetector()

	config := &behavior.RequestGeneratorConfig{
		Profile:         behavior.ChromeWindowsProfile(),
		ForceDetections: true,
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)

	// Round 1: No evasion for Gamepad or Hardware APIs
	ag.GetConfig().EvadeGamepadAPI = false
	ag.GetConfig().EvadeHardwareHardening = false

	req1 := ag.GenerateRequest("https://example.com")
	det1 := detector.AnalyzeRequest(req1, nil)
	report1 := det1.ToDetectionReport()
	fired1 := report1.FiredCheckNames()
	t.Logf("Round 1: Fired checks: %v", fired1)

	// Verify expected indicators are present
	hasGamepad := false
	hasBluetooth := false
	hasUSB := false
	for _, name := range fired1 {
		if name == "missing_navigator_getGamepads" || name == "gamepad_api_stubbed" {
			hasGamepad = true
		}
		if name == "bluetooth_api_stubbed" || name == "missing_navigator_bluetooth" {
			hasBluetooth = true
		}
		if name == "usb_api_stubbed" || name == "missing_navigator_usb" {
			hasUSB = true
		}
	}
	if !hasGamepad {
		t.Errorf("Phase 77 detection failed: missing gamepad indicator in %v", fired1)
	}
	if !hasBluetooth {
		t.Errorf("Phase 78 detection failed: missing bluetooth indicator in %v", fired1)
	}
	if !hasUSB {
		t.Errorf("Phase 78 detection failed: missing usb indicator in %v", fired1)
	}

	// Round 2: Apply feedback and verify fixes
	ag.ApplyFeedback(report1)

	req2 := ag.GenerateRequest("https://example.com")
	det2 := detector.AnalyzeRequest(req2, nil)
	report2 := det2.ToDetectionReport()
	fired2 := report2.FiredCheckNames()
	t.Logf("Round 2: Fired checks: %v", fired2)

	for _, name := range fired2 {
		if name == "missing_navigator_getGamepads" || name == "gamepad_api_stubbed" ||
			name == "bluetooth_api_stubbed" || name == "usb_api_stubbed" {
			t.Errorf("Detection leakage in round 2: %s", name)
		}
	}
}
