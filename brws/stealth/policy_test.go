package stealth

import (
	"fmt"
	"testing"

	"github.com/skunkworq/stealth/brws/browser/engine/chromium"
)

func TestBuildStateVector_EmptyAnomalies(t *testing.T) {
	vec := BuildStateVector(nil, nil, nil)
	if len(vec) != 18 {
		t.Fatalf("expected 18 dimensions, got %d", len(vec))
	}
	for i, v := range vec {
		if v != 0 {
			t.Errorf("expected vec[%d] = 0, got %.4f", i, v)
		}
	}
}

func TestBuildStateVector_AnomaliesMapping(t *testing.T) {
	anomalies := []string{
		"webdriver property detected",
		"canvas noise injection",
		"client_hints missing",
		"hardware mismatch",
		"timezone mismatch",
	}

	vec := BuildStateVector(anomalies, nil, nil)

	if vec[0] != 1.0 {
		t.Error("webdriver anomaly not mapped to vec[0]")
	}
	if vec[1] != 1.0 {
		t.Error("canvas anomaly not mapped to vec[1]")
	}
	if vec[2] != 1.0 {
		t.Error("client_hints anomaly not mapped to vec[2]")
	}
	if vec[4] != 1.0 {
		t.Error("hardware anomaly not mapped to vec[4]")
	}
	if vec[10] != 1.0 {
		t.Error("timezone anomaly not mapped to vec[10]")
	}
}

func TestBuildStateVector_CaptchaState(t *testing.T) {
	captcha := &CaptchaState{
		Presented:  true,
		Solved:     true,
		Difficulty: 0.75,
	}

	vec := BuildStateVector(nil, captcha, nil)

	if vec[11] != 1.0 {
		t.Error("captcha presented not mapped to vec[11]")
	}
	if vec[12] != 1.0 {
		t.Error("captcha solved not mapped to vec[12]")
	}
	if vec[13] != 0.75 {
		t.Errorf("captcha difficulty: expected 0.75, got %.4f", vec[13])
	}
}

func TestBuildStateVector_BehavioralState(t *testing.T) {
	behavioral := &BehavioralState{
		MouseVelocity: 1000.0, // 1000/2000 = 0.5
		TypingSpeed:   250.0,  // 250/500 = 0.5
		Straightness:  0.8,
		SolveTimeMs:   15000, // 15000/30000 = 0.5
	}

	vec := BuildStateVector(nil, nil, behavioral)

	if vec[14] != 0.5 {
		t.Errorf("mouse velocity: expected 0.5, got %.4f", vec[14])
	}
	if vec[15] != 0.5 {
		t.Errorf("typing speed: expected 0.5, got %.4f", vec[15])
	}
	if vec[16] != 0.8 {
		t.Errorf("straightness: expected 0.8, got %.4f", vec[16])
	}
	if vec[17] != 0.5 {
		t.Errorf("solve time: expected 0.5, got %.4f", vec[17])
	}
}

func TestApplyAction_StealthConfigToggle(t *testing.T) {
	tests := []struct {
		actionIdx int
		fieldName string
		checkFunc func(cfg *chromium.StealthConfig) bool
	}{
		{0, "RemoveWebDriver", func(c *chromium.StealthConfig) bool { return c.RemoveWebDriver }},
		{1, "CanvasNoise", func(c *chromium.StealthConfig) bool { return c.CanvasNoise }},
		{2, "ClientHints", func(c *chromium.StealthConfig) bool { return c.ClientHints }},
		{3, "RandomUserAgent", func(c *chromium.StealthConfig) bool { return c.RandomUserAgent }},
		{4, "WebGLSpoof", func(c *chromium.StealthConfig) bool { return c.WebGLSpoof }},
		{5, "HardwareSync", func(c *chromium.StealthConfig) bool { return c.HardwareSync }},
		{6, "NetworkSync", func(c *chromium.StealthConfig) bool { return c.NetworkSync }},
		{7, "PluginsSync", func(c *chromium.StealthConfig) bool { return c.PluginsSync }},
		{8, "GeometrySync", func(c *chromium.StealthConfig) bool { return c.GeometrySync }},
		{9, "VideoSync", func(c *chromium.StealthConfig) bool { return c.VideoSync }},
		{10, "PermissionsSync", func(c *chromium.StealthConfig) bool { return c.PermissionsSync }},
		{11, "TimezoneSync", func(c *chromium.StealthConfig) bool { return c.TimezoneSync }},
	}

	for _, tt := range tests {
		t.Run(tt.fieldName, func(t *testing.T) {
			cfg := &chromium.StealthConfig{}

			applied, name := ApplyAction(cfg, tt.actionIdx)
			if !applied {
				t.Errorf("expected action %d (%s) to be applied", tt.actionIdx, tt.fieldName)
			}
			if name != tt.fieldName {
				t.Errorf("expected field name %s, got %s", tt.fieldName, name)
			}
			if !tt.checkFunc(cfg) {
				t.Errorf("config field %s should be true after apply", tt.fieldName)
			}

			// Applying again should return false (already set)
			applied, _ = ApplyAction(cfg, tt.actionIdx)
			if applied {
				t.Errorf("re-applying action %d should return applied=false", tt.actionIdx)
			}
		})
	}
}

func TestApplyAction_SignalingActions(t *testing.T) {
	cfg := &chromium.StealthConfig{}

	// Actions 12-17 are signaling actions
	for i := 12; i <= 17; i++ {
		applied, name := ApplyAction(cfg, i)
		if !applied {
			t.Errorf("signaling action %d (%s) should always apply", i, name)
		}
	}
}

func TestApplyAction_InvalidAction(t *testing.T) {
	cfg := &chromium.StealthConfig{}

	applied, name := ApplyAction(cfg, 99)
	if applied {
		t.Error("invalid action should not be applied")
	}
	if name != "unknown" {
		t.Errorf("expected 'unknown' for invalid action, got %s", name)
	}
}

func TestExtractAnomalies(t *testing.T) {
	tests := []struct {
		errMsg   string
		expected []string
	}{
		{"WAF Challenge Detected", []string{"waf_challenge"}},
		{"webdriver property is true", []string{"webdriver_exposed"}},
		{"canvas noise detected", []string{"canvas_detected"}},
	}

	for _, tt := range tests {
		anomalies := extractAnomalies(fmt.Errorf("%s", tt.errMsg))
		if len(anomalies) == 0 {
			t.Errorf("expected anomalies from error '%s', got none", tt.errMsg)
		}

		for _, exp := range tt.expected {
			found := false
			for _, a := range anomalies {
				if a == exp {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected anomaly '%s' from error '%s'", exp, tt.errMsg)
			}
		}
	}
}

func TestExtractAnomalies_Nil(t *testing.T) {
	anomalies := extractAnomalies(nil)
	if anomalies != nil {
		t.Error("nil error should return nil anomalies")
	}
}

func TestClamp(t *testing.T) {
	if clamp(-1, 0, 1) != 0 {
		t.Error("clamp(-1, 0, 1) should be 0")
	}
	if clamp(2, 0, 1) != 1 {
		t.Error("clamp(2, 0, 1) should be 1")
	}
	if clamp(0.5, 0, 1) != 0.5 {
		t.Error("clamp(0.5, 0, 1) should be 0.5")
	}
}
