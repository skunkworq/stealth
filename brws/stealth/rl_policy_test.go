package stealth

import (
	"errors"
	"testing"
)

// mockStealthConfig records ToggleFeature calls for assertion.
type mockStealthConfig struct {
	toggled []string
}

func (m *mockStealthConfig) IsEnabled() bool                              { return true }
func (m *mockStealthConfig) SetEnabled(bool)                              {}
func (m *mockStealthConfig) ToggleFeature(name string) (bool, bool) {
	m.toggled = append(m.toggled, name)
	return true, false
}

// TestBuildStateVector_AnomalyIndexMapping verifies that each anomaly keyword
// sets exactly the expected dimension index.
func TestBuildStateVector_AnomalyIndexMapping(t *testing.T) {
	cases := []struct {
		anomaly string
		idx     int
	}{
		{"webdriver_exposed", 0},
		{"canvas_detected", 1},
		{"webgl_vendor", 1},
		{"client_hints_issues", 2},
		{"inconsistent_ch", 2},
		{"screen_mismatch", 3},
		{"waf_challenge", 3},
		{"blocked", 3},
		{"hardware_concurrency", 4},
		{"memory_check", 4},
		{"network_anomaly", 5},
		{"plugins_missing", 6},
		{"geometry_off", 7},
		{"video_codec", 8},
		{"permissions_denied", 9},
		{"timezone_offset", 10},
	}

	for _, tc := range cases {
		t.Run(tc.anomaly, func(t *testing.T) {
			vec := BuildStateVector([]string{tc.anomaly}, nil, nil)
			if vec[tc.idx] != 1.0 {
				t.Errorf("anomaly %q: expected vec[%d]=1.0, got %.1f (full vec: %v)",
					tc.anomaly, tc.idx, vec[tc.idx], vec)
			}
			// Verify other detection indices remain 0
			for i := 0; i <= 10; i++ {
				if i == tc.idx {
					continue
				}
				if vec[i] != 0.0 {
					t.Errorf("anomaly %q: unexpected vec[%d]=%.1f (should be 0)", tc.anomaly, i, vec[i])
				}
			}
		})
	}
}

// TestBuildStateVector_CaptchaState verifies that CaptchaState populates
// indices 11-13 and overrides any captcha anomaly in index 11.
func TestBuildStateVector_CaptchaState(t *testing.T) {
	cs := &CaptchaState{Presented: true, Solved: true, Difficulty: 0.8}
	vec := BuildStateVector(nil, cs, nil)

	if vec[11] != 1.0 {
		t.Errorf("expected vec[11]=1.0 (presented), got %.1f", vec[11])
	}
	if vec[12] != 1.0 {
		t.Errorf("expected vec[12]=1.0 (solved), got %.1f", vec[12])
	}
	if vec[13] != 0.8 {
		t.Errorf("expected vec[13]=0.8 (difficulty), got %.2f", vec[13])
	}
}

// TestBuildStateVector_BehavioralState verifies behavioral metrics are clamped
// and placed in indices 14-17.
func TestBuildStateVector_BehavioralState(t *testing.T) {
	bs := &BehavioralState{
		MouseVelocity: 1000.0, // → 0.5 (1000/2000)
		TypingSpeed:   250.0,  // → 0.5 (250/500)
		Straightness:  0.75,
		SolveTimeMs:   15000, // → 0.5 (15000/30000)
	}
	vec := BuildStateVector(nil, nil, bs)

	if vec[14] != 0.5 {
		t.Errorf("expected vec[14]=0.5 (mouse_velocity), got %.3f", vec[14])
	}
	if vec[15] != 0.5 {
		t.Errorf("expected vec[15]=0.5 (typing_speed), got %.3f", vec[15])
	}
	if vec[16] != 0.75 {
		t.Errorf("expected vec[16]=0.75 (straightness), got %.3f", vec[16])
	}
	if vec[17] != 0.5 {
		t.Errorf("expected vec[17]=0.5 (solve_time), got %.3f", vec[17])
	}
}

// TestBuildStateVector_CaptchaAnomalyWithoutState verifies that a "captcha" anomaly
// string sets index 11 only when no explicit CaptchaState is provided.
func TestBuildStateVector_CaptchaAnomalyWithoutState(t *testing.T) {
	vec := BuildStateVector([]string{"captcha_challenge"}, nil, nil)
	if vec[11] != 1.0 {
		t.Errorf("expected vec[11]=1.0 for captcha anomaly (no CaptchaState), got %.1f", vec[11])
	}

	// Explicit CaptchaState should override anomaly; here Presented=false.
	vec2 := BuildStateVector([]string{"captcha_challenge"}, &CaptchaState{Presented: false}, nil)
	if vec2[11] != 0.0 {
		t.Errorf("expected vec[11]=0.0 when CaptchaState.Presented=false, got %.1f", vec2[11])
	}
}

// TestApplyAction_ToggleActions verifies that action indices 0-11 call ToggleFeature
// with the correct field name.
func TestApplyAction_ToggleActions(t *testing.T) {
	cases := []struct {
		idx  int
		name string
	}{
		{0, "RemoveWebDriver"},
		{1, "CanvasNoise"},
		{2, "ClientHints"},
		{3, "RandomUserAgent"},
		{4, "WebGLSpoof"},
		{5, "HardwareSync"},
		{6, "NetworkSync"},
		{7, "PluginsSync"},
		{8, "GeometrySync"},
		{9, "VideoSync"},
		{10, "PermissionsSync"},
		{11, "TimezoneSync"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &mockStealthConfig{}
			applied, field := ApplyAction(cfg, tc.idx)
			if !applied {
				t.Errorf("action %d (%s): expected applied=true", tc.idx, tc.name)
			}
			if field != tc.name {
				t.Errorf("action %d: expected field %q, got %q", tc.idx, tc.name, field)
			}
			if len(cfg.toggled) != 1 || cfg.toggled[0] != tc.name {
				t.Errorf("action %d: expected ToggleFeature(%q), got %v", tc.idx, tc.name, cfg.toggled)
			}
		})
	}
}

// TestApplyAction_SignalingActions verifies that action indices 12-17 return
// applied=true without calling ToggleFeature (they are consumed by other subsystems).
func TestApplyAction_SignalingActions(t *testing.T) {
	cases := []struct {
		idx  int
		name string
	}{
		{12, "CaptchaSolver"},
		{13, "HumanizeInteraction"},
		{14, "DelayedNavigation"},
		{15, "WebRTCDisable"},
		{16, "CanvasNoiseStrength"},
		{17, "HeadlessPatches"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &mockStealthConfig{}
			applied, field := ApplyAction(cfg, tc.idx)
			if !applied {
				t.Errorf("action %d (%s): expected applied=true", tc.idx, tc.name)
			}
			if field != tc.name {
				t.Errorf("action %d: expected field %q, got %q", tc.idx, tc.name, field)
			}
			// Signaling actions must NOT mutate StealthConfig
			if len(cfg.toggled) != 0 {
				t.Errorf("action %d: unexpected ToggleFeature call(s): %v", tc.idx, cfg.toggled)
			}
		})
	}
}

// TestApplyAction_UnknownIndex verifies that out-of-range action indices return
// applied=false and the "unknown" sentinel.
func TestApplyAction_UnknownIndex(t *testing.T) {
	cfg := &mockStealthConfig{}
	for _, idx := range []int{-1, 18, 100} {
		applied, field := ApplyAction(cfg, idx)
		if applied {
			t.Errorf("action %d: expected applied=false for unknown index", idx)
		}
		if field != "unknown" {
			t.Errorf("action %d: expected field \"unknown\", got %q", idx, field)
		}
	}
}

// TestApplyAction_NilConfig verifies that toggle actions with a nil StealthConfig
// return applied=false (nothing to mutate).
func TestApplyAction_NilConfig(t *testing.T) {
	applied, field := ApplyAction(nil, 0)
	if applied {
		t.Errorf("expected applied=false for nil StealthConfig, got true")
	}
	if field != "RemoveWebDriver" {
		t.Errorf("expected field \"RemoveWebDriver\", got %q", field)
	}
}

// TestExtractAnomalies_KeywordMapping verifies that each keyword produces the
// expected anomaly string.
func TestExtractAnomalies_KeywordMapping(t *testing.T) {
	cases := []struct {
		msg     string
		want    string
	}{
		{"webdriver property exposed", "webdriver_exposed"},
		{"canvas fingerprint mismatch detected", "canvas_detected"},
		{"client_hints header missing", "client_hints_issues"},
		{"WAF blocked request", "waf_challenge"},
		{"request blocked by firewall", "blocked"},
		{"captcha required for verification", "captcha_challenge"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			anomalies := ExtractAnomalies(errors.New(tc.msg))
			found := false
			for _, a := range anomalies {
				if a == tc.want {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("message %q: expected anomaly %q in %v", tc.msg, tc.want, anomalies)
			}
		})
	}
}

// TestExtractAnomalies_NilError verifies that a nil error returns nil.
func TestExtractAnomalies_NilError(t *testing.T) {
	if result := ExtractAnomalies(nil); result != nil {
		t.Errorf("expected nil for nil error, got %v", result)
	}
}
