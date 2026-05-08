package challenge_test

import (
	"encoding/json"
	"strings"
	"testing"
	"github.com/skunkworq/stealth/brws/core/constants"
	"github.com/skunkworq/stealth/brws/stealth/behavior"
	"github.com/skunkworq/stealth/brws/stealth/challenge"
)

// From phase62_test.go
func TestPhase62Integration(t *testing.T) {
	// 1. Setup Adaptive Generator
	config := &behavior.RequestGeneratorConfig{
		Profile: behavior.ChromeWindowsProfile(),
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)
	detector := challenge.NewStealthDetector()

	// 2. Round 1: Verification of OffscreenCanvas and WebGL draft extensions
	hReq := ag.GenerateRequest("https://example.com/")

	// Check Navigator Data for offscreen_canvas_available
	navJSON := hReq.Header.Get(constants.HeaderNavigatorData)
	var navData map[string]interface{}
	json.Unmarshal([]byte(navJSON), &navData)

	if oc, ok := navData["offscreen_canvas_available"].(bool); !ok || !oc {
		t.Errorf("offscreen_canvas_available missing or false in navigator data")
	}

	// Check WebGL Data for draft extensions (when EvadeWebGLCount is ON)
	// We need to enable EvadeWebGLCount for Round 1 to pass the draft extension check
	config.EvadeWebGLCount = true
	ag = behavior.NewAdaptiveRequestGenerator(config)
	hReq = ag.GenerateRequest("https://example.com/")

	webglJSON := hReq.Header.Get(constants.HeaderWebGLData)
	var webglData map[string]interface{}
	json.Unmarshal([]byte(webglJSON), &webglData)

	exts, ok := webglData["webgl_extensions"].([]interface{})
	if !ok {
		t.Fatalf("webgl_extensions missing")
	}

	foundTimer := false
	for _, e := range exts {
		if e.(string) == "EXT_disjoint_timer_query_webgl2" {
			foundTimer = true
			break
		}
	}
	if !foundTimer {
		t.Errorf("EXT_disjoint_timer_query_webgl2 missing from webgl_extensions")
	}

	// 3. Run full detector analysis (should pass)
	detection := detector.AnalyzeRequest(hReq, nil)
	for _, ind := range detection.Indicators {
		if strings.Contains(ind.Name, "missing_offscreen_canvas") ||
			strings.Contains(ind.Name, "missing_webgl_draft_extensions") {
			t.Errorf("Shield flagged with Phase 62 gap: %s", ind.Name)
		}
	}

	// 4. Test "Learning" path for missing OffscreenCanvas
	// Reset config to defaults (where EvadeWebGLCount is false)
	config.EvadeWebGLCount = false
	ag = behavior.NewAdaptiveRequestGenerator(config)
	hReq = ag.GenerateRequest("https://example.com/")

	// Simulate a detection of missing offscreen canvas
	report := detector.AnalyzeRequest(hReq, nil).ToDetectionReport()
	report.Vectors = append(report.Vectors, challenge.VectorReport{
		Name: "Canvas/WebGL Fingerprint",
		Checks: []challenge.CheckReport{
			{
				Name:  "missing_offscreen_canvas",
				Fired: true,
			},
		},
	})

	ag.ApplyFeedback(report)

	// Re-verify after feedback
	hReq2 := ag.GenerateRequest("https://example.com/")
	detection2 := detector.AnalyzeRequest(hReq2, nil)

	for _, ind := range detection2.Indicators {
		if strings.Contains(ind.Name, "missing_offscreen_canvas") {
			t.Errorf("Shield still flagged with missing offscreen canvas after feedback: %s", ind.Name)
		}
	}
}

// From phase71_test.go
func TestPhase71Integration(t *testing.T) {
	// 1. Setup Detector and Adaptive Generator
	detector := challenge.NewStealthDetector()

	// Start with a broken generator that triggers Phase 71 checks
	config := &behavior.RequestGeneratorConfig{
		Profile:         behavior.ChromeWindowsProfile(),
		ForceDetections: true,
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)

	// Ensure we are in a "broken" state for Phase 71 (no evasion yet)
	ag.GetConfig().EvadeWebGLShaderPrecision = false

	// First round: Should detect missing/mismatching shader precision
	req1 := ag.GenerateRequest("https://example.com")
	det1 := detector.AnalyzeRequest(req1, nil)
	report1 := det1.ToDetectionReport()

	fired1 := report1.FiredCheckNames()
	t.Logf("Round 1: Fired checks: %v", fired1)

	foundPrecisionMismatch := false
	for _, name := range fired1 {
		if name == "webgl_shader_precision_mismatch" {
			foundPrecisionMismatch = true
			break
		}
	}

	if !foundPrecisionMismatch {
		t.Errorf("Expected webgl_shader_precision_mismatch detection in round 1")
	}

	// 2. Apply Feedback (Mutation)
	ag.ApplyFeedback(report1)

	// Second round: Should be clean
	req2 := ag.GenerateRequest("https://example.com")
	det2 := detector.AnalyzeRequest(req2, nil)
	report2 := det2.ToDetectionReport()

	fired2 := report2.FiredCheckNames()
	t.Logf("Round 2: Fired checks: %v", fired2)

	for _, ind := range fired2 {
		if ind == "webgl_shader_precision_mismatch" {
			t.Errorf("Detection leakage in round 2: %s", ind)
		}
	}
}

// From phase73_test.go
func TestPhase73Integration(t *testing.T) {
	// 1. Setup Detector and Adaptive Generator
	detector := challenge.NewStealthDetector()

	// Start with a Chrome profile but force detections (which triggers empty plugins)
	config := &behavior.RequestGeneratorConfig{
		Profile:         behavior.ChromeWindowsProfile(),
		ForceDetections: true,
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)

	// Ensure we are in a "broken" state for Phase 73 (no evasion yet)
	ag.GetConfig().EvadePlugins = false

	// First round: Should detect missing plugins on Chrome
	req1 := ag.GenerateRequest("https://example.com")
	det1 := detector.AnalyzeRequest(req1, nil)
	report1 := det1.ToDetectionReport()

	fired1 := report1.FiredCheckNames()
	t.Logf("Round 1: Fired checks: %v", fired1)

	foundEmptyPlugins := false
	for _, name := range fired1 {
		if name == "empty_plugins" {
			foundEmptyPlugins = true
			break
		}
	}

	if !foundEmptyPlugins {
		t.Errorf("Expected empty_plugins in round 1")
	}

	// 2. Apply Feedback (Mutation)
	ag.ApplyFeedback(report1)

	// Second round: Should be clean
	req2 := ag.GenerateRequest("https://example.com")
	det2 := detector.AnalyzeRequest(req2, nil)
	report2 := det2.ToDetectionReport()

	fired2 := report2.FiredCheckNames()
	t.Logf("Round 2: Fired checks: %v", fired2)

	for _, name := range fired2 {
		if name == "empty_plugins" || name == "plugin_missing_mime_types" {
			t.Errorf("Detection leakage in round 2: %s", name)
		}
	}
}

// From phase75_76_test.go
func TestPhases75_76Integration(t *testing.T) {
	detector := challenge.NewStealthDetector()

	config := &behavior.RequestGeneratorConfig{
		Profile:         behavior.ChromeWindowsProfile(),
		ForceDetections: true,
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)

	// Round 1: No evasion for Client Hints or OffscreenCanvas
	ag.GetConfig().EvadeClientHintsDeep = false
	ag.GetConfig().EvadeOffscreenCanvasDeep = false

	req1 := ag.GenerateRequest("https://example.com")
	// For Phase 75, we need to ensure the header doesn't match the navigator data
	// By default, generateUserAgentData will only have major versions in brands unless EvadeClientHintsDeep is true.
	// But our detector also checks fullVersionList.

	det1 := detector.AnalyzeRequest(req1, nil)
	report1 := det1.ToDetectionReport()
	fired1 := report1.FiredCheckNames()
	t.Logf("Round 1: Fired checks: %v", fired1)

	// Round 2: Apply feedback and verify fixes
	ag.ApplyFeedback(report1)

	req2 := ag.GenerateRequest("https://example.com")
	det2 := detector.AnalyzeRequest(req2, nil)
	report2 := det2.ToDetectionReport()
	fired2 := report2.FiredCheckNames()
	t.Logf("Round 2: Fired checks: %v", fired2)

	for _, name := range fired2 {
		if name == "ua_client_hints_mismatch" || name == "offscreen_canvas_metrics_mismatch" {
			t.Errorf("Detection leakage in round 2: %s", name)
		}
	}
}

// From phase77_78_test.go
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

// From phase79_80_test.go
func TestPhases79_80Integration(t *testing.T) {
	detector := challenge.NewStealthDetector()

	config := &behavior.RequestGeneratorConfig{
		Profile:         behavior.ChromeWindowsProfile(),
		ForceDetections: true,
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)

	// Round 1: No evasion for Screen Geometry or Navigator Prototype
	ag.GetConfig().EvadeScreenGeometryDeep = false
	ag.GetConfig().EvadeNavigatorPrototype = false

	req1 := ag.GenerateRequest("https://example.com")
	det1 := detector.AnalyzeRequest(req1, nil)
	report1 := det1.ToDetectionReport()
	fired1 := report1.FiredCheckNames()
	t.Logf("Round 1: Fired checks: %v", fired1)

	// Verify expected indicators are present
	hasGeometryMismatch := false
	hasPrototypeMismatch := false
	for _, name := range fired1 {
		if name == "screen_avail_geometry_mismatch" {
			hasGeometryMismatch = true
		}
		if name == "navigator_prototype_mismatch" {
			hasPrototypeMismatch = true
		}
	}
	if !hasGeometryMismatch {
		t.Errorf("Phase 79 detection failed: missing screen_avail_geometry_mismatch in %v", fired1)
	}
	if !hasPrototypeMismatch {
		t.Errorf("Phase 80 detection failed: missing navigator_prototype_mismatch in %v", fired1)
	}

	// Round 2: Apply feedback and verify fixes
	ag.ApplyFeedback(report1)

	req2 := ag.GenerateRequest("https://example.com")
	det2 := detector.AnalyzeRequest(req2, nil)
	report2 := det2.ToDetectionReport()
	fired2 := report2.FiredCheckNames()
	t.Logf("Round 2: Fired checks: %v", fired2)

	for _, name := range fired2 {
		if name == "screen_avail_geometry_mismatch" || name == "navigator_prototype_mismatch" {
			t.Errorf("Detection leakage in round 2: %s", name)
		}
	}
}

// From phase81_82_test.go
func TestPhases81_82Integration(t *testing.T) {
	detector := challenge.NewStealthDetector()

	// Use Mac profile to trigger renderer mismatch (ForceDetections will inject NVIDIA on Mac)
	config := &behavior.RequestGeneratorConfig{
		Profile:         behavior.ChromeMacOSProfile(),
		ForceDetections: true,
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)

	// Round 1: No evasion
	ag.GetConfig().EvadeWebGLRendererDeep = false
	ag.GetConfig().EvadeAudioContextDeep = false

	req1 := ag.GenerateRequest("https://example.com")
	det1 := detector.AnalyzeRequest(req1, nil)
	report1 := det1.ToDetectionReport()
	fired1 := report1.FiredCheckNames()
	t.Logf("Round 1: Fired checks: %v", fired1)

	hasRendererMismatch := false
	hasAudioStateMismatch := false
	hasAudioLatencyMismatch := false
	for _, name := range fired1 {
		if name == "renderer_platform_mismatch" {
			hasRendererMismatch = true
		}
		if name == "audio_context_static_state" {
			hasAudioStateMismatch = true
		}
		if name == "audio_latency_improbable" {
			hasAudioLatencyMismatch = true
		}
	}

	if !hasRendererMismatch {
		t.Errorf("Phase 81 detection failed: missing renderer_platform_mismatch")
	}
	if !hasAudioStateMismatch {
		t.Errorf("Phase 82 detection failed: missing audio_context_static_state")
	}
	if !hasAudioLatencyMismatch {
		t.Errorf("Phase 82 detection failed: missing audio_latency_improbable")
	}

	// Round 2: Apply feedback
	ag.ApplyFeedback(report1)

	req2 := ag.GenerateRequest("https://example.com")
	det2 := detector.AnalyzeRequest(req2, nil)
	report2 := det2.ToDetectionReport()
	fired2 := report2.FiredCheckNames()
	t.Logf("Round 2: Fired checks: %v", fired2)

	for _, name := range fired2 {
		if name == "renderer_platform_mismatch" || name == "audio_context_static_state" || name == "audio_latency_improbable" {
			t.Errorf("Detection leakage in round 2: %s", name)
		}
	}
}
