package challenge_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/skunkworq/stealth/brws/stealth/challenge"
	"github.com/skunkworq/stealth/brws/stealth/behavior"
	"github.com/skunkworq/stealth/brws/core/constants"
)

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
