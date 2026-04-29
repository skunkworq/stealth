package challenge_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/skunkworq/stealth/brws/stealth/challenge"
	"github.com/skunkworq/stealth/brws/stealth/behavior"
	"github.com/skunkworq/stealth/brws/core/constants"
)

func TestPhase60Integration(t *testing.T) {
	// 1. Setup Adaptive Generator
	config := &behavior.RequestGeneratorConfig{
		Profile:               behavior.ChromeWindowsProfile(),
		EvadeErrorStackFormat: true,
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)
	detector := challenge.NewStealthDetector()

	// 2. Round 1: Verification of memory scaling and stack realism
	hReq := ag.GenerateRequest("https://example.com/")
	t.Logf("DEBUG: hReq headers: %v", hReq.Header)

	navJSON := hReq.Header.Get(constants.HeaderNavigatorData)
	t.Logf("DEBUG: navJSON length: %d", len(navJSON))
	var navData map[string]interface{}
	json.Unmarshal([]byte(navJSON), &navData)

	// Verify performance_memory plausibility
	t.Logf("DEBUG: navData keys: %v", getMapKeys(navData))
	perfMem, ok := navData["performance_memory"].(map[string]interface{})
	if !ok {
		t.Fatalf("performance_memory missing")
	}
	limit := perfMem["jsHeapSizeLimit"].(float64)
	deviceMem := navData["deviceMemory"].(float64)

	if deviceMem >= 8 && limit < 3.5e9 {
		t.Errorf("performance_memory_limit too low for 8GB+ RAM: %.0f", limit)
	}

	// Verify Error.stack realism
	bhJSON := hReq.Header.Get(constants.HeaderBehavioralData)
	var bhData map[string]interface{}
	json.Unmarshal([]byte(bhJSON), &bhData)

	stack, ok := bhData["errorStack"].(string)
	if !ok || stack == "" {
		t.Fatalf("errorStack missing or empty")
	}

	if !strings.Contains(stack, ".js") {
		t.Errorf("errorStack missing .js filenames: %s", stack)
	}
	if !strings.Contains(stack, "async") {
		t.Errorf("errorStack missing async markers: %s", stack)
	}
	if strings.Count(stack, "\n") < 3 {
		t.Errorf("errorStack too short (frames < 4): %s", stack)
	}

	// 3. Run full detector analysis (should pass)
	detection := detector.AnalyzeRequest(hReq, nil)
	for _, ind := range detection.Indicators {
		if strings.Contains(ind.Name, "performance_memory_limit_too_low_for_ram") ||
			strings.Contains(ind.Name, "error_stack_suspiciously_clean") ||
			strings.Contains(ind.Name, "error_stack_missing_async_context") {
			t.Errorf("Shield flagged with Phase 60 gap: %s", ind.Name)
		}
	}

	// 4. Test "Learning" path for Automation Leak
	// We simulate an automation leak detection
	report := detection.ToDetectionReport()
	report.Vectors = append(report.Vectors, challenge.VectorReport{
		Name: "Navigator Properties",
		Checks: []challenge.CheckReport{
			{
				Name:  "automation_leak_detected",
				Fired: true,
			},
		},
	})

	ag.ApplyFeedback(report)

	// Re-verify after feedback
	hReq2 := ag.GenerateRequest("https://example.com/")
	detection2 := detector.AnalyzeRequest(hReq2, nil)

	for _, ind := range detection2.Indicators {
		if strings.Contains(ind.Name, "automation_leak_detected") {
			t.Errorf("Shield still flagged with automation leak after feedback: %s", ind.Name)
		}
	}
}

func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
