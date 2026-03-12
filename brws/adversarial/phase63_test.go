package adversarial_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
	"github.com/skunkworq/stealth/brws/constants"
)

func TestPhase63Integration(t *testing.T) {
	// 1. Setup Adaptive Generator
	config := &behavior.RequestGeneratorConfig{
		Profile: behavior.ChromeWindowsProfile(),
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)
	detector := adversarial.NewStealthDetector()

	// 2. Round 1: Verification of Storage usage and persistence
	hReq := ag.GenerateRequest("https://example.com/")

	// Check Navigator Data for storage fields
	navJSON := hReq.Header.Get(constants.HeaderNavigatorData)
	var navData map[string]interface{}
	json.Unmarshal([]byte(navJSON), &navData)

	usage, ok := navData["storage_usage"].(float64)
	if !ok || usage <= 0 {
		t.Errorf("storage_usage missing or non-positive: %v", usage)
	}

	persisted, ok := navData["storage_persisted"].(bool)
	if !ok {
		t.Errorf("storage_persisted missing")
	}
	_ = persisted

	quota, ok := navData["storage_quota"].(float64)
	if !ok || quota < 1024*1024*1024 {
		t.Errorf("storage_quota missing or too low: %v", quota)
	}

	// 3. Run full detector analysis (should pass)
	detection := detector.AnalyzeRequest(hReq, nil)
	for _, ind := range detection.Indicators {
		if strings.Contains(ind.Name, "missing_storage_usage") ||
			strings.Contains(ind.Name, "low_storage_quota") ||
			strings.Contains(ind.Name, "missing_storage_persistence") ||
			strings.Contains(ind.Name, "zero_storage_usage") {
			t.Errorf("Shield flagged with Phase 63 gap: %s", ind.Name)
		}
	}

	// 4. Test "Learning" path for missing storage usage
	// We'll manually create a request with missing storage keys
	navDataClone := make(map[string]interface{})
	json.Unmarshal([]byte(navJSON), &navDataClone)
	delete(navDataClone, "storage_usage")
	delete(navDataClone, "storage_persisted")

	b, _ := json.Marshal(navDataClone)
	hReq.Header.Set(constants.HeaderNavigatorData, string(b))

	// Run full detector analysis (should fail now)
	detection_fail := detector.AnalyzeRequest(hReq, nil)
	foundGap := false
	for _, ind := range detection_fail.Indicators {
		if strings.Contains(ind.Name, "missing_storage_usage") {
			foundGap = true
			break
		}
	}
	if !foundGap {
		t.Errorf("Detector failed to catch missing storage_usage")
	}

	// Apply feedback
	report := detection_fail.ToDetectionReport()
	ag.ApplyFeedback(report)

	// Re-verify after feedback (request generator should rebuild and include usage)
	hReq2 := ag.GenerateRequest("https://example.com/")
	detection2 := detector.AnalyzeRequest(hReq2, nil)

	for _, ind := range detection2.Indicators {
		if strings.Contains(ind.Name, "missing_storage_usage") {
			t.Errorf("Shield still flagged with missing storage usage after feedback: %s", ind.Name)
		}
	}
}
