package adversarial_test

import (
	"log"
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
)

func TestPhase64Integration(t *testing.T) {
	// 1. Setup detector and adaptive generator
	detector := adversarial.NewStealthDetector()

	// Let's use the broken generator first
	bg := behavior.NewBrokenRequestGenerator(nil)
	req := bg.GenerateRequest("https://example.com")

	// 2. Initial detection (expect failure)
	detection := detector.AnalyzeRequest(req, nil)
	log.Printf("Round 1 Score: %.3f (Bot: %v)", detection.Score, detection.IsBot)

	found := false
	for _, ind := range detection.Indicators {
		if ind.Name == "screen_is_extended_missing" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("expected screen_is_extended_missing indicator, but it was not found")
	}

	// 3. Apply feedback
	ag := behavior.NewAdaptiveRequestGenerator(nil)
	report := detection.ToDetectionReport()
	ag.ApplyFeedback(report)

	// 4. Second generation (expect fix)
	req2 := ag.GenerateRequest("https://example.com")
	detection2 := detector.AnalyzeRequest(req2, nil)
	log.Printf("Round 2 Score: %.3f (Bot: %v)", detection2.Score, detection2.IsBot)

	found2 := false
	for _, ind := range detection2.Indicators {
		if ind.Name == "screen_is_extended_missing" {
			found2 = true
			break
		}
	}

	if found2 {
		t.Errorf("screen_is_extended_missing should be fixed in Round 2")
	}
}
