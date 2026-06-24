package adversarial_test

import (
	"net/http"
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
)

// TestPhase99ScrollMomentumDecay verifies detection and evasion of scroll momentum decay.
// Real mouse scrolling exhibits an exponential velocity decay curve (momentum).
// Synthetic sequences frequently use arbitrary static decrements resulting
// in an absent or highly negative lag-1 exponential moving average.
func TestPhase99ScrollMomentumDecay(t *testing.T) {
	// 1. Setup Detector and Adaptive Generator
	t.Logf("Creating detector and generator")
	detector := adversarial.NewStealthDetector()

	// Start with a broken generator that triggers Phase 99 checks
	ag := behavior.NewAdaptiveFromBroken(nil)
	ag.GetConfig().ForceDetections = true

	var req *http.Request
	var detection *adversarial.StealthDetection
	var report *adversarial.DetectionReport
	var fired []string
	foundMomentumDeficit := false

	t.Logf("Round 1: Generating broken request(s) and asserting detection")
	// Poll until the randomized event generator produces a scroll sequence
	// without momentum that trips the detector. 10 loops is more than enough
	// reliably trigger stochastic behavioral vectors.
	for i := 0; i < 10; i++ {
		req = ag.GenerateRequest("https://example.com")
		detection = detector.AnalyzeRequest(req, nil)
		report = detection.ToDetectionReport()
		fired = report.FiredCheckNames()

		for _, name := range fired {
			if name == "scroll_delta_no_momentum" {
				foundMomentumDeficit = true
				break
			}
		}
		if foundMomentumDeficit {
			break
		}
	}

	t.Logf("Round 1: Fired checks: %v", fired)

	if !foundMomentumDeficit {
		t.Fatalf("Failed to trigger scroll_delta_no_momentum natively in 10 attempts.")
	} else {
		t.Logf("Caught: scroll_delta_no_momentum")
	}

	// 2. Apply Feedback (Mutation)
	t.Logf("Applying feedback")
	ag.ApplyFeedback(report)

	// Disable forced detections so Round 2 is evaluated against the actual
	// mutated generator rather than the deliberately broken test profile.
	ag.GetConfig().ForceDetections = false

	// Second round: Should be clean
	t.Logf("Round 2: Generating fixed request")
	req2 := ag.GenerateRequest("https://example.com")

	t.Logf("Round 2: Analyzing request")
	detection2 := detector.AnalyzeRequest(req2, nil)

	fired2 := detection2.ToDetectionReport().FiredCheckNames()
	t.Logf("Round 2: Fired checks: %v", fired2)

	for _, ind := range fired2 {
		if ind == "scroll_delta_no_momentum" {
			t.Errorf("Detection leakage in round 2: %s", ind)
		}
	}
}
