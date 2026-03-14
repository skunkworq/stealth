package adversarial_test

import (
	"fmt"
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
)

// TestAdaptiveEvasionFSM runs the finite state machine loop against the shield.
// When the shield is catching every strategy, the FSM should never converge on
// an evasion state and should fall through to its terminal strategy.
func TestAdaptiveEvasionFSM(t *testing.T) {
	shield := adversarial.NewStealthDetector()
	profiles := []*behavior.BrowserProfile{
		behavior.ChromeWindowsProfile(),
		behavior.ChromeMacOSProfile(),
		behavior.ChromeLinuxProfile(),
		behavior.FirefoxWindowsProfile(),
	}

	maxTrials := len(behavior.DefaultStrategies()) * 3

	for _, profile := range profiles {
		t.Run(profile.Name, func(t *testing.T) {
			fsm := behavior.NewAdaptiveEvasionFSM()

			for trial := 0; trial < maxTrials; trial++ {
				strategy := fsm.CurrentStrategy()

				config := behavior.MaxEvasionConfig(profile)
				config.EvasionStrategy = strategy

				rg := behavior.NewRequestGenerator(config)
				req := rg.GenerateRequest("https://example.com/api/telemetry")
				result := shield.AnalyzeRequest(req, nil)

				fsm.RecordResult(result.Score, result.IsBot)

			}

			strategy := fsm.CurrentStrategy()
			t.Logf("\n%s", fsm.Summary())
			t.Logf("Ended on: %s (fidelity=%.0f%%)", strategy.Name(), strategy.Fidelity()*100)

			if fsm.Converged() {
				t.Errorf("FSM should not converge on an evasion strategy")
			}
			if fsm.StateIndex() != len(behavior.DefaultStrategies())-1 {
				t.Errorf("FSM should fall through to the final defensive state, got state %d", fsm.StateIndex())
			}
		})
	}
}

// TestEvasionStrategyComparison runs every strategy independently against the
// shield for every profile and reports a fidelity vs detection matrix.
func TestEvasionStrategyComparison(t *testing.T) {
	shield := adversarial.NewStealthDetector()
	profiles := []*behavior.BrowserProfile{
		behavior.ChromeWindowsProfile(),
		behavior.ChromeMacOSProfile(),
		behavior.ChromeLinuxProfile(),
		behavior.FirefoxWindowsProfile(),
	}
	strategies := behavior.DefaultStrategies()
	trials := 20

	t.Logf("\n%-24s %-22s  %8s  %8s  %10s  %s",
		"Profile", "Strategy", "Fidelity", "Det%", "AvgScore", "Result")
	t.Logf("%-24s %-22s  %8s  %8s  %10s  %s",
		"-------", "--------", "--------", "----", "--------", "------")

	for _, profile := range profiles {
		for _, strategy := range strategies {
			detections := 0
			var totalScore float64
			indicators := make(map[string]int)

			for i := 0; i < trials; i++ {
				config := behavior.MaxEvasionConfig(profile)
				config.EvasionStrategy = strategy

				rg := behavior.NewRequestGenerator(config)
				req := rg.GenerateRequest("https://example.com/api/telemetry")
				result := shield.AnalyzeRequest(req, nil)

				totalScore += result.Score
				if result.IsBot {
					detections++
				}
				for _, ind := range result.Indicators {
					indicators[ind.Name]++
				}
			}

			avgScore := totalScore / float64(trials)
			detRate := float64(detections) / float64(trials)
			status := "WEAK"
			if detRate >= 0.95 {
				status = "CAUGHT"
			}

			t.Logf("%-24s %-22s  %7.0f%%  %7.0f%%  %9.3f  %s",
				profile.Name, strategy.Name(),
				strategy.Fidelity()*100, detRate*100, avgScore, status)

			if detRate < 0.95 {
				t.Errorf("%s/%s detection %.0f%% < 95%%", profile.Name, strategy.Name(), detRate*100)
			}
			if avgScore < 0.50 {
				t.Errorf("%s/%s avg score %.3f < 0.50", profile.Name, strategy.Name(), avgScore)
			}

			// Show top indicators if any detection occurred
			if detRate > 0 {
				type hit struct {
					name  string
					count int
				}
				var hits []hit
				for name, count := range indicators {
					hits = append(hits, hit{name, count})
				}
				for i := 0; i < len(hits); i++ {
					for j := i + 1; j < len(hits); j++ {
						if hits[j].count > hits[i].count {
							hits[i], hits[j] = hits[j], hits[i]
						}
					}
				}
				for k := 0; k < len(hits) && k < 3; k++ {
					t.Logf("  %55s  %s (%d/%d)",
						"", hits[k].name, hits[k].count, trials)
				}
			}
		}
	}
}

// TestFSMFallbackConvergence verifies the FSM exhausts the strategy list when
// the shield keeps detecting every attempt.
func TestFSMFallbackConvergence(t *testing.T) {
	shield := adversarial.NewStealthDetector()
	profile := behavior.ChromeWindowsProfile()

	fsm := behavior.NewAdaptiveEvasionFSM()

	for trial := 0; trial < 30; trial++ {
		strategy := fsm.CurrentStrategy()

		config := behavior.MaxEvasionConfig(profile)
		config.EvasionStrategy = strategy

		rg := behavior.NewRequestGenerator(config)
		req := rg.GenerateRequest("https://example.com/api/telemetry")
		result := shield.AnalyzeRequest(req, nil)

		fsm.RecordResult(result.Score, result.IsBot)
	}

	t.Logf("\n%s", fsm.Summary())

	if fsm.Converged() {
		t.Error("FSM should not converge on an evasion strategy")
	}

	strategy := fsm.CurrentStrategy()
	t.Logf("Final strategy: %s (fidelity=%.0f%%)", strategy.Name(), strategy.Fidelity()*100)

	if fsm.StateIndex() != len(behavior.DefaultStrategies())-1 {
		t.Fatalf("FSM should end on the terminal strategy, got state %d", fsm.StateIndex())
	}

	// Verify the terminal strategy is still detected consistently.
	config := behavior.MaxEvasionConfig(profile)
	config.EvasionStrategy = strategy

	detectionCount := 0
	for i := 0; i < 20; i++ {
		rg := behavior.NewRequestGenerator(config)
		req := rg.GenerateRequest("https://example.com/api/telemetry")
		result := shield.AnalyzeRequest(req, nil)
		if result.IsBot {
			detectionCount++
		}
	}

	detectionRate := float64(detectionCount) / 20.0
	t.Logf("Verification: %s detected %.0f%%", strategy.Name(), detectionRate*100)

	if detectionRate < 0.95 {
		t.Errorf("terminal strategy %q detected %.0f%% (want >= 95%%)", strategy.Name(), detectionRate*100)
	}
}

// TestFidelityPreservation verifies high-fidelity strategies preserve data.
func TestFidelityPreservation(t *testing.T) {
	profile := behavior.ChromeWindowsProfile()
	strategies := behavior.DefaultStrategies()

	headerNames := []string{
		"X-Navigator-Data", "X-WebGL-Data", "X-Plugin-Data",
		"X-Screen-Data", "X-Font-Data", "X-WebRTC-Data",
		"X-Behavioral-Data", "X-Timing-Data",
		"X-Canvas-Fingerprint", "X-Audio-Data",
	}

	for _, strategy := range strategies {
		t.Run(strategy.Name(), func(t *testing.T) {
			config := behavior.MaxEvasionConfig(profile)
			config.EvasionStrategy = strategy

			rg := behavior.NewRequestGenerator(config)
			req := rg.GenerateRequest("https://example.com/api/telemetry")

			headerPresent := 0
			for _, h := range headerNames {
				if req.Header.Get(h) != "" {
					headerPresent++
				}
			}

			bodyHasData := false
			if req.Body != nil {
				buf := make([]byte, 64*1024)
				n, _ := req.Body.Read(buf)
				bodyStr := string(buf[:n])
				for _, kw := range []string{"navigator", "timing", "canvas", "audio", "webgl"} {
					if len(bodyStr) > 0 && containsStr(bodyStr, kw) {
						bodyHasData = true
						break
					}
				}
			}

			t.Logf("%-22s: headers_present=%d/10 body_has_data=%v fidelity=%.0f%%",
				strategy.Name(), headerPresent, bodyHasData, strategy.Fidelity()*100)

			// High-fidelity strategies must have data somewhere
			if strategy.Fidelity() >= 0.9 {
				if headerPresent < 5 && !bodyHasData {
					t.Errorf("high-fidelity strategy %q preserves no data (headers=%d, body=%v)",
						strategy.Name(), headerPresent, bodyHasData)
				}
			}
		})
	}
}

// TestArmedSwordWithAdaptiveStrategy verifies the shield catches the armed
// sword's adaptive strategy across all browser profiles.
func TestArmedSwordWithAdaptiveStrategy(t *testing.T) {
	shield := adversarial.NewStealthDetector()
	profiles := []*behavior.BrowserProfile{
		behavior.ChromeWindowsProfile(),
		behavior.ChromeMacOSProfile(),
		behavior.ChromeLinuxProfile(),
		behavior.FirefoxWindowsProfile(),
	}

	trials := 20
	totalDetections := 0
	totalTrials := 0
	var totalScore float64

	for _, profile := range profiles {
		t.Run(fmt.Sprintf("adaptive_%s", profile.Name), func(t *testing.T) {
			detections := 0
			var score float64

			for i := 0; i < trials; i++ {
				config := behavior.MaxEvasionConfig(profile)
				rg := behavior.NewRequestGenerator(config)
				req := rg.GenerateRequest("https://example.com/api/telemetry")
				result := shield.AnalyzeRequest(req, nil)

				score += result.Score
				if result.IsBot {
					detections++
				}
			}

			avgScore := score / float64(trials)
			detectionRate := float64(detections) / float64(trials)
			totalDetections += detections
			totalTrials += trials
			totalScore += score

			t.Logf("Adaptive %s: detection=%.0f%% avg_score=%.3f",
				profile.Name, detectionRate*100, avgScore)

			if detectionRate < 0.95 {
				t.Errorf("adaptive strategy detected %.0f%% (want >= 95%%)", detectionRate*100)
			}
			if avgScore < 0.50 {
				t.Errorf("adaptive strategy avg_score=%.3f (want >= 0.50)", avgScore)
			}
		})
	}

	overallDetectionRate := float64(totalDetections) / float64(totalTrials)
	overallAvgScore := totalScore / float64(totalTrials)
	t.Logf("\nOverall: detection=%.0f%% avg_score=%.3f",
		overallDetectionRate*100, overallAvgScore)

	if overallDetectionRate < 0.95 {
		t.Errorf("expected overall detection >= 95%%, got %.0f%%", overallDetectionRate*100)
	}
	if overallAvgScore < 0.50 {
		t.Errorf("expected overall avg score >= 0.50, got %.3f", overallAvgScore)
	}
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
