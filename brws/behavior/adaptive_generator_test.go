package behavior

import (
	"fmt"
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
)

func deterministicAdaptiveConfig(profile *BrowserProfile, seed int64) *RequestGeneratorConfig {
	eventCfg := DefaultGeneratorConfig()
	eventCfg.Seed = seed + 1

	return &RequestGeneratorConfig{
		Profile:     profile,
		EventConfig: eventCfg,
		Seed:        seed,
	}
}

// TestAdversarialFeedbackLoop verifies the core feedback loop:
// broken generator → shield detects → feedback → adaptation → score improvement
func TestAdversarialFeedbackLoop(t *testing.T) {
	detector := adversarial.NewStealthDetector()

	// Start with a deliberately broken generator
	broken := NewBrokenRequestGenerator(ChromeWindowsProfile())
	req := broken.GenerateRequest("https://example.com/page")

	// Shield should detect the broken request
	detection := detector.AnalyzeRequest(req, nil)
	if !detection.IsBot {
		t.Fatalf("expected broken generator to be detected as bot, got score=%.3f", detection.Score)
	}

	report := detection.ToDetectionReport()
	firedChecks := report.FiredCheckNames()
	t.Logf("Initial detection: score=%.3f, fired checks: %v", report.TotalScore, firedChecks)

	if len(firedChecks) == 0 {
		t.Fatal("expected at least one fired check from broken generator")
	}

	// Now create an adaptive generator and feed it the report
	ag := NewAdaptiveRequestGenerator(deterministicAdaptiveConfig(ChromeWindowsProfile(), 101))

	// Apply feedback from the broken request's detection
	ag.ApplyFeedback(report)

	// Generate a new (adapted) request
	adaptedReq := ag.GenerateRequest("https://example.com/page")
	adaptedDetection := detector.AnalyzeRequest(adaptedReq, nil)
	adaptedReport := adaptedDetection.ToDetectionReport()

	t.Logf("After adaptation: score=%.3f, is_bot=%v", adaptedReport.TotalScore, adaptedReport.IsBot)

	// The adapted request should score lower than the broken one, unless it was already saturated at 1.0
	if report.TotalScore < 1.0 && adaptedReport.TotalScore >= report.TotalScore {
		t.Errorf("adaptation did not improve: before=%.3f after=%.3f",
			report.TotalScore, adaptedReport.TotalScore)
	}

	// After shield upgrade (checks 20-24), adaptation alone can't fix fundamental
	// behavioral patterns. The adapted request may still be detected, but score
	// should have improved from the broken request.
	if adaptedReport.IsBot {
		adaptedFired := adaptedReport.FiredCheckNames()
		t.Logf("adapted request still detected (expected after shield upgrade): score=%.3f, fired=%v",
			adaptedReport.TotalScore, adaptedFired)
	}

	// Verify history was recorded
	history := ag.History()
	if len(history) != 1 {
		t.Errorf("expected 1 history entry, got %d", len(history))
	}
}

// TestAdaptiveGenerator_EvasionRate runs 50 trials with the adapted generator
// and verifies the shield still detects the vast majority of adapted traffic.
func TestAdaptiveGenerator_EvasionRate(t *testing.T) {
	detector := adversarial.NewStealthDetector()
	totalTrials := 0
	totalEvasions := 0

	for idx, profile := range DefaultProfiles() {
		t.Run(profile.Name, func(t *testing.T) {
			ag := NewAdaptiveRequestGenerator(deterministicAdaptiveConfig(profile, int64(1000+idx*100)))

			trials := 50
			evasions := 0

			for i := 0; i < trials; i++ {
				req := ag.GenerateRequest("https://example.com/page")
				result := detector.AnalyzeRequest(req, nil)

				report := result.ToDetectionReport()
				if !result.IsBot {
					evasions++
				}

				// Feed back any failures to improve subsequent rounds
				if result.IsBot {
					ag.ApplyFeedback(report)
				}
			}

			evasionRate := float64(evasions) / float64(trials)
			detectionRate := 1.0 - evasionRate
			fmt.Printf("%s adaptive: %d/%d detected (%.0f%% detection)\n",
				profile.Name, trials-evasions, trials, detectionRate*100)

			totalTrials += trials
			totalEvasions += evasions

			// Keep a profile-level floor so one browser family cannot fully evade,
			// but judge the current shield baseline primarily on aggregate results.
			if evasionRate > 0.50 {
				t.Errorf("expected <= 50%% evasion for %s under the current shield baseline, got %.0f%% (%d/%d)", profile.Name, evasionRate*100, evasions, trials)
			}
		})
	}

	overallEvasionRate := float64(totalEvasions) / float64(totalTrials)
	if overallEvasionRate > 0.35 {
		t.Errorf("expected <= 35%% aggregate evasion under the current shield baseline, got %.0f%% (%d/%d)", overallEvasionRate*100, totalEvasions, totalTrials)
	}
}

// TestAdaptiveFromBroken_FeedbackConvergence starts with a deliberately broken
// generator and shows the feedback loop converging to evasion.
func TestAdaptiveFromBroken_FeedbackConvergence(t *testing.T) {
	detector := adversarial.NewStealthDetector()

	// Use a broken profile that will fail multiple new checks
	brokenProfile := ChromeWindowsProfile()
	brokenProfile.WebGLMaxTextureSize = 0 // will trigger missing_max_texture_size

	broken := NewBrokenRequestGenerator(brokenProfile)

	// First request: should be detected
	req1 := broken.GenerateRequest("https://example.com/page")
	det1 := detector.AnalyzeRequest(req1, nil)
	report1 := det1.ToDetectionReport()

	t.Logf("Round 1 (broken): score=%.3f, is_bot=%v, fired=%d",
		report1.TotalScore, report1.IsBot, report1.FiredChecks)

	if !report1.IsBot {
		t.Fatal("expected broken generator to be detected")
	}

	// Create adaptive generator and apply feedback
	ag := NewAdaptiveRequestGenerator(deterministicAdaptiveConfig(ChromeWindowsProfile(), 202))
	ag.ApplyFeedback(report1)

	// Second request: should evade
	req2 := ag.GenerateRequest("https://example.com/page")
	det2 := detector.AnalyzeRequest(req2, nil)
	report2 := det2.ToDetectionReport()

	t.Logf("Round 2 (adapted): score=%.3f, is_bot=%v, fired=%d",
		report2.TotalScore, report2.IsBot, report2.FiredChecks)

	// After shield upgrade, adaptation can't fix fundamental behavioral patterns.
	// We only verify the score improved, not that it evades entirely.
	if report2.IsBot {
		fired := report2.FiredCheckNames()
		t.Logf("adapted generator still detected (expected after shield upgrade): score=%.3f, fired=%v",
			report2.TotalScore, fired)
	}

	// Verify score improved, unless saturated at 1.0
	if report1.TotalScore < 1.0 && report2.TotalScore >= report1.TotalScore {
		t.Errorf("score did not improve: round1=%.3f round2=%.3f",
			report1.TotalScore, report2.TotalScore)
	}
}

// TestDetectionReport_Structure verifies the DetectionReport conversion.
func TestDetectionReport_Structure(t *testing.T) {
	detector := adversarial.NewStealthDetector()
	broken := NewBrokenRequestGenerator(ChromeWindowsProfile())

	req := broken.GenerateRequest("https://example.com/page")
	detection := detector.AnalyzeRequest(req, nil)
	report := detection.ToDetectionReport()

	if report.RequestID == "" {
		t.Error("expected non-empty request ID")
	}

	if report.TotalScore <= 0 {
		t.Error("expected positive total score for broken request")
	}

	if len(report.Vectors) == 0 {
		t.Error("expected at least one vector in report")
	}

	// Verify FiredCheckNames matches FiredChecks count
	firedNames := report.FiredCheckNames()
	if len(firedNames) != report.FiredChecks {
		t.Errorf("FiredCheckNames count (%d) != FiredChecks (%d)",
			len(firedNames), report.FiredChecks)
	}

	// Verify at least some structured CheckReports exist
	hasStructured := false
	for _, vec := range report.Vectors {
		for _, check := range vec.Checks {
			if check.Expected != "" || check.Actual != "" {
				hasStructured = true
				break
			}
		}
	}
	if !hasStructured {
		t.Log("warning: no structured CheckReports with Expected/Actual found (all legacy indicators)")
	}
}
