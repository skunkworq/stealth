package behavior_test

import (
	"fmt"
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
)

func TestFullBrowserEvasion(t *testing.T) {
	detector := adversarial.NewStealthDetector()

	for _, profile := range behavior.DefaultProfiles() {
		t.Run(profile.Name, func(t *testing.T) {
			const trials = 20
			detections := 0
			var totalScore float64

			for i := 0; i < trials; i++ {
				cfg := behavior.MaxEvasionConfig(profile)
				cfg.EvasionStrategy = &behavior.FullBrowserStrategy{}
				gen := behavior.NewRequestGenerator(cfg)
				req := gen.GenerateRequest("https://api.example.com/telemetry")
				detection := detector.AnalyzeRequest(req, nil)

				totalScore += detection.Score
				if detection.IsBot {
					detections++
					if i == 0 {
						for _, vec := range detection.Vectors {
							if vec.Score > 0 {
								fmt.Printf("  [%.2f] %s: %v\n", vec.Score, vec.Name, vec.Indicators)
							}
						}
					}
				}
			}

			avgScore := totalScore / float64(trials)
			detRate := float64(detections) / float64(trials)
			fmt.Printf("  %s: detection=%.0f%% avg_score=%.3f\n", profile.Name, detRate*100, avgScore)

			if detRate > 0.05 {
				t.Errorf("expected <= 5%% detection for %s, got %.0f%%", profile.Name, detRate*100)
			}
			if avgScore > 0.10 {
				t.Errorf("expected avg_score <= 0.10 for %s, got %.3f", profile.Name, avgScore)
			}
		})
	}
}
