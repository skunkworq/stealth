package behavior_test

import (
	"testing"

	"github.com/skunkworq/stealth/brws/core/detection"
	"github.com/skunkworq/stealth/brws/stealth/behavior"
)

func TestSendBeaconEvasion(t *testing.T) {
	detector := detection.NewStealthDetector()

	for _, profile := range behavior.DefaultProfiles() {
		t.Run(profile.Name, func(t *testing.T) {
			const trials = 20
			detections := 0
			var totalScore float64

			for i := 0; i < trials; i++ {
				cfg := behavior.MaxEvasionConfig(profile)
				gen := behavior.NewRequestGenerator(cfg)
				req := gen.GenerateRequest("https://example.com/product")
				detection := detector.AnalyzeRequest(req, nil)

				totalScore += detection.Score
				if detection.IsBot {
					detections++
					if i == 0 {
						for _, vec := range detection.Vectors {
							for _, ind := range vec.Indicators {
								t.Logf("  Indicator: %s", ind)
							}
						}
					}
				}
			}

			avgScore := totalScore / float64(trials)
			detRate := float64(detections) / float64(trials)
			t.Logf("%s: detection=%.0f%% avg_score=%.3f", profile.Name, detRate*100, avgScore)
			if detRate > 0.5 {
				t.Errorf("%s: detection rate %.0f%% exceeds 50%% threshold (%d/%d detected)",
					profile.Name, detRate*100, detections, trials)
			}
		})
	}
}
