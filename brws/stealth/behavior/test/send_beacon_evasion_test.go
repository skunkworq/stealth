package behavior_test

import (
	"fmt"
	"testing"

	"github.com/skunkworq/stealth/brws/stealth/behavior"
	"github.com/skunkworq/stealth/brws/stealth/challenge"
)

func TestSendBeaconEvasion(t *testing.T) {
	detector := challenge.NewStealthDetector()

	for _, profile := range behavior.DefaultProfiles() {
		t.Run(profile.Name, func(t *testing.T) {
			const trials = 20
			detections := 0
			var totalScore float64

			for i := 0; i < trials; i++ {
				cfg := behavior.MaxEvasionConfig(profile)
				cfg.EvasionStrategy = &behavior.FirefoxInitNavStrategy{}
				gen := behavior.NewRequestGenerator(cfg)
				req := gen.GenerateRequest("https://api.example.com/telemetry")
				detection := detector.AnalyzeRequest(req, nil)

				totalScore += detection.Score
				if detection.IsBot {
					detections++
					if i == 0 {
						for _, vec := range detection.Vectors {
							for _, ind := range vec.Indicators {
								fmt.Println("  Indicator:", ind)
							}
						}
					}
				}
			}

			avgScore := totalScore / float64(trials)
			detRate := float64(detections) / float64(trials)
			t.Logf("%s: detection=%.0f%% avg_score=%.3f", profile.Name, detRate*100, avgScore)
		})
	}
}
