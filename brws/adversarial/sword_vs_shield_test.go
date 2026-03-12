package adversarial_test

import (
	"fmt"
	"net/http"
	"sort"
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
	"github.com/skunkworq/stealth/brws/benchmark"
)

// TestSwordVsShield runs the actual Sword (behavior.RequestGenerator) against the
// Shield (StealthDetector) across all 4 default profiles. After the shield upgrade
// (checks 20-24), the sword should be detected >= 70% of the time across 20 trials.
// Single-trial testing is too noisy due to stochastic behavioral generation.
func TestSwordVsShield(t *testing.T) {
	profiles := behavior.DefaultProfiles()

	for _, profile := range profiles {
		t.Run("sword_"+profile.Name, func(t *testing.T) {
			detector := adversarial.NewStealthDetector()

			const trials = 20
			detections := 0
			totalScore := 0.0
			totalConfidence := 0.0
			indicatorCounts := make(map[string]int)

			for i := 0; i < trials; i++ {
				gen := behavior.NewRequestGenerator(&behavior.RequestGeneratorConfig{
					Profile: profile,
				})
				req := gen.GenerateRequest("http://test/api/ml/trap")
				detection := detector.AnalyzeRequest(req, nil)
				totalScore += detection.Score
				totalConfidence += detection.Confidence

				if detection.IsBot {
					if i == 0 {
						for _, vec := range detection.Vectors {
							for _, ind := range vec.Indicators {
								fmt.Println("  Caught:", ind)
							}
						}
					}
					detections++
				}

				for _, vec := range detection.Vectors {
					if !vec.Detected {
						continue
					}
					for _, ind := range vec.Indicators {
						indicatorCounts[ind]++
					}
				}
			}

			detectionRate := float64(detections) / float64(trials)
			avgScore := totalScore / float64(trials)
			avgConfidence := totalConfidence / float64(trials)
			fmt.Printf("  %s: %d/%d detected (%.0f%%) | avg score=%.3f | avg confidence=%.3f\n",
				profile.Name, detections, trials, detectionRate*100, avgScore, avgConfidence)

			type indicatorHit struct {
				name  string
				count int
			}
			topIndicators := make([]indicatorHit, 0, len(indicatorCounts))
			for name, count := range indicatorCounts {
				topIndicators = append(topIndicators, indicatorHit{name: name, count: count})
			}
			sort.Slice(topIndicators, func(i, j int) bool {
				if topIndicators[i].count == topIndicators[j].count {
					return topIndicators[i].name < topIndicators[j].name
				}
				return topIndicators[i].count > topIndicators[j].count
			})
			for i := 0; i < len(topIndicators) && i < 5; i++ {
				fmt.Printf("    top indicator %d: %s (%d/%d)\n", i+1, topIndicators[i].name, topIndicators[i].count, trials)
			}

			if detectionRate < 0.95 {
				t.Errorf("sword profile %q detection rate %.0f%% < 95%% (%d/%d)",
					profile.Name, detectionRate*100, detections, trials)
			}
			if avgScore < 0.90 {
				t.Errorf("sword profile %q avg score %.3f < 0.90", profile.Name, avgScore)
			}
			if avgConfidence < 0.95 {
				t.Errorf("sword profile %q avg confidence %.3f < 0.95", profile.Name, avgConfidence)
			}
		})
	}

	t.Run("library_matrix_comparison", func(t *testing.T) {
		report := benchmark.RunToolComparison(&benchmark.ToolComparisonConfig{
			IncludeBehavioral: true,
			Iterations:        3,
		})

		resultMap := make(map[string]benchmark.ToolResult, len(report.Results))
		for _, result := range report.Results {
			resultMap[result.Tool.Name] = result
		}

		fmt.Println("  Library comparison against the current shield:")
		for _, name := range []string{"our_stealth_sword", "playwright_default", "nodriver", "scrapling_stealthy", "curl_impersonate_ch116"} {
			result, ok := resultMap[name]
			if !ok {
				t.Fatalf("missing tool result for %s", name)
			}
			fmt.Printf("    %-24s detection=%.0f%% avg score=%.3f avg confidence=%.3f\n",
				name, result.DetectionRate*100, result.AvgBotScore, result.AvgConfidence)
		}

		swordResult, ok := resultMap["our_stealth_sword"]
		if !ok {
			t.Fatal("missing tool result for our_stealth_sword")
		}
		if swordResult.DetectionRate < 1.0 {
			t.Fatalf("expected 100%% detection for our_stealth_sword in library matrix, got %.0f%%",
				swordResult.DetectionRate*100)
		}
		if swordResult.AvgConfidence < 0.95 {
			t.Fatalf("expected high sword confidence in library matrix, got %.3f", swordResult.AvgConfidence)
		}
	})

	// Also verify a real browser request is NOT flagged.
	t.Run("real_firefox_should_pass", func(t *testing.T) {
		detector := adversarial.NewStealthDetector()
		req, _ := http.NewRequest("GET", "http://test/", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Upgrade-Insecure-Requests", "1")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-User", "?1")
		req.Header.Set("X-Stealth-Header-Order", "User-Agent,Accept,Accept-Language,Accept-Encoding,Connection,Upgrade-Insecure-Requests,Sec-Fetch-Dest,Sec-Fetch-Mode,Sec-Fetch-Site,Sec-Fetch-User")

		detection := detector.AnalyzeRequest(req, nil)

		t.Logf("Real Firefox | Score: %.3f | IsBot: %v", detection.Score, detection.IsBot)
		for _, v := range detection.Vectors {
			if v.Score > 0 {
				t.Logf("  Vector %s: %.3f detected=%v indicators=%v", v.Category, v.Score, v.Detected, v.Indicators)
			}
		}

		if detection.Score >= 0.20 {
			t.Errorf("real Firefox request should pass (score < 0.20), got %.3f", detection.Score)
		}
		if detection.IsBot {
			t.Error("real Firefox request should not be classified as bot")
		}
	})
}
