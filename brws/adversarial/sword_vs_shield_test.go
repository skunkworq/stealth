package adversarial_test

import (
	"net/http"
	"testing"

	"github.com/stealth/brwslab/brws/adversarial"
	"github.com/stealth/brwslab/brws/behavior"
)

// TestSwordVsShield runs the actual Sword (behavior.RequestGenerator) against the
// Shield (StealthDetector) across all 4 default profiles. After the sword boost,
// the sword should evade (score < 0.25, IsBot=false).
func TestSwordVsShield(t *testing.T) {
	profiles := behavior.DefaultProfiles()

	for _, profile := range profiles {
		t.Run("sword_"+profile.Name, func(t *testing.T) {
			detector := adversarial.NewStealthDetector()
			gen := behavior.NewRequestGenerator(&behavior.RequestGeneratorConfig{
				Profile: profile,
			})
			req := gen.GenerateRequest("http://test/api/ml/trap")

			detection := detector.AnalyzeRequest(req, nil)

			t.Logf("Profile: %s | Score: %.3f | IsBot: %v", profile.Name, detection.Score, detection.IsBot)
			for _, v := range detection.Vectors {
				if v.Score > 0 {
					t.Logf("  Vector %s: %.3f detected=%v indicators=%v", v.Category, v.Score, v.Detected, v.Indicators)
				}
			}

			if detection.Score >= 0.25 {
				t.Errorf("sword profile %q should evade (score < 0.25), got %.3f", profile.Name, detection.Score)
			}
			if detection.IsBot {
				t.Errorf("sword profile %q should NOT be classified as bot", profile.Name)
			}
		})
	}

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
