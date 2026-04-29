package challenge

import (
	"net/http/httptest"
	"testing"
)

func TestEvasionDemo(t *testing.T) {
	detector := NewTracingDetector()

	t.Run("Current stealth - INJECTING headers (DETECTED)", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Sec-Ch-Ua", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\"")
		req.Header.Set("Sec-Ch-Ua-Platform", "\"macOS\"")

		// PROBLEM: We're injecting these headers - HUGE red flag!
		req.Header.Set("X-Navigator-Data", `{"webdriver":false,"platform":"MacIntel"}`)
		req.Header.Set("X-Canvas-Fingerprint", "randomized=true")
		req.Header.Set("X-Behavioral-Data", `{"mouseEvents":5,"mouseStdDev":0}`)

		trace := detector.AnalyzeWithTrace(req, nil)

		t.Logf("=== CURRENT STEALTH (injecting headers) ===")
		t.Logf("Score: %.2f | IsBot: %v | Failed: %d", trace.FinalScore, trace.IsBot, len(trace.FailedChecks))

		// This gets detected!
		if trace.IsBot {
			t.Logf("❌ DETECTED because we're injecting fingerprint headers")
		}
	})

	t.Run("FIXED stealth - NO injected headers (PASSES)", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		// Perfect Chrome headers - no injection!
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		req.Header.Set("Sec-Ch-Ua", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"")
		req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
		req.Header.Set("Sec-Ch-Ua-Platform", "\"macOS\"")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-User", "?1")
		req.Header.Set("Upgrade-Insecure-Requests", "1")

		// NO X-Navigator-Data, NO X-Canvas-Fingerprint, NO X-Behavioral-Data!
		// Real browsers don't send these!

		trace := detector.AnalyzeWithTrace(req, nil)

		t.Logf("=== FIXED STEALTH (no injection) ===")
		t.Logf("Score: %.2f | IsBot: %v | Failed: %d", trace.FinalScore, trace.IsBot, len(trace.FailedChecks))

		for _, check := range trace.FailedChecks {
			t.Logf("  - %s: %s", check.CheckName, check.Details)
		}

		if !trace.IsBot {
			t.Logf("✅ PASSED - no detection headers injected!")
		}
	})

	t.Run("What real Chrome looks like", func(t *testing.T) {
		// This is what a real Chrome browser sends - NOTHING extra
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		req.Header.Set("Sec-Ch-Ua", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"")
		req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
		req.Header.Set("Sec-Ch-Ua-Platform", "\"macOS\"")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-User", "?1")
		req.Header.Set("Upgrade-Insecure-Requests", "1")

		trace := detector.AnalyzeWithTrace(req, nil)

		t.Logf("=== REAL CHROME ===")
		t.Logf("Score: %.2f | IsBot: %v | Failed: %d", trace.FinalScore, trace.IsBot, len(trace.FailedChecks))

		// Only failure is that we didn't inject X-Navigator-Data (which is good!)
		for _, check := range trace.FailedChecks {
			t.Logf("  - %s: %s", check.CheckName, check.Details)
		}
	})
}
