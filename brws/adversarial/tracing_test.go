package adversarial

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/skunkworq/stealth/brws/engine"
	_ "github.com/skunkworq/stealth/brws/engine/native"
)

func TestDetailedDetectionTrace(t *testing.T) {
	detector := NewTracingDetector()

	t.Run("Trace our stealth browser detection", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Sec-Ch-Ua", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\"")
		req.Header.Set("Sec-Ch-Ua-Platform", "\"macOS\"")

		// Simulate our stealth browser injecting navigator data
		navData := map[string]interface{}{
			"webdriver":           false,
			"platform":            "MacIntel",
			"vendor":              "Google Inc.",
			"languages":           []string{"en-US", "en"},
			"hardwareConcurrency": 8,
		}
		navJSON, _ := json.Marshal(navData)
		req.Header.Set("X-Navigator-Data", string(navJSON))

		// Simulate canvas fingerprinting - THIS IS THE KEY DETECTOR
		req.Header.Set("X-Canvas-Fingerprint", "randomized=true,hash=c2hha3Mte3M3MTE=")

		// Simulate behavioral simulation with ZERO VARIANCE - DETECTED!
		behavData := map[string]interface{}{
			"mouseEvents":       5,
			"mouseStdDev":       0.0, // ZERO - DETECTED!
			"mouseStraightness": 1.0, // PERFECT LINEAR - DETECTED!
			"typingEvents":      10,
			"typingStdDev":      0.0, // ZERO - DETECTED!
		}
		behavJSON, _ := json.Marshal(behavData)
		req.Header.Set("X-Behavioral-Data", string(behavJSON))

		trace := detector.AnalyzeWithTrace(req, nil)

		// Print detailed trace
		detector.PrintTrace(trace)

		t.Logf("\n=== SUMMARY ===")
		t.Logf("Final Score: %.2f", trace.FinalScore)
		t.Logf("Is Bot: %v", trace.IsBot)
		t.Logf("Is Suspicious: %v", trace.IsStealth)
		t.Logf("Failed Checks: %d", len(trace.FailedChecks))

		// What we need to fix:
		t.Logf("\n=== WHAT TO FIX ===")
		for _, check := range trace.FailedChecks {
			t.Logf("- %s: %s (score: %.2f)", check.CheckName, check.Details, check.Score)
		}
	})

	t.Run("Trace real Chrome browser", func(t *testing.T) {
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

		t.Logf("\n=== REAL CHROME ===")
		t.Logf("Final Score: %.2f", trace.FinalScore)
		t.Logf("Is Bot: %v", trace.IsBot)
		t.Logf("Failed Checks: %d", len(trace.FailedChecks))

		for _, check := range trace.FailedChecks {
			t.Logf("  - %s: %s", check.CheckName, check.Details)
		}
	})

	t.Run("Trace our Native Engine with StealthTLS", func(t *testing.T) {
		// Use the actual native engine with StealthTLS
		eng, err := engine.New("native", engine.Options{
			StealthTLS: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = eng.Close() }()

		resp, err := eng.Do(context.Background(), &engine.Request{
			URL:    "http://example.com",
			Method: "GET",
		})
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("Trace entries: %d", len(resp.Trace.Entries))
		if len(resp.Trace.Entries) > 0 {
			t.Logf("Request headers from trace:")
			for k, v := range resp.Trace.Entries[0].Request.Headers {
				t.Logf("  %s: %s", k, v)
			}
		}

		// Reconstruct the request that was sent
		req := httptest.NewRequest("GET", "http://example.com", nil)
		for k, v := range resp.Trace.Entries[0].Request.Headers {
			req.Header.Set(k, v)
		}

		trace := detector.AnalyzeWithTrace(req, nil)

		t.Logf("\n=== NATIVE ENGINE + STEALTHTLS ===")
		t.Logf("Final Score: %.2f", trace.FinalScore)
		t.Logf("Is Bot: %v", trace.IsBot)
		t.Logf("Failed Checks: %d", len(trace.FailedChecks))
		t.Logf("Status: %d", resp.Status)

		t.Logf("\nHeaders sent (from trace):")
		for k, v := range trace.RawHeaders {
			t.Logf("  %s: %s", k, v)
		}

		if len(trace.FailedChecks) > 0 {
			t.Logf("\nFailed checks:")
			for _, check := range trace.FailedChecks {
				t.Logf("  - %s: %s (score: %.2f)", check.CheckName, check.Details, check.Score)
			}
		}
	})
}
