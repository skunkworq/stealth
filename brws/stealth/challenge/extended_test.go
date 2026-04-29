package challenge

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestExtendedFingerprintDetection(t *testing.T) {
	detector := NewTracingDetector()

	t.Run("Extended fingerprint analysis - Go http.Client", func(t *testing.T) {
		// This simulates what our stealth browser might look like
		// using Go's native http.Client with spoofed headers
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html")
		// Missing many headers that real Chrome sends

		trace := detector.AnalyzeWithTrace(req, nil)

		t.Logf("=== Go http.Client Fingerprint ===")
		t.Logf("Total Checks: %d", len(trace.AllChecks))
		t.Logf("Score: %.2f | IsBot: %v | IsStealth: %v", trace.FinalScore, trace.IsBot, trace.IsStealth)
		t.Logf("Failed: %d", len(trace.FailedChecks))

		for _, check := range trace.AllChecks {
			status := "✅"
			if !check.Passed {
				status = "❌"
			}
			t.Logf("  %s [%s] %s = %.2f", status, check.Category, check.CheckName, check.Score)
		}
	})

	t.Run("Perfect Chrome fingerprint", func(t *testing.T) {
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

		t.Logf("=== Perfect Chrome Fingerprint ===")
		t.Logf("Total Checks: %d", len(trace.AllChecks))
		t.Logf("Score: %.2f | IsBot: %v | IsStealth: %v", trace.FinalScore, trace.IsBot, trace.IsStealth)

		passed := 0
		for _, check := range trace.AllChecks {
			if check.Passed {
				passed++
			} else {
				t.Logf("  ❌ [%s] %s = %.2f - %s", check.Category, check.CheckName, check.Score, check.Details)
			}
		}
		t.Logf("Passed: %d/%d", passed, len(trace.AllChecks))
	})

	t.Run("Stealth browser with injected canvas - DETECTED", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html")

		// PROBLEM: Injecting canvas fingerprint header - huge red flag!
		req.Header.Set("X-Canvas-Fingerprint", "randomized=true,hash=abc123")

		trace := detector.AnalyzeWithTrace(req, nil)

		t.Logf("=== Stealth with Canvas Injection ===")
		t.Logf("Score: %.2f | IsBot: %v | Failed: %d", trace.FinalScore, trace.IsBot, len(trace.FailedChecks))

		for _, check := range trace.FailedChecks {
			t.Logf("  ❌ [%s] %s", check.CheckName, check.Details)
		}
	})

	t.Run("Stealth with zero variance behavioral - DETECTED", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("Accept", "text/html")

		// Zero variance - mechanical behavior
		behavData := map[string]interface{}{
			"mouseEvents":       10,
			"mouseStdDev":       0.0,
			"mouseStraightness": 1.0,
			"typingStdDev":      0.0,
		}
		behavJSON, _ := json.Marshal(behavData)
		req.Header.Set("X-Behavioral-Data", string(behavJSON))

		trace := detector.AnalyzeWithTrace(req, nil)

		t.Logf("=== Stealth with Zero Variance ===")
		t.Logf("Score: %.2f | IsBot: %v | Failed: %d", trace.FinalScore, trace.IsBot, len(trace.FailedChecks))

		for _, check := range trace.FailedChecks {
			t.Logf("  ❌ [%s] %s - %s", check.Severity, check.CheckName, check.Details)
		}
	})

	t.Run("Inconsistent fingerprint - DETECTED", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		// Windows in User-Agent but Linux in Client Hints - mismatch!
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		req.Header.Set("Accept", "text/html")
		req.Header.Set("Sec-Ch-Ua", "\"Not_A Brand\";v=\"8\"")
		req.Header.Set("Sec-Ch-Ua-Platform", "\"Linux\"")

		trace := detector.AnalyzeWithTrace(req, nil)

		t.Logf("=== Inconsistent Fingerprint ===")
		t.Logf("Score: %.2f | IsBot: %v | Failed: %d", trace.FinalScore, trace.IsBot, len(trace.FailedChecks))

		for _, check := range trace.FailedChecks {
			t.Logf("  ❌ [%s] %s - %s", check.Severity, check.CheckName, check.Details)
		}
	})
}

func TestAllDetectionCategories(t *testing.T) {
	detector := NewTracingDetector()

	// Create a request that triggers multiple detection categories
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("User-Agent", "python-requests/2.28.0")    // Suspicious UA
	req.Header.Set("X-Canvas-Fingerprint", "randomized=true") // Canvas injection
	req.Header.Set("X-Behavioral-Data", `{"mouseStdDev":0}`)  // Zero variance

	trace := detector.AnalyzeWithTrace(req, nil)

	t.Logf("=== Multi-Category Detection ===")
	t.Logf("Score: %.2f | IsBot: %v\n", trace.FinalScore, trace.IsBot)

	// Group by category
	byCategory := make(map[string][]CheckResult)
	for _, check := range trace.AllChecks {
		if !check.Passed {
			byCategory[check.Category] = append(byCategory[check.Category], check)
		}
	}

	for category, checks := range byCategory {
		t.Logf("\n[%s] (%d failures)", category, len(checks))
		for _, c := range checks {
			t.Logf("  - %s: %s (%.2f)", c.CheckName, c.Details, c.Score)
		}
	}
}
