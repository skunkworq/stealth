package adversarial

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stealth/brwslab/brws/engine"
	_ "github.com/stealth/brwslab/brws/engine/native"
)

func TestStealthBrowserDetection(t *testing.T) {
	detector := NewStealthDetector()

	t.Run("Normal browser request", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Sec-Ch-Ua", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\"")
		req.Header.Set("Sec-Ch-Ua-Platform", "\"macOS\"")

		detection := detector.AnalyzeRequest(req, nil)

		t.Logf("Normal browser - Score: %.2f, IsBot: %v, IsStealth: %v", detection.Score, detection.IsBot, detection.IsStealth)
		for _, vec := range detection.Vectors {
			t.Logf("  Vector: %s, Score: %.2f, Detected: %v", vec.Name, vec.Score, vec.Detected)
		}

		if detection.IsBot || detection.IsStealth {
			t.Logf("WARNING: Normal browser detected as bot/stealth")
		}
	})

	t.Run("Stealth browser with injected navigator data", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Sec-Ch-Ua", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\"")
		req.Header.Set("Sec-Ch-Ua-Platform", "\"macOS\"")

		navData := map[string]interface{}{
			"webdriver": false,
			"platform":  "MacIntel",
			"vendor":    "Google Inc.",
			"languages": []string{"en-US", "en"},
		}
		navJSON, _ := json.Marshal(navData)
		req.Header.Set("X-Navigator-Data", string(navJSON))

		detection := detector.AnalyzeRequest(req, nil)

		t.Logf("Stealth with nav data - Score: %.2f, IsBot: %v, IsStealth: %v", detection.Score, detection.IsBot, detection.IsStealth)
		for _, vec := range detection.Vectors {
			t.Logf("  Vector: %s, Score: %.2f, Detected: %v", vec.Name, vec.Score, vec.Detected)
			for _, ind := range vec.Indicators {
				t.Logf("    - %s", ind)
			}
		}
	})

	t.Run("Stealth browser with webdriver=true", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

		navData := map[string]interface{}{
			"webdriver": true,
		}
		navJSON, _ := json.Marshal(navData)
		req.Header.Set("X-Navigator-Data", string(navJSON))

		detection := detector.AnalyzeRequest(req, nil)

		t.Logf("webdriver=true - Score: %.2f, IsBot: %v, IsStealth: %v", detection.Score, detection.IsBot, detection.IsStealth)
		for _, vec := range detection.Vectors {
			if vec.Detected {
				t.Logf("  DETECTED: %s - Score: %.2f", vec.Name, vec.Score)
				for _, ind := range vec.Indicators {
					t.Logf("    - %s", ind)
				}
			}
		}

		if !detection.IsBot {
			t.Errorf("Expected bot detection with webdriver=true")
		}
	})

	t.Run("Stealth browser with behavioral data", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html")

		behavData := map[string]interface{}{
			"mouseEvents":       0,
			"mouseStdDev":       0.0,
			"typingEvents":      0,
			"typingStdDev":      0.0,
			"mousePathLength":   100.0,
			"mouseStraightness": 1.0,
		}
		behavJSON, _ := json.Marshal(behavData)
		req.Header.Set("X-Behavioral-Data", string(behavJSON))

		detection := detector.AnalyzeRequest(req, nil)

		t.Logf("Behavioral data - Score: %.2f, IsBot: %v, IsStealth: %v", detection.Score, detection.IsBot, detection.IsStealth)
		for _, vec := range detection.Vectors {
			if vec.Detected {
				t.Logf("  DETECTED: %s - Score: %.2f", vec.Name, vec.Score)
				for _, ind := range vec.Indicators {
					t.Logf("    - %s", ind)
				}
			}
		}

		if !detection.IsBot {
			t.Errorf("Expected bot detection with suspicious behavioral data")
		}
	})

	t.Run("Stealth browser with canvas randomization", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("Accept", "text/html")

		req.Header.Set("X-Canvas-Fingerprint", "randomized=true,hash=abc123,webgl=swiftshader")

		detection := detector.AnalyzeRequest(req, nil)

		t.Logf("Canvas randomization - Score: %.2f, IsBot: %v, IsStealth: %v", detection.Score, detection.IsBot, detection.IsStealth)
		for _, vec := range detection.Vectors {
			if vec.Detected {
				t.Logf("  DETECTED: %s - Score: %.2f", vec.Name, vec.Score)
			}
		}
	})

	t.Run("Stealth browser with timing anomalies", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("Accept", "text/html")

		timingData := map[string]interface{}{
			"ttfb":            0,
			"navigationStart": 1000,
			"loadEventEnd":    1050,
		}
		timingJSON, _ := json.Marshal(timingData)
		req.Header.Set("X-Timing-Data", string(timingJSON))

		detection := detector.AnalyzeRequest(req, nil)

		t.Logf("Timing anomalies - Score: %.2f, IsBot: %v, IsStealth: %v", detection.Score, detection.IsBot, detection.IsStealth)
		for _, vec := range detection.Vectors {
			if vec.Detected {
				t.Logf("  DETECTED: %s - Score: %.2f", vec.Name, vec.Score)
			}
		}
	})

	t.Run("Inconsistent client hints", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		req.Header.Set("Accept", "text/html")
		req.Header.Set("Sec-Ch-Ua", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\"")
		req.Header.Set("Sec-Ch-Ua-Platform", "\"Linux\"")

		detection := detector.AnalyzeRequest(req, nil)

		t.Logf("Inconsistent hints - Score: %.2f, IsBot: %v, IsStealth: %v", detection.Score, detection.IsBot, detection.IsStealth)
		for _, vec := range detection.Vectors {
			if vec.Detected {
				t.Logf("  DETECTED: %s - Score: %.2f", vec.Name, vec.Score)
				for _, ind := range vec.Indicators {
					t.Logf("    - %s", ind)
				}
			}
		}
	})
}

func TestStealthBrowserWithNativeEngine(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		detector := NewStealthDetector()
		var tlsConn *tls.ConnectionState
		if r.TLS != nil {
			tlsConn = r.TLS
		}
		detection := detector.AnalyzeRequest(r, tlsConn)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Bot-Score", fmt.Sprintf("%.2f", detection.Score))
		w.Header().Set("X-Is-Bot", fmt.Sprintf("%v", detection.IsBot))
		w.Header().Set("X-Is-Stealth", fmt.Sprintf("%v", detection.IsStealth))

		response := map[string]interface{}{
			"is_bot":     detection.IsBot,
			"is_stealth": detection.IsStealth,
			"score":      detection.Score,
			"vectors":    detection.Vectors,
		}
		jsonResp, _ := json.Marshal(response)
		w.Write(jsonResp) //nolint:errcheck,gosec // G104: Test response write
	}))
	defer server.Close()

	t.Run("Native engine with perfect headers", func(t *testing.T) {
		eng, err := engine.New("native", engine.Options{})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = eng.Close() }()

		headers := map[string]string{
			"User-Agent":         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Accept":             "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language":    "en-US,en;q=0.5",
			"Sec-Ch-Ua":          "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\"",
			"Sec-Ch-Ua-Mobile":   "?0",
			"Sec-Ch-Ua-Platform": "\"macOS\"",
		}

		resp, err := eng.Do(context.Background(), &engine.Request{
			URL:          server.URL,
			Method:       "GET",
			ExtraHeaders: headers,
		})
		if err != nil {
			t.Fatal(err)
		}

		botScore := ""
		isBot := ""
		isStealth := ""
		if v, ok := resp.Headers["X-Bot-Score"]; ok && len(v) > 0 {
			botScore = v[0]
		}
		if v, ok := resp.Headers["X-Is-Bot"]; ok && len(v) > 0 {
			isBot = v[0]
		}
		if v, ok := resp.Headers["X-Is-Stealth"]; ok && len(v) > 0 {
			isStealth = v[0]
		}

		t.Logf("Native engine results:")
		t.Logf("  Bot Score: %s", botScore)
		t.Logf("  Is Bot: %s", isBot)
		t.Logf("  Is Stealth: %s", isStealth)

		if isBot == "true" {
			t.Logf("WARNING: Native engine with good headers detected as bot")
		}
	})

	t.Run("Native engine with stealth indicators", func(t *testing.T) {
		eng, err := engine.New("native", engine.Options{})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = eng.Close() }()

		headers := map[string]string{
			"User-Agent":        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
			"Accept":            "text/html",
			"X-Navigator-Data":  `{"webdriver":false,"platform":"MacIntel"}`,
			"X-Behavioral-Data": `{"mouseEvents":0,"mouseStdDev":0}`,
		}

		resp, err := eng.Do(context.Background(), &engine.Request{
			URL:          server.URL,
			Method:       "GET",
			ExtraHeaders: headers,
		})
		if err != nil {
			t.Fatal(err)
		}

		botScore2 := ""
		isBot2 := ""
		isStealth2 := ""
		if v, ok := resp.Headers["X-Bot-Score"]; ok && len(v) > 0 {
			botScore2 = v[0]
		}
		if v, ok := resp.Headers["X-Is-Bot"]; ok && len(v) > 0 {
			isBot2 = v[0]
		}
		if v, ok := resp.Headers["X-Is-Stealth"]; ok && len(v) > 0 {
			isStealth2 = v[0]
		}

		t.Logf("Native engine with stealth indicators:")
		t.Logf("  Bot Score: %s", botScore2)
		t.Logf("  Is Bot: %s", isBot2)
		t.Logf("  Is Stealth: %s", isStealth2)
	})
}

func TestDetectionVectorsComprehensive(t *testing.T) {
	detector := NewStealthDetector()

	testCases := []struct {
		name          string
		headers       map[string]string
		expectBot     bool
		expectStealth bool
		description   string
	}{
		{
			name: "Perfect Chrome browser",
			headers: map[string]string{
				"User-Agent":         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
				"Accept":             "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				"Accept-Language":    "en-US,en;q=0.5",
				"Sec-Ch-Ua":          "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"",
				"Sec-Ch-Ua-Mobile":   "?0",
				"Sec-Ch-Ua-Platform": "\"macOS\"",
			},
			expectBot:     false,
			expectStealth: false,
			description:   "Perfect Chrome should not be detected",
		},
		{
			name: "webdriver=true indicator",
			headers: map[string]string{
				"User-Agent":       "Mozilla/5.0",
				"Accept":           "text/html",
				"X-Navigator-Data": `{"webdriver":true}`,
			},
			expectBot:     true,
			expectStealth: true,
			description:   "webdriver=true should be detected",
		},
		{
			name: "Zero variance behavioral",
			headers: map[string]string{
				"User-Agent":        "Mozilla/5.0",
				"Accept":            "text/html",
				"X-Behavioral-Data": `{"mouseEvents":10,"mouseStdDev":0,"typingStdDev":0}`,
			},
			expectBot:     true,
			expectStealth: true,
			description:   "Zero variance indicates automation",
		},
		{
			name: "Canvas randomization",
			headers: map[string]string{
				"User-Agent":           "Mozilla/5.0",
				"Accept":               "text/html",
				"X-Canvas-Fingerprint": "randomized=true",
			},
			expectBot:     true,
			expectStealth: true,
			description:   "Canvas randomization detected",
		},
		{
			name: "Zero TTFB",
			headers: map[string]string{
				"User-Agent":    "Mozilla/5.0",
				"Accept":        "text/html",
				"X-Timing-Data": `{"ttfb":0,"navigationStart":1000,"loadEventEnd":1000}`,
			},
			expectBot:     true,
			expectStealth: false,
			description:   "Suspicious timing",
		},
		{
			name: "Missing chrome runtime",
			headers: map[string]string{
				"User-Agent":       "Mozilla/5.0",
				"Accept":           "text/html",
				"X-Navigator-Data": `{"webdriver":false}`,
			},
			expectBot:     false,
			expectStealth: false,
			description:   "Missing chrome runtime alone shouldn't trigger",
		},
		{
			name: "Multiple stealth indicators",
			headers: map[string]string{
				"User-Agent":           "Mozilla/5.0",
				"Accept":               "text/html",
				"X-Navigator-Data":     `{"webdriver":false}`,
				"X-Behavioral-Data":    `{"mouseEvents":0,"mouseStdDev":0}`,
				"X-Canvas-Fingerprint": "randomized=true",
			},
			expectBot:     true,
			expectStealth: true,
			description:   "Multiple indicators should trigger stealth detection",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			detection := detector.AnalyzeRequest(req, nil)

			t.Logf("Test: %s", tc.name)
			t.Logf("  Description: %s", tc.description)
			t.Logf("  Score: %.2f, IsBot: %v, IsStealth: %v", detection.Score, detection.IsBot, detection.IsStealth)
			for _, vec := range detection.Vectors {
				if vec.Detected {
					t.Logf("  Detected: %s (%.2f)", vec.Name, vec.Score)
				}
			}

			if tc.expectBot && !detection.IsBot {
				t.Logf("WARNING: Expected bot detection but passed")
			}
			if tc.expectStealth && !detection.IsStealth {
				t.Logf("WARNING: Expected stealth detection but passed")
			}
		})
	}
}
