package adversarial

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/skunkworq/stealth/brws/engine"
	_ "github.com/skunkworq/stealth/brws/engine/native"
)

func TestStealthBrowserCatching(t *testing.T) {
	detector := NewStealthDetector()

	t.Run("Our stealth browser signals - should be caught", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Sec-Ch-Ua", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\"")
		req.Header.Set("Sec-Ch-Ua-Platform", "\"macOS\"")

		navData := map[string]interface{}{
			"webdriver":           false,
			"platform":            "MacIntel",
			"vendor":              "Google Inc.",
			"languages":           []string{"en-US", "en"},
			"hardwareConcurrency": 8,
		}
		navJSON, _ := json.Marshal(navData)
		req.Header.Set("X-Navigator-Data", string(navJSON))

		req.Header.Set("X-Canvas-Fingerprint", "randomized=true,hash=c2hha3Mte3M3MTE=")

		behavData := map[string]interface{}{
			"mouseEvents":       5,
			"mouseStdDev":       0.0,
			"mouseStraightness": 1.0,
			"typingEvents":      10,
			"typingStdDev":      0.0,
		}
		behavJSON, _ := json.Marshal(behavData)
		req.Header.Set("X-Behavioral-Data", string(behavJSON))

		detection := detector.AnalyzeRequest(req, nil)

		t.Logf("=== Our Stealth Browser Signals Test ===")
		t.Logf("Score: %.2f", detection.Score)
		t.Logf("IsBot: %v", detection.IsBot)
		t.Logf("IsStealth: %v", detection.IsStealth)
		t.Logf("\nAll Vectors:")
		for _, vec := range detection.Vectors {
			if vec.Detected {
				t.Logf("  [%s] Score: %.2f", vec.Name, vec.Score)
				for _, ind := range vec.Indicators {
					t.Logf("    - %s", ind)
				}
			}
		}

		if !detection.IsBot && !detection.IsStealth {
			t.Errorf("FAIL: Our stealth browser was NOT detected!")
		} else {
			t.Logf("SUCCESS: Our stealth browser was detected!")
		}
	})

	t.Run("Real browser - should NOT be caught", func(t *testing.T) {
		// Use Firefox-style headers (no Client Hints) to represent a real browser
		// without triggering the fingerprint_coverage check for Chrome + no JS data
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Upgrade-Insecure-Requests", "1")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-User", "?1")
		req.Header.Set("DNT", "1")

		detection := detector.AnalyzeRequest(req, nil)

		t.Logf("=== Real Browser Test ===")
		t.Logf("Score: %.2f", detection.Score)
		t.Logf("IsBot: %v", detection.IsBot)
		t.Logf("IsStealth: %v", detection.IsStealth)

		if detection.IsBot {
			t.Errorf("FAIL: Real browser was incorrectly detected as bot!")
		} else {
			t.Logf("SUCCESS: Real browser was NOT detected as bot")
		}
	})

	t.Run("Puppeteer/Playwright - should be caught", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://example.com", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html")

		navData := map[string]interface{}{
			"webdriver": true,
			"puppeteer": true,
		}
		navJSON, _ := json.Marshal(navData)
		req.Header.Set("X-Navigator-Data", string(navJSON))

		detection := detector.AnalyzeRequest(req, nil)

		t.Logf("=== Puppeteer Test ===")
		t.Logf("Score: %.2f", detection.Score)
		t.Logf("IsBot: %v", detection.IsBot)

		if !detection.IsBot {
			t.Errorf("FAIL: Puppeteer was NOT detected!")
		}
	})
}

func TestNativeEngineWithStealthSignals(t *testing.T) {
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

		jsonResp, _ := json.Marshal(map[string]interface{}{
			"is_bot": detection.IsBot,
			"score":  detection.Score,
		})
		w.Write(jsonResp) //nolint:errcheck,gosec // G104: Test response write
	}))
	defer server.Close()

	t.Run("Native engine with stealth signals", func(t *testing.T) {
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

		isBot := ""
		if v, ok := resp.Headers["X-Is-Bot"]; ok && len(v) > 0 {
			isBot = v[0]
		}

		t.Logf("Native engine with stealth signals - IsBot: %s", isBot)

		if isBot == "false" {
			t.Logf("WARNING: Native engine with stealth signals was not detected")
		}
	})
}

func TestDetectionThreshold(t *testing.T) {
	detector := NewStealthDetector()

	testCases := []struct {
		name    string
		setup   func(*http.Request)
		wantBot bool
	}{
		{
			name: "Zero signals - clean",
			setup: func(req *http.Request) {
				req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")
				req.Header.Set("Accept", "text/html,application/xhtml+xml")
				req.Header.Set("Accept-Language", "en-US")
				req.Header.Set("Sec-Ch-Ua", "\"Not_A Brand\";v=\"8\"")
				req.Header.Set("Sec-Ch-Ua-Platform", "\"macOS\"")
			},
			wantBot: false,
		},
		{
			name: "webdriver=true",
			setup: func(req *http.Request) {
				req.Header.Set("User-Agent", "Mozilla/5.0")
				req.Header.Set("X-Navigator-Data", `{"webdriver":true}`)
			},
			wantBot: true,
		},
		{
			name: "Zero variance behavior",
			setup: func(req *http.Request) {
				req.Header.Set("User-Agent", "Mozilla/5.0")
				req.Header.Set("X-Behavioral-Data", `{"mouseEvents":10,"mouseStdDev":0,"typingStdDev":0}`)
			},
			wantBot: true,
		},
		{
			name: "Canvas randomization",
			setup: func(req *http.Request) {
				req.Header.Set("User-Agent", "Mozilla/5.0")
				req.Header.Set("X-Canvas-Fingerprint", "randomized=true")
			},
			wantBot: true,
		},
		{
			name: "Multiple stealth signals",
			setup: func(req *http.Request) {
				req.Header.Set("User-Agent", "Mozilla/5.0")
				req.Header.Set("X-Navigator-Data", `{"webdriver":false}`)
				req.Header.Set("X-Behavioral-Data", `{"mouseEvents":0,"mouseStdDev":0}`)
				req.Header.Set("X-Canvas-Fingerprint", "randomized=true")
			},
			wantBot: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com", nil)
			tc.setup(req)

			detection := detector.AnalyzeRequest(req, nil)

			t.Logf("Test: %s - Score: %.2f, IsBot: %v",
				tc.name, detection.Score, detection.IsBot)

			if tc.wantBot && !detection.IsBot {
				t.Errorf("Expected bot detection")
			}
		})
	}
}
