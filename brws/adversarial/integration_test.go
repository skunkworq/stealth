package adversarial

import (
	"context"
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/stealth/brwslab/brws/engine"
	_ "github.com/stealth/brwslab/brws/engine/native"
)

func TestStealthClient_AgainstAdversarialServer(t *testing.T) {
	server := NewTestServer()
	defer server.Close()

	t.Run("Native engine with default headers", func(t *testing.T) {
		server.ClearDetections()

		eng, err := engine.New("native", engine.Options{
			HTTP2: false,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer eng.Close()

		resp, err := eng.Do(context.Background(), &engine.Request{
			URL:    server.URL,
			Method: "GET",
		})
		if err != nil {
			t.Fatal(err)
		}

		detection := server.GetLastDetection()
		if detection == nil {
			t.Fatal("Expected detection record")
		}

		t.Logf("=== Native Engine Test Results ===")
		t.Logf("Detection: is_bot=%v, score=%.2f", detection.IsBot, detection.Score)
		t.Logf("Status: %d", resp.Status)
		t.Logf("Request Headers:")
		for k, v := range detection.Request.Headers {
			t.Logf("  %s: %v", k, v)
		}
		t.Logf("Vector Results:")
		for _, vr := range detection.VectorResults {
			t.Logf("  - %s: detected=%v, score=%.2f", vr.Vector, vr.Detected, vr.Score)
			for _, ind := range vr.Indicators {
				t.Logf("      * %s: %s", ind.Check, ind.Message)
			}
		}

		if detection.IsBot {
			t.Logf("FAIL: Native engine detected as bot")
			for _, ind := range detection.Indicators {
				t.Logf("  Detection reason: %s - %s", ind.Name, ind.Message)
			}
		} else {
			t.Logf("PASS: Native engine not detected as bot")
		}
	})

	t.Run("Native engine with Stealth mode", func(t *testing.T) {
		server.ClearDetections()

		eng, err := engine.New("native", engine.Options{
			HTTP2:   false,
			Stealth: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer eng.Close()

		resp, err := eng.Do(context.Background(), &engine.Request{
			URL:    server.URL,
			Method: "GET",
		})
		if err != nil {
			t.Fatal(err)
		}

		detection := server.GetLastDetection()
		if detection == nil {
			t.Fatal("Expected detection record")
		}

		t.Logf("=== Native Engine Stealth Mode Test Results ===")
		t.Logf("Detection: is_bot=%v, score=%.2f", detection.IsBot, detection.Score)
		t.Logf("Status: %d", resp.Status)
		t.Logf("Request Headers:")
		for k, v := range detection.Request.Headers {
			t.Logf("  %s: %v", k, v)
		}
		t.Logf("Vector Results:")
		for _, vr := range detection.VectorResults {
			t.Logf("  - %s: detected=%v, score=%.2f", vr.Vector, vr.Detected, vr.Score)
			for _, ind := range vr.Indicators {
				t.Logf("      * %s: %s", ind.Check, ind.Message)
			}
		}

		if detection.IsBot {
			t.Errorf("FAIL: Stealth mode detected as bot (score=%.2f)", detection.Score)
			for _, ind := range detection.Indicators {
				t.Logf("  Detection reason: %s - %s", ind.Name, ind.Message)
			}
		} else {
			t.Logf("PASS: Stealth mode not detected as bot")
		}
	})

	t.Run("Native engine with StealthTLS (TLS fingerprint spoofing)", func(t *testing.T) {
		server.ClearDetections()

		eng, err := engine.New("native", engine.Options{
			HTTP2:      false,
			StealthTLS: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer eng.Close()

		resp, err := eng.Do(context.Background(), &engine.Request{
			URL:    server.URL,
			Method: "GET",
		})
		if err != nil {
			t.Fatal(err)
		}

		detection := server.GetLastDetection()
		if detection == nil {
			t.Fatal("Expected detection record")
		}

		t.Logf("=== Native Engine StealthTLS Test Results ===")
		t.Logf("Detection: is_bot=%v, score=%.2f", detection.IsBot, detection.Score)
		t.Logf("Status: %d", resp.Status)
		t.Logf("Request Headers:")
		for k, v := range detection.Request.Headers {
			t.Logf("  %s: %v", k, v)
		}
		t.Logf("Vector Results:")
		for _, vr := range detection.VectorResults {
			t.Logf("  - %s: detected=%v, score=%.2f", vr.Vector, vr.Detected, vr.Score)
			for _, ind := range vr.Indicators {
				t.Logf("      * %s: %s", ind.Check, ind.Message)
			}
		}

		if detection.IsBot {
			t.Errorf("FAIL: StealthTLS detected as bot (score=%.2f)", detection.Score)
			for _, ind := range detection.Indicators {
				t.Logf("  Detection reason: %s - %s", ind.Name, ind.Message)
			}
		} else {
			t.Logf("PASS: StealthTLS not detected as bot")
		}
	})

	t.Run("Native engine with spoofed Chrome headers", func(t *testing.T) {
		server.ClearDetections()

		eng, err := engine.New("native", engine.Options{
			HTTP2: false,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer eng.Close()

		spoofedHeaders := map[string]string{
			"User-Agent":                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			"Accept-Language":           "en-US,en;q=0.5",
			"Accept-Encoding":           "gzip, deflate, br",
			"Sec-Ch-Ua":                 "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"",
			"Sec-Ch-Ua-Mobile":          "?0",
			"Sec-Ch-Ua-Platform":        "\"macOS\"",
			"Sec-Fetch-Dest":            "document",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-User":            "?1",
			"Upgrade-Insecure-Requests": "1",
		}

		resp, err := eng.Do(context.Background(), &engine.Request{
			URL:          server.URL,
			Method:       "GET",
			ExtraHeaders: spoofedHeaders,
		})
		if err != nil {
			t.Fatal(err)
		}

		detection := server.GetLastDetection()
		if detection == nil {
			t.Fatal("Expected detection record")
		}

		t.Logf("=== Spoofed Headers Test Results ===")
		t.Logf("Detection: is_bot=%v, score=%.2f", detection.IsBot, detection.Score)
		t.Logf("Status: %d", resp.Status)
		t.Logf("Request Headers:")
		for k, v := range detection.Request.Headers {
			t.Logf("  %s: %v", k, v)
		}
		t.Logf("Vector Results:")
		for _, vr := range detection.VectorResults {
			t.Logf("  - %s: detected=%v, score=%.2f", vr.Vector, vr.Detected, vr.Score)
			for _, ind := range vr.Indicators {
				t.Logf("      * %s: %s", ind.Check, ind.Message)
			}
		}

		if detection.IsBot {
			t.Logf("FAIL: Spoofed headers detected as bot")
			for _, ind := range detection.Indicators {
				t.Logf("  Detection reason: %s - %s", ind.Name, ind.Message)
			}
		} else {
			t.Logf("PASS: Spoofed headers not detected as bot")
		}
	})
}

func TestStealthClient_DetailedAnalysis(t *testing.T) {
	server := NewFingerprintTestServer()
	defer server.Close()

	t.Run("Full fingerprint analysis", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}

		req, _ := http.NewRequest("GET", server.URL, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		req.Header.Set("Sec-Ch-Ua", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"")
		req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
		req.Header.Set("Sec-Ch-Ua-Platform", "\"macOS\"")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		detection := server.GetLastDetection()
		if detection == nil {
			t.Fatal("Expected detection")
		}

		t.Logf("=== Detailed Fingerprint Analysis ===")
		t.Logf("Should Block: %v", detection.ShouldBlock)
		t.Logf("Block Reason: %s", detection.BlockReason)
		t.Logf("Bot Score: %.2f", detection.Analysis.BotScore)
		t.Logf("Is Bot: %v", detection.Analysis.IsBot)
		t.Logf("Confidence: %.2f", detection.Analysis.Confidence)

		t.Logf("\nVector Results:")
		for _, vr := range detection.Analysis.VectorResults {
			t.Logf("  Vector: %s", vr.Vector)
			t.Logf("    Detected: %v, Score: %.2f", vr.Detected, vr.Score)
			for _, ind := range vr.Indicators {
				t.Logf("    - %s: %s", ind.Check, ind.Message)
			}
		}

		t.Logf("\nAnomalies:")
		for _, a := range detection.Analysis.Anomalies {
			t.Logf("  - %s", a)
		}

		t.Logf("\nHTTP Request Headers:")
		for k, v := range detection.HTTPRequest.Headers {
			t.Logf("  %s: %s", k, v)
		}
	})
}

func TestHeaderSpoofingAnalysis(t *testing.T) {
	server := NewTestServer()
	defer server.Close()

	testCases := []struct {
		name        string
		headers     map[string]string
		expectBot   bool
		description string
	}{
		{
			name: "Perfect Chrome headers",
			headers: map[string]string{
				"User-Agent":                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
				"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
				"Accept-Language":           "en-US,en;q=0.5",
				"Accept-Encoding":           "gzip, deflate, br",
				"Sec-Ch-Ua":                 "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"",
				"Sec-Ch-Ua-Mobile":          "?0",
				"Sec-Ch-Ua-Platform":        "\"macOS\"",
				"Sec-Fetch-Dest":            "document",
				"Sec-Fetch-Mode":            "navigate",
				"Sec-Fetch-Site":            "none",
				"Sec-Fetch-User":            "?1",
				"Upgrade-Insecure-Requests": "1",
			},
			expectBot:   false,
			description: "Complete Chrome headers should pass",
		},
		{
			name: "Missing Accept-Language",
			headers: map[string]string{
				"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
				"Accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			},
			expectBot:   true,
			description: "Missing headers should be detected",
		},
		{
			name: "Inconsistent Client Hints",
			headers: map[string]string{
				"User-Agent":         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
				"Sec-Ch-Ua":          "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\"",
				"Sec-Ch-Ua-Platform": "\"Linux\"",
			},
			expectBot:   true,
			description: "Inconsistent platform hints should be detected",
		},
		{
			name: "Minimal headers only",
			headers: map[string]string{
				"User-Agent": "Mozilla/5.0",
			},
			expectBot:   true,
			description: "Minimal headers should be detected",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server.ClearDetections()

			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}

			req, _ := http.NewRequest("GET", server.URL, nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			detection := server.GetLastDetection()

			t.Logf("=== Test: %s ===", tc.name)
			t.Logf("Description: %s", tc.description)
			t.Logf("Expected bot: %v, Got bot: %v", tc.expectBot, detection.IsBot)
			t.Logf("Score: %.2f", detection.Score)

			if detection.IsBot {
				for _, ind := range detection.Indicators {
					t.Logf("  Indicator: %s - %s", ind.Name, ind.Message)
				}
			}

			if tc.expectBot && !detection.IsBot {
				t.Logf("WARNING: Expected bot detection but passed")
			}
		})
	}
}

func TestRoundTripDetection(t *testing.T) {
	server := NewTestServer()
	defer server.Close()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 30 * time.Second,
	}

	req, _ := http.NewRequest("GET", server.URL, nil)

	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
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

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	detection := server.GetLastDetection()

	t.Logf("=== Round Trip Detection Test ===")
	t.Logf("Request time: %v", elapsed)
	t.Logf("Response status: %s", resp.Status)
	t.Logf("Bot detected: %v", detection.IsBot)
	t.Logf("Bot score: %.2f", detection.Score)

	if detection.IsBot {
		t.Logf("\nFAIL: Request was detected as bot")
		t.Logf("Indicators:")
		for _, ind := range detection.Indicators {
			t.Logf("  [%s] %s: %s", ind.Category, ind.Name, ind.Message)
		}
	} else {
		t.Logf("\nPASS: Request was not detected as bot")
	}
}

func TestBrowserProfiles(t *testing.T) {
	server := NewTestServer()
	defer server.Close()

	testCases := []struct {
		name        string
		profileName string
		expectBot   bool
	}{
		{
			name:        "Chrome 120 macOS",
			profileName: "chrome-120-macos",
			expectBot:   false,
		},
		{
			name:        "Chrome 120 Windows",
			profileName: "chrome-120-windows",
			expectBot:   false,
		},
		{
			name:        "Firefox 120 Windows",
			profileName: "firefox-120-windows",
			expectBot:   false,
		},
		{
			name:        "Safari 16 macOS",
			profileName: "safari-16-macos",
			expectBot:   false,
		},
		{
			name:        "Edge 120 Windows",
			profileName: "edge-120-windows",
			expectBot:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server.ClearDetections()

			eng, err := engine.New("native", engine.Options{
				ProfileName: tc.profileName,
				Stealth:     true,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer eng.Close()

			resp, err := eng.Do(context.Background(), &engine.Request{
				URL:    server.URL,
				Method: "GET",
			})
			if err != nil {
				t.Fatal(err)
			}

			detection := server.GetLastDetection()
			t.Logf("Profile: %s, Bot: %v, Score: %.2f, Status: %d",
				tc.profileName, detection.IsBot, detection.Score, resp.Status)

			if tc.expectBot && !detection.IsBot {
				t.Errorf("Expected bot detection for profile %s", tc.profileName)
			}
			if !tc.expectBot && detection.IsBot {
				t.Errorf("Unexpected bot detection for profile %s", tc.profileName)
			}
		})
	}
}
