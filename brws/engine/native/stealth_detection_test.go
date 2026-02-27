package native

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stealth/brwslab/brws/adversarial"
	"github.com/stealth/brwslab/brws/engine"
	"github.com/stealth/brwslab/brws/engine/testserver"
)

func TestAdvancedSpoofingDetection(t *testing.T) {
	// Test with advanced detection that can spot spoofing
	server := testserver.NewWithConfig(&testserver.ServerConfig{
		DetectHTTPFingerprint: true,
	})
	defer server.Close()

	// Test 1: Standard Go client (should be detected as bot)
	t.Run("Standard Go Client Detection", func(t *testing.T) {
		client := &http.Client{}
		resp, _ := client.Get(server.URL + "/headers")
		if resp != nil {
			defer resp.Body.Close()
		}

		lastReq := server.GetLastRequest()
		if lastReq != nil {
			mockReq, _ := http.NewRequest("GET", server.URL, nil)
			for k, v := range lastReq.Headers {
				mockReq.Header.Set(k, v)
			}

			detector := adversarial.NewAdvancedDetection()
			checks := detector.AnalyzeHeaders(mockReq)

			fmt.Printf("\n=== Standard Go Client Detection ===\n")
			for _, c := range checks {
				if c.Score > 0 {
					fmt.Printf("Check: %s, Passed: %v, Score: %.2f, Details: %s\n",
						c.CheckName, c.Passed, c.Score, c.Details)
				}
			}
		}
		server.ClearRequests()
	})

	// Test 2: Native with Chrome stealth (incomplete - missing TLS)
	t.Run("Native Stealth Chrome Detection", func(t *testing.T) {
		eng, _ := New(engine.Options{
			Timeout:     30 * time.Second,
			Stealth:     true,
			ProfileName: "chrome-120-macos",
		})
		defer eng.Close()

		req := &engine.Request{
			Method:  "GET",
			URL:     server.URL + "/headers",
			Timeout: 30 * time.Second,
		}

		ctx := context.Background()
		eng.Do(ctx, req)

		lastReq := server.GetLastRequest()
		if lastReq != nil {
			mockReq, _ := http.NewRequest("GET", server.URL, nil)
			for k, v := range lastReq.Headers {
				mockReq.Header.Set(k, v)
			}

			detector := adversarial.NewAdvancedDetection()
			checks := detector.AnalyzeHeaders(mockReq)

			fmt.Printf("\n=== Native Stealth Chrome Detection ===\n")
			fmt.Printf("User-Agent: %s\n", lastReq.Headers["User-Agent"])
			fmt.Printf("Sec-Ch-Ua: %s\n", lastReq.Headers["Sec-Ch-Ua"])

			hasIssues := false
			for _, c := range checks {
				if c.Score > 0 {
					fmt.Printf("Check: %s, Passed: %v, Score: %.2f, Details: %s\n",
						c.CheckName, c.Passed, c.Score, c.Details)
					hasIssues = true
				}
			}
			if !hasIssues {
				fmt.Println("No detection issues found - spoofing not detected!")
			}
		}
		server.ClearRequests()
	})

	// Test 3: Native with Firefox (incomplete - missing Chrome headers)
	t.Run("Native Stealth Firefox Detection", func(t *testing.T) {
		eng, _ := New(engine.Options{
			Timeout:     30 * time.Second,
			Stealth:     true,
			ProfileName: "firefox-120-macos",
		})
		defer eng.Close()

		req := &engine.Request{
			Method:  "GET",
			URL:     server.URL + "/headers",
			Timeout: 30 * time.Second,
		}

		ctx := context.Background()
		eng.Do(ctx, req)

		lastReq := server.GetLastRequest()
		if lastReq != nil {
			mockReq, _ := http.NewRequest("GET", server.URL, nil)
			for k, v := range lastReq.Headers {
				mockReq.Header.Set(k, v)
			}

			detector := adversarial.NewAdvancedDetection()
			checks := detector.AnalyzeHeaders(mockReq)

			fmt.Printf("\n=== Native Stealth Firefox Detection ===\n")
			fmt.Printf("User-Agent: %s\n", lastReq.Headers["User-Agent"])
			fmt.Printf("Has Sec-Ch-Ua: %v\n", lastReq.Headers["Sec-Ch-Ua"] != "")
			fmt.Printf("Has Sec-Fetch: %v\n", lastReq.Headers["Sec-Fetch-Dest"] != "")

			for _, c := range checks {
				if c.Score > 0 {
					fmt.Printf("Check: %s, Passed: %v, Score: %.2f, Details: %s\n",
						c.CheckName, c.Passed, c.Score, c.Details)
				}
			}
		}
		server.ClearRequests()
	})
}

func TestStealthDetection(t *testing.T) {
	// Create a test server with detection enabled
	server := testserver.NewWithConfig(&testserver.ServerConfig{
		DetectHTTPFingerprint: true,
		DetectTLSFingerprint:  true,
		StrictHeaders:         false,
	})
	defer server.Close()

	// Create stealth engine with Chrome profile
	eng, err := New(engine.Options{
		Timeout:     30 * time.Second,
		HTTP2:       true,
		Stealth:     true,
		ProfileName: "chrome-120-macos",
	})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer eng.Close()

	// Make request
	req := &engine.Request{
		Method: "GET",
		URL:    server.URL + "/headers",
		Headers: map[string][]string{
			"Accept": {"application/json"},
		},
		Timeout: 30 * time.Second,
	}

	ctx := context.Background()
	resp, err := eng.Do(ctx, req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	fmt.Printf("Response status: %d\n", resp.Status)
	fmt.Printf("Response body: %s\n", string(resp.Body))

	// Get the last request captured by server
	lastReq := server.GetLastRequest()
	if lastReq == nil {
		t.Fatal("No request captured")
	}

	fmt.Printf("\n=== Captured Request Info ===\n")
	fmt.Printf("Headers: %v\n", lastReq.Headers)

	// Now analyze with adversarial detector
	detector := adversarial.NewStealthDetector()

	// Create a mock http.Request to analyze
	mockReq, _ := http.NewRequest("GET", server.URL, nil)
	for k, v := range lastReq.Headers {
		mockReq.Header.Set(k, v)
	}

	detection := detector.AnalyzeRequest(mockReq, nil)

	fmt.Printf("\n=== Detection Results ===\n")
	fmt.Printf("Is Bot: %v\n", detection.IsBot)
	fmt.Printf("Score: %.2f\n", detection.Score)
	fmt.Printf("Confidence: %.2f\n", detection.Confidence)

	for _, vec := range detection.Vectors {
		fmt.Printf("\nVector: %s\n", vec.Name)
		fmt.Printf("  Detected: %v\n", vec.Detected)
		fmt.Printf("  Score: %.2f\n", vec.Score)
		for _, ind := range vec.Indicators {
			fmt.Printf("  - %s\n", ind)
		}
	}
}

func TestStealthTLSDetection(t *testing.T) {
	// Create a TLS test server
	server := testserver.NewWithTLS()
	defer server.Close()

	// Create stealth engine with TLS spoofing
	eng, err := New(engine.Options{
		Timeout:     30 * time.Second,
		HTTP2:       true,
		StealthTLS:  true,
		ProfileName: "chrome-120-macos",
	})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer eng.Close()

	// Make request - will fail due to self-signed cert but we can still analyze
	req := &engine.Request{
		Method:  "GET",
		URL:     server.URL + "/fingerprint",
		Timeout: 30 * time.Second,
	}

	ctx := context.Background()
	_, err = eng.Do(ctx, req)

	fmt.Printf("TLS request error (expected with self-signed cert): %v\n", err)

	// Get detection info
	detector := adversarial.NewStealthDetector()
	detection := detector.AnalyzeRequest(nil, nil)

	fmt.Printf("\n=== TLS Detection ===\n")
	fmt.Printf("Is Bot: %v\n", detection.IsBot)
	fmt.Printf("Score: %.2f\n", detection.Score)
}

func TestProfileFingerprintDetection(t *testing.T) {
	// Test different profiles against detection
	profiles := []string{
		"chrome-120-macos",
		"chrome-120-windows",
		"firefox-120-macos",
		"safari-16-macos",
	}

	server := testserver.NewWithConfig(&testserver.ServerConfig{
		DetectHTTPFingerprint: true,
	})
	defer server.Close()

	for _, profileName := range profiles {
		t.Run(profileName, func(t *testing.T) {
			eng, err := New(engine.Options{
				Timeout:     30 * time.Second,
				HTTP2:       true,
				Stealth:     true,
				ProfileName: profileName,
			})
			if err != nil {
				t.Fatalf("Failed to create engine: %v", err)
			}
			defer eng.Close()

			req := &engine.Request{
				Method:  "GET",
				URL:     server.URL + "/headers",
				Timeout: 30 * time.Second,
			}

			ctx := context.Background()
			_, err = eng.Do(ctx, req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}

			lastReq := server.GetLastRequest()
			if lastReq == nil {
				t.Fatal("No request captured")
			}

			fmt.Printf("\n=== Profile: %s ===\n", profileName)
			fmt.Printf("User-Agent: %s\n", lastReq.Headers["User-Agent"])
			fmt.Printf("Sec-Ch-Ua: %s\n", lastReq.Headers["Sec-Ch-Ua"])
			fmt.Printf("Sec-Ch-Ua-Platform: %s\n", lastReq.Headers["Sec-Ch-Ua-Platform"])

			// Analyze with detector
			detector := adversarial.NewStealthDetector()
			mockReq, _ := http.NewRequest("GET", server.URL, nil)
			for k, v := range lastReq.Headers {
				mockReq.Header.Set(k, v)
			}

			detection := detector.AnalyzeRequest(mockReq, nil)
			fmt.Printf("Detection Score: %.2f\n", detection.Score)
			fmt.Printf("Is Bot: %v\n", detection.IsBot)

			server.ClearRequests()
		})
	}
}

func TestNativeVsRealBrowserDetection(t *testing.T) {
	// Compare native stealth vs what a real browser would look like
	server := testserver.NewWithConfig(&testserver.ServerConfig{
		DetectHTTPFingerprint: true,
		StrictHeaders:         true,
	})
	defer server.Close()

	fmt.Println("\n=== Testing Different Request Types ===")

	// Test 1: Standard Go HTTP client (no stealth)
	t.Run("Standard Go Client", func(t *testing.T) {
		client := &http.Client{}
		resp, _ := client.Get(server.URL + "/headers")
		if resp != nil {
			defer resp.Body.Close()
		}

		lastReq := server.GetLastRequest()
		if lastReq != nil {
			fmt.Printf("\nStandard Go Client:\n")
			fmt.Printf("  User-Agent: %s\n", lastReq.Headers["User-Agent"])
			fmt.Printf("  Has Sec-Ch-Ua: %v\n", lastReq.Headers["Sec-Ch-Ua"] != "")
		}
		server.ClearRequests()
	})

	// Test 2: Native with stealth
	t.Run("Native Stealth", func(t *testing.T) {
		eng, _ := New(engine.Options{
			Timeout:     30 * time.Second,
			Stealth:     true,
			ProfileName: "chrome-120-macos",
		})
		defer eng.Close()

		req := &engine.Request{
			Method:  "GET",
			URL:     server.URL + "/headers",
			Timeout: 30 * time.Second,
		}

		ctx := context.Background()
		eng.Do(ctx, req)

		lastReq := server.GetLastRequest()
		if lastReq != nil {
			fmt.Printf("\nNative Stealth (Chrome):\n")
			fmt.Printf("  User-Agent: %s\n", lastReq.Headers["User-Agent"])
			fmt.Printf("  Sec-Ch-Ua: %s\n", lastReq.Headers["Sec-Ch-Ua"])
			fmt.Printf("  Sec-Ch-Ua-Platform: %s\n", lastReq.Headers["Sec-Ch-Ua-Platform"])

			// Analyze
			detector := adversarial.NewStealthDetector()
			mockReq, _ := http.NewRequest("GET", server.URL, nil)
			for k, v := range lastReq.Headers {
				mockReq.Header.Set(k, v)
			}
			detection := detector.AnalyzeRequest(mockReq, nil)
			fmt.Printf("  Detection Score: %.2f\n", detection.Score)
			fmt.Printf("  Is Bot: %v\n", detection.IsBot)
		}
		server.ClearRequests()
	})

	// Test 3: Native with Firefox profile
	t.Run("Native Stealth Firefox", func(t *testing.T) {
		eng, _ := New(engine.Options{
			Timeout:     30 * time.Second,
			Stealth:     true,
			ProfileName: "firefox-120-macos",
		})
		defer eng.Close()

		req := &engine.Request{
			Method:  "GET",
			URL:     server.URL + "/headers",
			Timeout: 30 * time.Second,
		}

		ctx := context.Background()
		eng.Do(ctx, req)

		lastReq := server.GetLastRequest()
		if lastReq != nil {
			fmt.Printf("\nNative Stealth (Firefox):\n")
			fmt.Printf("  User-Agent: %s\n", lastReq.Headers["User-Agent"])
			fmt.Printf("  Has Sec-Ch-Ua: %v\n", lastReq.Headers["Sec-Ch-Ua"] != "")
			fmt.Printf("  Has Sec-Fetch-* headers: %v\n", lastReq.Headers["Sec-Fetch-Dest"] != "")
		}
		server.ClearRequests()
	})
}
