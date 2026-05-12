package native

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/skunkworq/stealth/brws/stealth/challenge"
	"github.com/skunkworq/stealth/brws/browser/engine"
	"github.com/skunkworq/stealth/brws/browser/engine/testutil/testserver"
)

func TestTLSSpoofingWithRealTLS(t *testing.T) {
	// Create TLS test server
	server := testserver.NewWithTLS()
	defer server.Close()

	// Get TLS client config that trusts the server cert
	tlsConfig := server.TLSConfigWithCA()

	fmt.Printf("TLS Server URL: %s\n", server.URL)

	// Test 1: Standard Go HTTP (no spoofing)
	t.Run("Standard Go TLS", func(t *testing.T) {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}

		resp, err := client.Get(server.URL + "/tls")
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		var tlsInfo testserver.TLSInfo
		_ = json.NewDecoder(resp.Body).Decode(&tlsInfo)

		_ = tlsInfo

		fmt.Printf("\n=== Standard Go TLS ===\n")
		fmt.Printf("TLS Version: %s\n", tlsInfo.Version)
		fmt.Printf("Cipher Suite: %s\n", tlsInfo.CipherSuite)
		fmt.Printf("JA4: %s\n", tlsInfo.JA4)
		fmt.Printf("Negotiated Proto: %s\n", tlsInfo.NegotiatedProto)

		// Test detection
		ad := challenge.NewAdvancedDetection()

		var version uint16
		_, _ = fmt.Sscanf(tlsInfo.Version, "%x", &version)
		var cipherSuite uint16
		_, _ = fmt.Sscanf(tlsInfo.CipherSuite, "%x", &cipherSuite)

		mockTLS := &tls.ConnectionState{
			Version:            version,
			CipherSuite:        cipherSuite,
			ServerName:         "localhost",
			NegotiatedProtocol: tlsInfo.NegotiatedProto,
		}

		checks := ad.AnalyzeTLS(mockTLS, "Go-http-client/1.1")

		fmt.Printf("\nDetection:\n")
		for _, c := range checks {
			if c.Score > 0 {
				fmt.Printf("  %s: Score %.2f - %s\n", c.CheckName, c.Score, c.Details)
			}
		}
	})

	// Test 2: Native with Chrome TLS spoofing
	t.Run("Native Chrome TLS Spoofing", func(t *testing.T) {
		eng, err := New(engine.Options{
			Timeout:     30 * time.Second,
			HTTP2:       true,
			StealthTLS:  true,
			ProfileName: "chrome-120-macos",
		})
		if err != nil {
			t.Fatalf("Failed to create engine: %v", err)
		}
		defer func() { _ = eng.Close() }()

		// We need to use the same TLS config for the engine
		// But native engine doesn't support custom TLS config yet
		// So we'll just make the request and see what happens

		req := &engine.Request{
			Method:  "GET",
			URL:     server.URL + "/tls",
			Timeout: 30 * time.Second,
		}

		ctx := context.Background()
		_, err = eng.Do(ctx, req)

		// With self-signed certs, this will fail
		// But we can still get the TLS info from the server if it captured it
		lastReq := server.GetLastRequest()

		fmt.Printf("\n=== Native Chrome TLS Spoofing ===\n")
		if err != nil {
			fmt.Printf("TLS Error (expected): %v\n", err)
		}

		if lastReq != nil && lastReq.TLS != nil {
			fmt.Printf("TLS Version: %s\n", lastReq.TLS.Version)
			fmt.Printf("Cipher Suite: %s\n", lastReq.TLS.CipherSuite)
			fmt.Printf("JA4: %s\n", lastReq.TLS.JA4)
			fmt.Printf("Negotiated Proto: %s\n", lastReq.TLS.NegotiatedProto)
		} else {
			fmt.Println("No TLS info captured (handshake failed)")
		}

		server.ClearRequests()
	})
}

func TestProfilesAgainstDetection(t *testing.T) {
	server := testserver.NewWithConfig(&testserver.ServerConfig{
		DetectHTTPFingerprint: true,
	})
	defer server.Close()

	profiles := []struct {
		name       string
		profile    string
		stealthTLS bool
	}{
		{"Chrome 120 macOS", "chrome-120-macos", false},
		{"Chrome 120 Windows", "chrome-120-windows", false},
		{"Firefox 120 macOS (with Chrome headers)", "firefox-120-macos", false},
		{"Firefox 120 Windows", "firefox-120-windows", false},
		{"Safari 16 macOS", "safari-16-macos", false},
		{"Edge 120 Windows", "edge-120-windows", false},
	}

	for _, tc := range profiles {
		t.Run(tc.name, func(t *testing.T) {
			eng, err := New(engine.Options{
				Timeout:     30 * time.Second,
				HTTP2:       true,
				Stealth:     true,
				ProfileName: tc.profile,
			})
			if err != nil {
				t.Fatalf("Failed to create engine: %v", err)
			}
			defer func() { _ = eng.Close() }()

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

			// Run detection
			mockReq, _ := http.NewRequest("GET", server.URL, nil)
			_ = mockReq
			for k, v := range lastReq.Headers {
				mockReq.Header.Set(k, v)
			}

			detector := challenge.NewAdvancedDetection()
			checks := detector.AnalyzeHeaders(mockReq)

			var totalScore float64
			fmt.Printf("\n=== %s ===\n", tc.name)
			fmt.Printf("User-Agent: %s\n", lastReq.Headers["User-Agent"])
			fmt.Printf("Has Sec-Ch-Ua: %v\n", lastReq.Headers["Sec-Ch-Ua"] != "")

			for _, c := range checks {
				if c.Score > 0 {
					fmt.Printf("  %s: Score %.2f\n", c.CheckName, c.Score)
					totalScore += c.Score
				}
			}

			if totalScore == 0 {
				fmt.Println("  ✅ PASS - No detection!")
			} else {
				fmt.Printf("  Score: %.2f\n", totalScore)
			}

			server.ClearRequests()
		})
	}
}
