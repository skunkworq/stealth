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
	"github.com/skunkworq/stealth/brws/browser/engine/testserver"
)

func TestRealTLSSpoofingDetection(t *testing.T) {
	// Create a real TLS server with self-signed cert
	server := testserver.NewWithTLS()
	defer server.Close()

	fmt.Printf("TLS Server URL: %s\n", server.URL)

	// Test 1: Standard Go HTTP client (no TLS spoofing)
	t.Run("Standard Go TLS", func(t *testing.T) {
		// Create client that skips cert verification
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // G402: Test server uses self-signed cert
		}
		client := &http.Client{Transport: tr}

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

		// Now analyze with advanced detection
		ad := challenge.NewAdvancedDetection()

		// Create mock TLS connection state
		var version uint16
		_, _ = fmt.Sscanf(tlsInfo.Version, "%x", &version)
		var cipherSuite uint16
		_, _ = fmt.Sscanf(tlsInfo.CipherSuite, "%x", &cipherSuite)

		mockTLS := &tls.ConnectionState{
			Version:            version,
			CipherSuite:        cipherSuite,
			ServerName:         "localhost",
			NegotiatedProtocol: "h2",
		}

		checks := ad.AnalyzeTLS(mockTLS, "Go-http-client/1.1")

		fmt.Printf("Detection checks:\n")
		for _, c := range checks {
			if c.Score > 0 {
				fmt.Printf("  %s: Score %.2f - %s\n", c.CheckName, c.Score, c.Details)
			}
		}
	})

	// Test 2: Native engine WITHOUT TLS spoofing
	t.Run("Native No TLS Spoofing", func(t *testing.T) {
		eng, err := New(engine.Options{
			Timeout:    30 * time.Second,
			HTTP2:      true,
			Stealth:    false,
			StealthTLS: false,
		})
		if err != nil {
			t.Fatalf("Failed to create engine: %v", err)
		}
		defer func() { _ = eng.Close() }()

		req := &engine.Request{
			Method:  "GET",
			URL:     server.URL + "/tls",
			Timeout: 30 * time.Second,
		}

		ctx := context.Background()
		resp, err := eng.Do(ctx, req)
		if err != nil {
			// TLS error expected due to self-signed cert
			fmt.Printf("Expected TLS error: %v\n", err)
			return
		}

		var tlsInfo testserver.TLSInfo
		_ = json.Unmarshal(resp.Body, &tlsInfo)

		fmt.Printf("\n=== Native No TLS Spoofing ===\n")
		fmt.Printf("TLS Version: %s\n", tlsInfo.Version)
		fmt.Printf("Cipher Suite: %s\n", tlsInfo.CipherSuite)
		fmt.Printf("JA4: %s\n", tlsInfo.JA4)
	})

	// Test 3: Native engine WITH TLS spoofing (Chrome)
	t.Run("Native Chrome TLS Spoofing", func(t *testing.T) {
		eng, err := New(engine.Options{
			Timeout:     30 * time.Second,
			HTTP2:       true,
			Stealth:     false,
			StealthTLS:  true,
			ProfileName: "chrome-120-macos",
		})
		if err != nil {
			t.Fatalf("Failed to create engine: %v", err)
		}
		defer func() { _ = eng.Close() }()

		req := &engine.Request{
			Method:  "GET",
			URL:     server.URL + "/tls",
			Timeout: 30 * time.Second,
		}

		ctx := context.Background()
		resp, err := eng.Do(ctx, req)
		if err != nil {
			fmt.Printf("TLS error: %v\n", err)
			// Try getting the TLS info from the request captured
			lastReq := server.GetLastRequest()
			if lastReq != nil && lastReq.TLS != nil {
				fmt.Printf("\n=== Native Chrome TLS Spoofing (from server) ===\n")
				fmt.Printf("TLS Version: %s\n", lastReq.TLS.Version)
				fmt.Printf("Cipher Suite: %s\n", lastReq.TLS.CipherSuite)
				fmt.Printf("JA4: %s\n", lastReq.TLS.JA4)
			}
			return
		}

		var tlsInfo testserver.TLSInfo
		_ = json.Unmarshal(resp.Body, &tlsInfo)

		fmt.Printf("\n=== Native Chrome TLS Spoofing ===\n")
		fmt.Printf("TLS Version: %s\n", tlsInfo.Version)
		fmt.Printf("Cipher Suite: %s\n", tlsInfo.CipherSuite)
		fmt.Printf("JA4: %s\n", tlsInfo.JA4)

		// Analyze with detection
		ad := challenge.NewAdvancedDetection()

		var version uint16
		_, _ = fmt.Sscanf(tlsInfo.Version, "%x", &version)
		var cipherSuite uint16
		_, _ = fmt.Sscanf(tlsInfo.CipherSuite, "%x", &cipherSuite)

		mockTLS := &tls.ConnectionState{
			Version:            version,
			CipherSuite:        cipherSuite,
			ServerName:         "localhost",
			NegotiatedProtocol: "h2",
		}

		checks := ad.AnalyzeTLS(mockTLS, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

		fmt.Printf("Detection checks:\n")
		for _, c := range checks {
			if c.CheckName == "TLS-Go-Fingerprint" || c.CheckName == "TLS-JA4-Fingerprint" {
				fmt.Printf("  %s: Score %.2f - %s (Passed: %v)\n", c.CheckName, c.Score, c.Details, c.Passed)
			}
		}
	})
}

func TestCombinedSpoofingDetection(t *testing.T) {
	// Test the full spoofing detection with both HTTP and TLS
	server := testserver.NewWithTLS()
	defer server.Close()

	fmt.Printf("\n=== Testing Combined HTTP + TLS Spoofing ===\n")

	// Test with Chrome profile and TLS spoofing
	eng, err := New(engine.Options{
		Timeout:     30 * time.Second,
		HTTP2:       true,
		Stealth:     true,
		StealthTLS:  true,
		ProfileName: "chrome-120-macos",
	})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer func() { _ = eng.Close() }()

	req := &engine.Request{
		Method:  "GET",
		URL:     server.URL + "/tls",
		Timeout: 30 * time.Second,
	}

	ctx := context.Background()
	_, _ = eng.Do(ctx, req)

	// Get TLS info from server
	lastReq := server.GetLastRequest()
	if lastReq == nil || lastReq.TLS == nil {
		fmt.Printf("No TLS info captured (expected with self-signed cert errors)\n")
		return
	}

	fmt.Printf("\n=== Captured TLS Info ===\n")
	fmt.Printf("TLS Version: %s\n", lastReq.TLS.Version)
	fmt.Printf("Cipher Suite: %s\n", lastReq.TLS.CipherSuite)
	fmt.Printf("JA4: %s\n", lastReq.TLS.JA4)
	fmt.Printf("Server Name: %s\n", lastReq.TLS.ServerName)

	// Now run the combined HTTP + TLS analysis
	ad := challenge.NewAdvancedDetection()

	var version uint16
	_, _ = fmt.Sscanf(lastReq.TLS.Version, "%x", &version)
	var cipherSuite uint16
	_, _ = fmt.Sscanf(lastReq.TLS.CipherSuite, "%x", &cipherSuite)

	mockTLS := &tls.ConnectionState{
		Version:            version,
		CipherSuite:        cipherSuite,
		ServerName:         lastReq.TLS.ServerName,
		NegotiatedProtocol: lastReq.TLS.NegotiatedProto,
	}

	mockReq, _ := http.NewRequest("GET", server.URL, nil)

	_ = mockReq
	mockReq.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	mockReq.Header.Set("Sec-Ch-Ua", `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`)
	mockReq.Header.Set("Sec-Ch-Ua-Platform", `"macOS"`)

	// Run combined analysis
	checks := ad.AnalyzeHTTPHeadersAndTLS(mockReq, mockTLS)

	fmt.Printf("\n=== Detection Results ===\n")
	totalScore := 0.0
	for _, c := range checks {
		if c.Score > 0 {
			fmt.Printf("%s: Score %.2f - %s (Passed: %v)\n", c.CheckName, c.Score, c.Details, c.Passed)
			totalScore += c.Score
		}
	}
	fmt.Printf("\nTotal Score: %.2f\n", totalScore)

	if totalScore > 0.5 {
		fmt.Println("RESULT: Detected as bot/spoofing!")
	} else if totalScore > 0.2 {
		fmt.Println("RESULT: Suspicious - needs more investigation")
	} else {
		fmt.Println("RESULT: Passed - likely legitimate browser")
	}
}
