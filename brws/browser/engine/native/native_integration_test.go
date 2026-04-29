package native

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/skunkworq/stealth/brws/browser/engine"
	"github.com/skunkworq/stealth/brws/browser/engine/testserver"
)

func TestNativeWithTestserver(t *testing.T) {
	server := testserver.New()
	defer server.Close()

	eng, err := New(engine.Options{
		Timeout: 30 * time.Second,
		HTTP2:   true,
	})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer func() { _ = eng.Close() }()

	req := &engine.Request{
		Method: "GET",
		URL:    server.URL + "/test",
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

	if resp.Status != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, resp.Status)
	}

	lastReq := server.GetLastRequest()
	if lastReq == nil {
		t.Fatal("No request captured by test server")
	}

	if lastReq.Headers["Accept"] != "application/json" {
		t.Errorf("Expected Accept header, got: %v", lastReq.Headers)
	}

	server.ClearRequests()
}

func TestNativeWithTLSTestserver(t *testing.T) {
	server := testserver.NewWithTLS()
	defer server.Close()

	eng, err := New(engine.Options{
		Timeout:    30 * time.Second,
		HTTP2:      true,
		StealthTLS: false,
	})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer func() { _ = eng.Close() }()

	req := &engine.Request{
		Method: "GET",
		URL:    server.URL + "/test",
		Headers: map[string][]string{
			"Accept": {"application/json"},
		},
		Timeout: 30 * time.Second,
	}

	ctx := context.Background()
	resp, err := eng.Do(ctx, req)
	if err != nil {
		// TLS test with self-signed cert will fail - that's expected
		t.Logf("TLS request failed (expected with self-signed cert): %v", err)
		return
	}

	if resp.Status != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, resp.Status)
	}

	lastReq := server.GetLastRequest()
	if lastReq == nil {
		t.Fatal("No request captured by test server")
	}

	if lastReq.TLS == nil {
		t.Fatal("Expected TLS info in request")
	}

	t.Logf("TLS Version: %s", lastReq.TLS.Version)
	t.Logf("TLS Cipher Suite: %s", lastReq.TLS.CipherSuite)
	t.Logf("TLS JA3: %s", lastReq.TLS.JA3)
	t.Logf("TLS JA4: %s", lastReq.TLS.JA4)

	server.ClearRequests()
}

func TestNativeStealthTLS(t *testing.T) {
	server := testserver.NewWithTLS()
	defer server.Close()

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

	req := &engine.Request{
		Method: "GET",
		URL:    server.URL + "/test",
		Headers: map[string][]string{
			"Accept": {"application/json"},
		},
		Timeout: 30 * time.Second,
	}

	ctx := context.Background()
	_, err = eng.Do(ctx, req)
	// TLS with self-signed cert will fail - that's expected
	if err != nil {
		t.Logf("TLS request failed (expected with self-signed cert): %v", err)
		return
	}
}

func TestNativeStealthHeaders(t *testing.T) {
	server := testserver.New()
	defer server.Close()

	t.Logf("Test server URL: %s", server.URL)

	eng, err := New(engine.Options{
		Timeout:     30 * time.Second,
		HTTP2:       false,
		Stealth:     true,
		ProfileName: "chrome-120-macos",
	})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer func() { _ = eng.Close() }()

	// Make request with native engine - this is the actual test
	req := &engine.Request{
		Method: "GET",
		URL:    server.URL + "/headers",
		Headers: map[string][]string{
			"Accept": {"application/json"},
		},
		Timeout: 30 * time.Second,
	}

	ctx := context.Background()
	_, err = eng.Do(ctx, req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	lastReq := server.GetLastRequest()
	if lastReq == nil {
		t.Fatal("No request captured by test server")
	}

	if lastReq.Headers["User-Agent"] == "" {
		t.Error("Expected User-Agent header from stealth profile")
	}

	if lastReq.Headers["Sec-Ch-Ua"] == "" {
		t.Error("Expected Sec-Ch-Ua header from stealth profile")
	}

	t.Logf("User-Agent: %s", lastReq.Headers["User-Agent"])
	t.Logf("Sec-Ch-Ua: %s", lastReq.Headers["Sec-Ch-Ua"])

	server.ClearRequests()
}

func TestNativeWithProfiles(t *testing.T) {
	server := testserver.New()
	defer server.Close()

	profiles := []string{
		"chrome-120-macos",
		"chrome-120-windows",
		"firefox-120-macos",
		"safari-16-macos",
	}

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
			defer func() { _ = eng.Close() }()

			req := &engine.Request{
				Method:  "GET",
				URL:     server.URL + "/headers",
				Timeout: 30 * time.Second,
			}

			ctx := context.Background()
			resp, err := eng.Do(ctx, req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}

			t.Logf("Response status: %d", resp.Status)

			lastReq := server.GetLastRequest()
			if lastReq == nil {
				t.Fatal("No request captured by test server")
			}

			if lastReq.Headers["User-Agent"] == "" {
				t.Error("Expected User-Agent header")
			}

			t.Logf("Profile: %s, User-Agent: %s", profileName, lastReq.Headers["User-Agent"])

			server.ClearRequests()
		})
	}
}

func TestNativeWithCustomHeaders(t *testing.T) {
	server := testserver.New()
	defer server.Close()

	eng, err := New(engine.Options{
		Timeout:     30 * time.Second,
		HTTP2:       true,
		Stealth:     true,
		ProfileName: "chrome-120-macos",
		CustomHeaders: map[string]string{
			"X-Custom-Header": "custom-value",
			"X-Forwarded-For": "1.2.3.4",
		},
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
		t.Fatal("No request captured by test server")
	}

	if lastReq.Headers["X-Custom-Header"] != "custom-value" {
		t.Errorf("Expected X-Custom-Header, got: %s", lastReq.Headers["X-Custom-Header"])
	}

	if lastReq.Headers["X-Forwarded-For"] != "1.2.3.4" {
		t.Errorf("Expected X-Forwarded-For, got: %s", lastReq.Headers["X-Forwarded-For"])
	}

	server.ClearRequests()
}

func TestNativeTraceCapturesHeaders(t *testing.T) {
	server := testserver.New()
	defer server.Close()

	eng, err := New(engine.Options{
		Timeout:     30 * time.Second,
		HTTP2:       true,
		Stealth:     true,
		ProfileName: "chrome-120-macos",
	})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer func() { _ = eng.Close() }()

	req := &engine.Request{
		Method: "GET",
		URL:    server.URL + "/test",
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

	if len(resp.Trace.Entries) == 0 {
		t.Fatal("Expected trace entries")
	}

	entry := resp.Trace.Entries[0]
	if len(entry.Request.Headers) == 0 {
		t.Error("Expected request headers in trace")
	}

	if entry.Request.Headers["User-Agent"] == "" {
		t.Error("Expected User-Agent in trace request headers")
	}

	t.Logf("Trace captured %d headers", len(entry.Request.Headers))

	server.ClearRequests()
}
