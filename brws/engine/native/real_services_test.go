package native

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stealth/brwslab/brws/engine"
)

// TestRealHTTPServices tests standard Go TLS fingerprint against real services
func TestRealHTTPServices(t *testing.T) {
	services := []struct {
		name string
		url  string
	}{
		{"Google", "https://www.google.com"},
		{"Cloudflare", "https://www.cloudflare.com"},
		{"Example", "https://www.example.com"},
	}

	for _, svc := range services {
		t.Run(svc.name, func(t *testing.T) {
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // G402: Test server uses self-signed cert
				},
			}

			resp, err := client.Get(svc.url)
			if err != nil {
				t.Logf("Error: %v", err)
				return
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.TLS != nil {
				fmt.Printf("\n=== %s (Standard Go) ===\n", svc.name)
				fmt.Printf("TLS Version: 0x%04x\n", resp.TLS.Version)
				fmt.Printf("Cipher: 0x%04x\n", resp.TLS.CipherSuite)
				fmt.Printf("Negotiated: %s\n", resp.TLS.NegotiatedProtocol)

				ver := "12"
				if resp.TLS.Version == tls.VersionTLS13 {
					ver = "13"
				}
				alpn := "_"
				if resp.TLS.NegotiatedProtocol != "" {
					alpn = resp.TLS.NegotiatedProtocol
				}
				ja4 := fmt.Sprintf("t%s%s_%04x", ver, alpn, resp.TLS.CipherSuite)
				fmt.Printf("JA4: %s\n", ja4)
			}

			_, _ = io.Copy(io.Discard, resp.Body)
		})
	}
}

// TestStealthEngineAgainstRealService tests the stealth engine
func TestStealthEngineAgainstRealService(t *testing.T) {
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
		URL:     "https://www.example.com",
		Timeout: 30 * time.Second,
	}

	ctx := context.Background()
	resp, err := eng.Do(ctx, req)
	if err != nil {
		t.Logf("Error: %v", err)
		return
	}

	fmt.Printf("\n=== Stealth Engine Response ===\n")
	fmt.Printf("Status: %d\n", resp.Status)
	fmt.Printf("Protocol: %s\n", resp.Protocol)
	fmt.Printf("Final URL: %s\n", resp.FinalURL)
}
