package native

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stealth/brwslab/brws/engine"
)

// TestPlainHTTPS tests basic HTTPS without any spoofing
func TestPlainHTTPS(t *testing.T) {
	eng, err := New(engine.Options{
		Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer eng.Close()

	req := &engine.Request{
		Method:  "GET",
		URL:     "https://www.example.com",
		Timeout: 30 * time.Second,
	}

	ctx := context.Background()
	resp, err := eng.Do(ctx, req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	fmt.Printf("Status: %d\n", resp.Status)
	fmt.Printf("Protocol: %s\n", resp.Protocol)
}

// TestPlainHTTPSWithStealthOnly tests HTTPS with only stealth headers (no TLS spoofing)
func TestPlainHTTPSWithStealthOnly(t *testing.T) {
	eng, err := New(engine.Options{
		Timeout:     30 * time.Second,
		Stealth:     true,
		StealthTLS:  false,
		ProfileName: "chrome-120-macos",
	})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer eng.Close()

	req := &engine.Request{
		Method:  "GET",
		URL:     "https://www.example.com",
		Timeout: 30 * time.Second,
	}

	ctx := context.Background()
	resp, err := eng.Do(ctx, req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	fmt.Printf("\n=== Stealth Headers Only ===\n")
	fmt.Printf("Status: %d\n", resp.Status)
	fmt.Printf("Protocol: %s\n", resp.Protocol)
}
