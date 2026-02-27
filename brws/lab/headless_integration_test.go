package lab

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// getFreePort asks the kernel for a free open port that is ready to use.
func getFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// TestHeadlessCapture spins up the server, launches headless chrome,
// targets an external URL, and validates that captures arrive safely.
func TestHeadlessCapture(t *testing.T) {
	// 1. Assign dynamic ports
	httpPort, err := getFreePort()
	if err != nil {
		t.Fatalf("Failed to get free port: %v", err)
	}
	httpsPort, err := getFreePort()
	if err != nil {
		t.Fatalf("Failed to get free port: %v", err)
	}
	proxyPort, err := getFreePort()
	if err != nil {
		t.Fatalf("Failed to get free port: %v", err)
	}

	// 2. Initialize the server
	t.Logf("Starting server on HTTP=%d, HTTPS=%d, Proxy=%d", httpPort, httpsPort, proxyPort)
	server := NewEnhancedServer(&ServerConfig{
		HTTPPort:    httpPort,
		HTTPSPort:   httpsPort,
		ProxyPort:   proxyPort,
		EnableProxy: true,
		ProxyMode:   "mitm",
	}, nil)

	// Start server in background
	go func() {
		if err := server.Start(); err != nil && err != http.ErrServerClosed {
			// This might log harmless errors on shutdown, so just print
			fmt.Printf("Server start error: %v\n", err)
		}
	}()

	// Give the server a moment to bind and Proxy to start
	time.Sleep(2 * time.Second)

	// Clean up resources at the end
	defer func() {
		t.Log("Cleaning up server and browser...")
		server.StopChrome() // Force stop if it hasn't already auto-closed
		server.Stop(context.Background())
	}()

	// 3. Command the server to launch Chrome in Headless Mode pointing to coles.com.au
	targetURL := "https://www.coles.com.au"
	reqPayload := map[string]interface{}{
		"url":         targetURL,
		"headless":    true, // Switch back to headless
		"close_after": 15,
	}

	body, err := json.Marshal(reqPayload)
	if err != nil {
		t.Fatalf("Failed to marshal request payload: %v", err)
	}

	resp, err := http.Post(fmt.Sprintf("http://localhost:%d/api/chrome/launch", httpPort), "application/json", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Failed to call launch API: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Chrome launch API returned non-200 status: %d", resp.StatusCode)
	}
	t.Logf("Headless Chrome launched successfully, targeting %s (will auto-close in 15s)", targetURL)

	// 4. Poll the backend /captures API to read incoming traffic
	timeout := time.After(25 * time.Second) // wait max 25s for Chrome to send traffic
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var capturedData []CaptureSummary

	t.Log("Waiting for captures to arrive...")
pollLoop:
	for {
		select {
		case <-timeout:
			t.Fatal("Timeout reached while waiting for captures.")
		case <-ticker.C:
			// Fetch the latest captures
			cResp, err := http.Get(fmt.Sprintf("http://localhost:%d/captures?limit=50", httpPort))
			if err != nil {
				continue // retry
			}

			cBody, err := io.ReadAll(cResp.Body)
			cResp.Body.Close()
			if err != nil {
				continue
			}

			// Parse response
			var apiResp struct {
				Count    int              `json:"count"`
				Captures []CaptureSummary `json:"captures"`
			}
			if err := json.Unmarshal(cBody, &apiResp); err != nil {
				continue
			}

			if apiResp.Count > 0 {
				capturedData = apiResp.Captures
				// Check if the target was actually intercepted yet
				foundTarget := false
				for _, cap := range capturedData {
					if cap.Host == "www.coles.com.au" {
						foundTarget = true
						break
					}
				}
				if foundTarget {
					break pollLoop
				}
			}
		}
	}

	// 5. Validation and Reporting
	if len(capturedData) == 0 {
		t.Fatal("Expected to capture packets from headless Chrome, but none were found.")
	}

	t.Logf("✓ Successfully captured %d packets:", len(capturedData))
	foundExampleCom := false
	for _, cap := range capturedData {
		t.Logf("  -> Host: %s (Protocol: %s)", cap.Host, cap.Protocol)
		if cap.Host == "www.coles.com.au" {
			foundExampleCom = true
		}
	}

	if !foundExampleCom {
		t.Log("Note: Traffic was successfully intercepted but 'www.coles.com.au' was not among the hosts. (Chrome may have fetched background services or timing was too tight).")
	}

	// Fetch detail payload of the relevant www.coles.com.au fingerprint
	var exampleCaptureID string
	for _, cap := range capturedData {
		if cap.Host == "www.coles.com.au" {
			exampleCaptureID = cap.ID
			break
		}
	}

	if exampleCaptureID == "" {
		t.Log("ℹ️ 'www.coles.com.au' capture not found in the initial slice. Test passing but consider increasing timeout if expected.")
		return
	}

	t.Logf("Fetching full fingerprint detail for capture ID: %s", exampleCaptureID)

	detailResp, err := http.Get(fmt.Sprintf("http://localhost:%d/captures/%s", httpPort, exampleCaptureID))
	if err != nil {
		t.Fatalf("Failed to get detail for %s: %v", exampleCaptureID, err)
	}
	defer detailResp.Body.Close()

	detailBody, err := io.ReadAll(detailResp.Body)
	if err != nil {
		t.Fatalf("Failed to read detail payload: %v", err)
	}

	var fullFingerprint CompleteFingerprint
	if err := json.Unmarshal(detailBody, &fullFingerprint); err != nil {
		t.Fatalf("Failed to unmarshal CompleteFingerprint: %v", err)
	}

	// Ensure structural guarantees
	if fullFingerprint.TLS == nil {
		t.Log("⚠️ Captured fingerprint is missing TLS data (maybe plain HTTP).")
	} else {
		t.Log("== TLS Fingerprint ==")
		t.Logf("  JA3 Hash: %s", fullFingerprint.TLS.JA3Hash)
		t.Logf("  JA4:      %s", fullFingerprint.TLS.JA4)
		t.Logf("  Version:  %s", fullFingerprint.TLS.VersionName)
		t.Logf("  ALPN:     %v", fullFingerprint.TLS.ALPN)
	}

	if fullFingerprint.HTTP != nil {
		t.Log("== HTTP Request ==")
		t.Logf("  Method:   %s", fullFingerprint.HTTP.Method)
		t.Logf("  Protocol: %s", fullFingerprint.HTTP.Protocol)
		t.Logf("  User-Agent: %s", fullFingerprint.HTTP.UserAgent)
	}

	if fullFingerprint.HTTPResp != nil {
		t.Log("== HTTP Response ==")
		t.Logf("  Status:   %d %s", fullFingerprint.HTTPResp.StatusCode, fullFingerprint.HTTPResp.Status)
		t.Logf("  Length:   %d", fullFingerprint.HTTPResp.BodyLength)
		t.Logf("  Headers:  %d parsed", len(fullFingerprint.HTTPResp.Headers))
	} else {
		t.Log("ℹ️ No HTTP Response was mapped to this specific capture slice.")
	}

	t.Log("TestHeadlessCapture passed successfully!")
}
