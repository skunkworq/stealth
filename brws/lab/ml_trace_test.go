package lab

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stealth/brwslab/brws/types"
)

func TestMLEvasionTraceExtraction(t *testing.T) {
	// 1. Start a mock WAF server that returns a detection response.
	// The handleTestSignature handler will make a real HTTP request to this server
	// using the spoof engine, so it must be a live server.
	mockWAF := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"detection_type": "stealth_analysis",
			"bot_score":      0.15,
			"signals": map[string]interface{}{
				"tls_match":     true,
				"header_match":  true,
				"ua_consistent": true,
			},
		})
	}))
	defer mockWAF.Close()

	// 2. Initialize Server environment
	server := &EnhancedServer{
		capture: NewCaptureServer(),
		logger:  slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	// Create a CompleteFingerprint with enough TLS data for the spoof engine
	fpID := "ml_trace_test_id"
	testFp := &CompleteFingerprint{
		ID:        fpID,
		Timestamp: time.Now(),
		SourceIP:  "127.0.0.1",
		TLS: &types.TLSFingerprint{
			Version:     0x0303,
			VersionName: "TLS 1.2",
			JA3Hash:     "e7d705a3286e19ea42f587b344ee6865",
			JA4:         "t13d1516h2_8c21_0800",
			CipherSuites: []types.CipherInfo{
				{Value: 0x1301, Name: "TLS_AES_128_GCM_SHA256"},
				{Value: 0x1302, Name: "TLS_AES_256_GCM_SHA384"},
				{Value: 0xc02b, Name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
			},
			Extensions: []types.ExtensionInfo{
				{Type: 0x0000, Name: "server_name"},
				{Type: 0x000a, Name: "supported_groups"},
				{Type: 0x000b, Name: "ec_point_formats"},
				{Type: 0x0010, Name: "application_layer_protocol_negotiation"},
				{Type: 0x0023, Name: "session_ticket"},
				{Type: 0x002b, Name: "supported_versions"},
				{Type: 0x002d, Name: "psk_key_exchange_modes"},
				{Type: 0x0033, Name: "key_share"},
			},
			SupportedGroups: []uint16{0x001d, 0x0017, 0x0018},
			KeyShareGroups:  []uint16{0x001d},
			ALPN:            []string{"h2", "http/1.1"},
		},
		HTTP: &types.HTTPFingerprint{
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		},
	}

	// Inject it into the server's state map (mimicking a proxy sniff)
	server.capture.mu.Lock()
	server.capture.captures[fpID] = testFp
	server.capture.mu.Unlock()

	// 3. Clear trace directory for the test
	homeDir, _ := os.UserHomeDir()
	traceDir := filepath.Join(homeDir, ".stealth", "traces")
	if err := os.RemoveAll(traceDir); err != nil {
		t.Logf("Warning: failed to clean trace dir: %v", err)
	}
	// Clean up after test
	defer os.RemoveAll(traceDir)

	// Use mock WAF server URL with "stealth-test" in the path
	// (the handler checks strings.Contains(req.URL, "stealth-test") to trigger trace writing)
	targetURL := mockWAF.URL + "/api/stealth-test"

	reqBody := map[string]string{
		"id":  fpID,
		"url": targetURL,
	}

	b, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Failed to marshal request body: %v", err)
	}
	req := httptest.NewRequest("POST", "/api/test-signature", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// 4. Fire the test execution directly into the handler
	server.handleTestSignature(w, req)

	// 5. Asserting the Trace Generation on Disk
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK from test-signature, got %d. Body: %s", w.Code, w.Body.String())
	}

	// Check the response indicates success
	var respBody map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &respBody); err != nil {
		t.Fatalf("Response body is not valid JSON: %v", err)
	}
	if success, ok := respBody["success"].(bool); !ok || !success {
		t.Fatalf("Expected success=true in response, got: %s", w.Body.String())
	}

	// Verify trace directory exists
	entries, err := os.ReadDir(traceDir)
	if err != nil {
		t.Fatalf("Trace Directory not created or missing: %v", err)
	}

	if len(entries) == 0 {
		t.Fatalf("No JSON traces were dropped to %s", traceDir)
	}

	// Check the contents of the generated trace
	firstTrace := entries[0]
	if !strings.HasSuffix(firstTrace.Name(), ".json") {
		t.Fatalf("Expected JSON trace file, got %s", firstTrace.Name())
	}

	tracePath := filepath.Join(traceDir, firstTrace.Name())
	//nolint:gosec // G304: Test reads from temp file
	traceData, err := os.ReadFile(tracePath)
	if err != nil {
		t.Fatalf("Failed to read created trace %s: %v", tracePath, err)
	}

	// The trace should contain the merged ML data (Source fingerprint AND WAF response)
	var mlData map[string]interface{}
	if err := json.Unmarshal(traceData, &mlData); err != nil {
		t.Fatalf("Created trace is not valid JSON: %v", err)
	}

	// Assert presence of original fingerprint payload
	source, hasSource := mlData["source_fingerprint"].(map[string]interface{})
	if !hasSource {
		t.Fatalf("Trace JSON is missing the original ML 'source_fingerprint' property")
	}
	if source["id"] != fpID {
		t.Fatalf("Expected trace source to be %s, got %v", fpID, source["id"])
	}

	// Assert presence of the Adversarial output block
	if _, hasDetection := mlData["detection_type"]; !hasDetection {
		t.Fatalf("Trace JSON is missing the 'detection_type' shield payload from the WAF")
	}
}
