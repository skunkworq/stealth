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
	// 1. Initialize Server environment
	server := &EnhancedServer{
		capture: NewCaptureServer(),
		logger:  slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}
	
	// Create a dummy CompleteFingerprint
	fpID := "ml_trace_test_id"
	testFp := &CompleteFingerprint{
		ID:        fpID,
		Timestamp: time.Now(),
		SourceIP:  "127.0.0.1",
		TLS: &types.TLSFingerprint{
			JA4: "t13d1516h2_8c21_0800",
		},
		HTTP: &types.HTTPFingerprint{
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		},
	}
	
	// Inject it into the server's state map (mimicking a proxy sniff)
	server.capture.mu.Lock()
	server.capture.captures[fpID] = testFp
	server.capture.mu.Unlock()
	
	// 2. Clear trace directory for the test
	homeDir, _ := os.UserHomeDir()
	traceDir := filepath.Join(homeDir, ".stealth", "traces")
	if err := os.RemoveAll(traceDir); err != nil {
		t.Logf("Warning: failed to clean trace dir: %v", err)
	}
	
	reqBody := map[string]string{
		"id":  fpID,
		"url": "http://localhost:8080/api/stealth-test", // Target internal WAF hook
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
	
	// Verify directory exists
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
