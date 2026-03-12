package native

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/skunkworq/stealth/brws/engine"
)

func TestNew(t *testing.T) {
	eng, err := New(engine.Options{
		Timeout: 30 * time.Second,
		HTTP2:   true,
	})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer func() { _ = eng.Close() }()

	if eng.Name() != "native" {
		t.Errorf("Expected name 'native', got '%s'", eng.Name())
	}

	caps := eng.Capabilities()
	if caps.JavaScript {
		t.Error("Native engine should not support JavaScript")
	}
	if !caps.HTTP2 {
		t.Error("Native engine should support HTTP/2")
	}
}

func TestDo(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Test-Header", "test-value")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message": "hello"}`))
	}))
	defer server.Close()

	eng, err := New(engine.Options{
		Timeout: 30 * time.Second,
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

	if string(resp.Body) != `{"message": "hello"}` {
		t.Errorf("Unexpected body: %s", string(resp.Body))
	}

	// Check headers
	if ct := resp.Headers["Content-Type"]; len(ct) == 0 || ct[0] != "application/json" {
		t.Errorf("Unexpected Content-Type: %v", ct)
	}
}

func TestDoWithTimeout(t *testing.T) {
	// Create slow test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	eng, err := New(engine.Options{
		Timeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer func() { _ = eng.Close() }()

	req := &engine.Request{
		Method:  "GET",
		URL:     server.URL,
		Timeout: 100 * time.Millisecond,
	}

	ctx := context.Background()
	_, err = eng.Do(ctx, req)
	if err == nil {
		t.Error("Expected timeout error, got nil")
	}
}

func TestFlattenHeaders(t *testing.T) {
	input := map[string][]string{
		"Accept":  {"application/json"},
		"X-Multi": {"value1", "value2"},
	}

	result := flattenHeaders(input)

	if result["Accept"] != "application/json" {
		t.Errorf("Unexpected Accept header: %s", result["Accept"])
	}

	if result["X-Multi"] != "value1" {
		t.Errorf("Expected first value for multi-value header, got: %s", result["X-Multi"])
	}
}
