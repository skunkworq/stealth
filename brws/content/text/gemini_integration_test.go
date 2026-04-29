package langextract

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestGeminiProviderIntegrationWithMockServer(t *testing.T) {
	t.Parallel()

	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}

		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("failed to decode payload: %v", err)
		}
		_ = r.Body.Close()

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"candidates":[
				{"content":{"parts":[{"text":"{\"extractions\":[{\"person\":\"Alice\"}]}"}]}}
			]
		}`))
	}))
	defer server.Close()

	raw, err := ExtractRaw(
		context.Background(),
		"Alice Johnson is a software engineer at Acme Corp. She works with Bob Lee.",
		WithExamples(testExamples()...),
		WithModelConfig(ModelConfig{
			ModelID:  "gemini-2.5-flash",
			Provider: "gemini",
			ProviderKwargs: map[string]any{
				"api_key":  "test-key",
				"base_url": server.URL,
			},
		}),
		WithMaxCharBuffer(60),
		WithBatchLength(2),
	)
	if err != nil {
		t.Fatalf("extract raw failed: %v", err)
	}
	if raw.Provider != "gemini" {
		t.Fatalf("expected gemini provider, got %q", raw.Provider)
	}
	if len(raw.Extractions) == 0 {
		t.Fatalf("expected non-empty extractions")
	}
	if got := requestCount.Load(); got == 0 {
		t.Fatalf("expected at least one request to mock gemini server")
	}
}
