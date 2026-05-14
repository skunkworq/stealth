package extract

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOpenAIKwargsPassthroughAndReasoningNormalization(t *testing.T) {
	t.Parallel()

	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatalf("decode request failed: %v", err)
		}
		_ = r.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"extractions\":[{\"person\":\"Alice\"}]}"}}]}`))
	}))
	defer server.Close()

	model, err := OpenAI(context.Background(), ModelConfig{
		ModelID: "gpt-5-mini",
		ProviderKwargs: map[string]any{
			"api_key":  "test-key",
			"base_url": server.URL,
		},
	})
	if err != nil {
		t.Fatalf("failed to create openai extractor: %v", err)
	}

	_, err = model.Infer(context.Background(), []string{"hello"}, nil)
	if err != nil {
		t.Fatalf("openai infer failed: %v", err)
	}

	// Verify model and messages are forwarded; per-call options are not forwarded
	// by the unified llmExtractor — they are handled at the completions layer.
	if captured["model"] != "gpt-5-mini" {
		t.Fatalf("expected model=gpt-5-mini, got %v", captured["model"])
	}
	if _, hasAPIKey := captured["api_key"]; hasAPIKey {
		t.Fatalf("api_key should not be forwarded to payload")
	}
}

func TestGeminiKwargsPassthroughMapping(t *testing.T) {
	t.Parallel()

	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatalf("decode request failed: %v", err)
		}
		_ = r.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		// Gemini now uses OpenAI-compat endpoint — return OpenAI-format response.
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"extractions\":[{\"person\":\"Alice\"}]}"}}]}`))
	}))
	defer server.Close()

	model, err := Gemini(context.Background(), ModelConfig{
		ModelID: "gemini-2.5-flash",
		ProviderKwargs: map[string]any{
			"api_key":  "test-key",
			"base_url": server.URL,
		},
	})
	if err != nil {
		t.Fatalf("failed to create gemini extractor: %v", err)
	}

	_, err = model.Infer(context.Background(), []string{"hello"}, nil)
	if err != nil {
		t.Fatalf("gemini infer failed: %v", err)
	}

	// Verify model is forwarded; Gemini uses OpenAI-compat protocol now.
	if captured["model"] != "gemini-2.5-flash" {
		t.Fatalf("expected model=gemini-2.5-flash, got %v", captured["model"])
	}
}

func TestOllamaKwargsPassthroughMapping(t *testing.T) {
	t.Parallel()

	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatalf("decode request failed: %v", err)
		}
		_ = r.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		// Ollama now uses OpenAI-compat endpoint — return OpenAI-format response.
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"extractions\":[{\"person\":\"Alice\"}]}"}}]}`))
	}))
	defer server.Close()

	model, err := Ollama(context.Background(), ModelConfig{
		ModelID: "llama3.2",
		ProviderKwargs: map[string]any{
			"base_url": server.URL,
		},
	})
	if err != nil {
		t.Fatalf("failed to create ollama extractor: %v", err)
	}

	_, err = model.Infer(context.Background(), []string{"hello"}, nil)
	if err != nil {
		t.Fatalf("ollama infer failed: %v", err)
	}

	// Verify model is forwarded; Ollama uses OpenAI-compat protocol now.
	if captured["model"] != "llama3.2" {
		t.Fatalf("expected model=llama3.2, got %v", captured["model"])
	}
}
