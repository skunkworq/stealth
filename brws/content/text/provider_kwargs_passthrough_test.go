package langextract

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
		if r.URL.Path != "/v1/chat/completions" {
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

	_, err = model.Infer(context.Background(), []string{"hello"}, map[string]any{
		"reasoning":         map[string]any{"other_field": "value"},
		"reasoning_effort":  "minimal",
		"temperature":       0.2,
		"max_output_tokens": 99,
		"response_format":   map[string]any{"type": "text"},
		"api_key":           "should-not-leak",
		"base_url":          "should-not-leak",
	})
	if err != nil {
		t.Fatalf("openai infer failed: %v", err)
	}

	reasoning, ok := captured["reasoning"].(map[string]any)
	if !ok {
		t.Fatalf("expected reasoning map, got %T", captured["reasoning"])
	}
	if reasoning["other_field"] != "value" {
		t.Fatalf("expected reasoning.other_field passthrough, got %v", reasoning["other_field"])
	}
	if reasoning["effort"] != "minimal" {
		t.Fatalf("expected reasoning.effort from reasoning_effort alias, got %v", reasoning["effort"])
	}
	if captured["max_tokens"] != float64(99) {
		t.Fatalf("expected max_tokens=99, got %v", captured["max_tokens"])
	}
	if _, hasAPIKey := captured["api_key"]; hasAPIKey {
		t.Fatalf("api_key should not be forwarded to payload")
	}
	if _, hasBaseURL := captured["base_url"]; hasBaseURL {
		t.Fatalf("base_url should not be forwarded to payload")
	}
	respFormat, ok := captured["response_format"].(map[string]any)
	if !ok || respFormat["type"] != "text" {
		t.Fatalf("expected runtime response_format override, got %v", captured["response_format"])
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
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"{\"extractions\":[{\"person\":\"Alice\"}]}"}]}}]}`))
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

	_, err = model.Infer(context.Background(), []string{"hello"}, map[string]any{
		"temperature":       0.1,
		"max_output_tokens": 128,
		"top_p":             0.9,
		"top_k":             40,
		"candidate_count":   2,
		"stop_sequences":    []string{"\n\n"},
		"api_key":           "should-not-leak",
	})
	if err != nil {
		t.Fatalf("gemini infer failed: %v", err)
	}

	genCfg, ok := captured["generationConfig"].(map[string]any)
	if !ok {
		t.Fatalf("expected generationConfig object, got %T", captured["generationConfig"])
	}
	if genCfg["maxOutputTokens"] != float64(128) {
		t.Fatalf("expected maxOutputTokens=128, got %v", genCfg["maxOutputTokens"])
	}
	if genCfg["topP"] != 0.9 {
		t.Fatalf("expected topP=0.9, got %v", genCfg["topP"])
	}
	if genCfg["topK"] != float64(40) {
		t.Fatalf("expected topK=40, got %v", genCfg["topK"])
	}
	if genCfg["candidateCount"] != float64(2) {
		t.Fatalf("expected candidateCount=2, got %v", genCfg["candidateCount"])
	}
	if stops, ok := genCfg["stopSequences"].([]any); !ok || len(stops) != 1 || stops[0] != "\n\n" {
		t.Fatalf("expected stopSequences passthrough, got %v", genCfg["stopSequences"])
	}
	if _, hasAPIKey := genCfg["api_key"]; hasAPIKey {
		t.Fatalf("api_key should not be forwarded into generationConfig")
	}
}

func TestOllamaKwargsPassthroughMapping(t *testing.T) {
	t.Parallel()

	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/generate" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatalf("decode request failed: %v", err)
		}
		_ = r.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":"{\"extractions\":[{\"person\":\"Alice\"}]}"}`))
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

	_, err = model.Infer(context.Background(), []string{"hello"}, map[string]any{
		"temperature":       0.3,
		"top_p":             0.8,
		"max_output_tokens": 64,
		"api_key":           "should-not-leak",
	})
	if err != nil {
		t.Fatalf("ollama infer failed: %v", err)
	}

	opts, ok := captured["options"].(map[string]any)
	if !ok {
		t.Fatalf("expected options object in ollama payload, got %T", captured["options"])
	}
	if opts["temperature"] != 0.3 {
		t.Fatalf("expected temperature=0.3, got %v", opts["temperature"])
	}
	if opts["top_p"] != 0.8 {
		t.Fatalf("expected top_p=0.8 passthrough, got %v", opts["top_p"])
	}
	if opts["num_predict"] != float64(64) {
		t.Fatalf("expected max_output_tokens mapping to num_predict=64, got %v", opts["num_predict"])
	}
	if _, hasAPIKey := opts["api_key"]; hasAPIKey {
		t.Fatalf("api_key should not be forwarded in ollama options")
	}
}
