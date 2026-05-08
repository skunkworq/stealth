package langextract

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestGeminiUsageCaptured exercises the Gemini provider's usage extraction
// against a stub server that returns the same shape the real Gemini API
// uses (usageMetadata.{promptTokenCount, candidatesTokenCount, ...}).
func TestGeminiUsageCaptured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "generateContent") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"candidates": []map[string]any{
				{"content": map[string]any{"parts": []map[string]string{{"text": `{"extractions":[]}`}}}},
			},
			"usageMetadata": map[string]int64{
				"promptTokenCount":        420,
				"candidatesTokenCount":    87,
				"totalTokenCount":         507,
				"cachedContentTokenCount": 100,
				"thoughtsTokenCount":      0,
			},
		})
	}))
	defer srv.Close()

	cfg := ModelConfig{
		ModelID:  "gemini-2.5-flash",
		Provider: "gemini",
		ProviderKwargs: map[string]any{
			"api_key":  "stub",
			"base_url": srv.URL,
		},
	}
	model, err := Gemini(context.Background(), cfg)
	if err != nil {
		t.Fatalf("provider build: %v", err)
	}
	out, err := model.Infer(context.Background(), []string{"hello"}, nil)
	if err != nil {
		t.Fatalf("infer: %v", err)
	}
	if len(out) != 1 || len(out[0]) != 1 || out[0][0].Usage == nil {
		t.Fatalf("expected one ScoredOutput with Usage, got %+v", out)
	}
	u := out[0][0].Usage
	if u.Provider != "gemini" || u.Model != "gemini-2.5-flash" {
		t.Errorf("provider/model: got %s/%s", u.Provider, u.Model)
	}
	if u.InputTokens != 420 || u.OutputTokens != 87 || u.TotalTokens != 507 {
		t.Errorf("token counts off: in=%d out=%d total=%d", u.InputTokens, u.OutputTokens, u.TotalTokens)
	}
	if u.CachedInputTokens != 100 {
		t.Errorf("cached: got %d want 100", u.CachedInputTokens)
	}
	if u.LatencyMs < 0 {
		t.Errorf("latency: got negative %d", u.LatencyMs)
	}
}

// TestOpenAIUsageCaptured exercises the OpenAI/DeepSeek-compat provider's
// usage extraction. Verifies the DeepSeek-specific cached-prompt-tokens
// field (prompt_cache_hit_tokens) is captured correctly when prompt_tokens_details
// is absent.
func TestOpenAIUsageCaptured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"content": `{"extractions":[]}`}},
			},
			"model": "deepseek-chat",
			"usage": map[string]int64{
				"prompt_tokens":           1024,
				"completion_tokens":       256,
				"total_tokens":            1280,
				"prompt_cache_hit_tokens": 512,
			},
		})
	}))
	defer srv.Close()

	cfg := ModelConfig{
		ModelID:  "deepseek-chat",
		Provider: "deepseek",
		ProviderKwargs: map[string]any{
			"api_key":  "stub",
			"base_url": srv.URL,
		},
	}
	model, err := DeepSeek(context.Background(), cfg)
	if err != nil {
		t.Fatalf("provider build: %v", err)
	}
	out, err := model.Infer(context.Background(), []string{"hello"}, nil)
	if err != nil {
		t.Fatalf("infer: %v", err)
	}
	u := out[0][0].Usage
	if u == nil {
		t.Fatal("expected Usage populated")
	}
	if u.Provider != "deepseek" {
		t.Errorf("provider: got %q want deepseek", u.Provider)
	}
	if u.Model != "deepseek-chat" {
		t.Errorf("model: got %q want deepseek-chat", u.Model)
	}
	if u.InputTokens != 1024 || u.OutputTokens != 256 || u.TotalTokens != 1280 {
		t.Errorf("token counts: in=%d out=%d total=%d", u.InputTokens, u.OutputTokens, u.TotalTokens)
	}
	if u.CachedInputTokens != 512 {
		t.Errorf("cache hit: got %d want 512", u.CachedInputTokens)
	}
}

// TestInferenceUsageAdd guards the per-pass aggregation logic in
// extract.go against silent regressions.
func TestInferenceUsageAdd(t *testing.T) {
	a := InferenceUsage{InputTokens: 10, OutputTokens: 5, TotalTokens: 15, LatencyMs: 100}
	b := &InferenceUsage{Provider: "gemini", Model: "gemini-2.5-flash", InputTokens: 20, OutputTokens: 8, TotalTokens: 28, CachedInputTokens: 10, LatencyMs: 250}
	a.Add(b)

	if a.InputTokens != 30 || a.OutputTokens != 13 || a.TotalTokens != 43 {
		t.Errorf("token sum off: %+v", a)
	}
	if a.CachedInputTokens != 10 {
		t.Errorf("cached: got %d want 10", a.CachedInputTokens)
	}
	if a.LatencyMs != 350 {
		t.Errorf("latency: got %d want 350", a.LatencyMs)
	}
	if a.Provider != "gemini" || a.Model != "gemini-2.5-flash" {
		t.Errorf("provider/model not picked up: %+v", a)
	}

	// Adding nil should be a no-op.
	before := a
	a.Add(nil)
	if a != before {
		t.Errorf("Add(nil) mutated receiver: before=%+v after=%+v", before, a)
	}
}
