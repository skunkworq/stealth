package extract

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAIInferEdgeBranches(t *testing.T) {
	t.Parallel()

	t.Run("empty prompts", func(t *testing.T) {
		t.Parallel()
		model, err := OpenAI(context.Background(), ModelConfig{
			ModelID: "gpt-4o-mini",
			ProviderKwargs: map[string]any{
				"api_key": "test-key",
			},
		})
		if err != nil {
			t.Fatalf("openai constructor failed: %v", err)
		}
		out, err := model.Infer(context.Background(), nil, nil)
		if err != nil {
			t.Fatalf("expected nil error for empty prompts, got %v", err)
		}
		if len(out) != 0 {
			t.Fatalf("expected empty output for empty prompts")
		}
	})

	t.Run("non-2xx status", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "bad gateway", http.StatusBadGateway)
		}))
		defer server.Close()

		model, err := OpenAI(context.Background(), ModelConfig{
			ModelID: "gpt-4o-mini",
			ProviderKwargs: map[string]any{
				"api_key":  "test-key",
				"base_url": server.URL,
			},
		})
		if err != nil {
			t.Fatalf("openai constructor failed: %v", err)
		}
		_, err = model.Infer(context.Background(), []string{"hi"}, nil)
		if err == nil || !strings.Contains(err.Error(), "status 502") {
			t.Fatalf("expected status error, got %v", err)
		}
	})

	t.Run("invalid json response", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{not-json"))
		}))
		defer server.Close()

		model, err := OpenAI(context.Background(), ModelConfig{
			ModelID: "gpt-4o-mini",
			ProviderKwargs: map[string]any{
				"api_key":  "test-key",
				"base_url": server.URL,
			},
		})
		if err != nil {
			t.Fatalf("openai constructor failed: %v", err)
		}
		_, err = model.Infer(context.Background(), []string{"hi"}, nil)
		if err == nil {
			t.Fatalf("expected unmarshal error")
		}
	})

	t.Run("no choices", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"choices":[]}`))
		}))
		defer server.Close()

		model, err := OpenAI(context.Background(), ModelConfig{
			ModelID: "gpt-4o-mini",
			ProviderKwargs: map[string]any{
				"api_key":  "test-key",
				"base_url": server.URL,
			},
		})
		if err != nil {
			t.Fatalf("openai constructor failed: %v", err)
		}
		_, err = model.Infer(context.Background(), []string{"hi"}, nil)
		if err == nil || !strings.Contains(err.Error(), "empty choices") {
			t.Fatalf("expected empty choices error, got %v", err)
		}
	})
}

func TestGeminiInferEdgeBranches(t *testing.T) {
	t.Parallel()

	t.Run("empty prompts", func(t *testing.T) {
		t.Parallel()
		model, err := Gemini(context.Background(), ModelConfig{
			ModelID: "gemini-2.5-flash",
			ProviderKwargs: map[string]any{
				"api_key": "test-key",
			},
		})
		if err != nil {
			t.Fatalf("gemini constructor failed: %v", err)
		}
		out, err := model.Infer(context.Background(), nil, nil)
		if err != nil {
			t.Fatalf("expected nil error for empty prompts, got %v", err)
		}
		if len(out) != 0 {
			t.Fatalf("expected empty output for empty prompts")
		}
	})

	t.Run("non-2xx status", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "service down", http.StatusServiceUnavailable)
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
			t.Fatalf("gemini constructor failed: %v", err)
		}
		_, err = model.Infer(context.Background(), []string{"hi"}, nil)
		if err == nil || !strings.Contains(err.Error(), "status 503") {
			t.Fatalf("expected status error, got %v", err)
		}
	})

	t.Run("invalid json response", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{broken"))
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
			t.Fatalf("gemini constructor failed: %v", err)
		}
		_, err = model.Infer(context.Background(), []string{"hi"}, nil)
		if err == nil {
			t.Fatalf("expected unmarshal error")
		}
	})

	t.Run("no candidates", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"choices":[]}`))
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
			t.Fatalf("gemini constructor failed: %v", err)
		}
		_, err = model.Infer(context.Background(), []string{"hi"}, nil)
		if err == nil || !strings.Contains(err.Error(), "empty choices") {
			t.Fatalf("expected empty choices error, got %v", err)
		}
	})
}

func TestOllamaInferEdgeBranches(t *testing.T) {
	t.Parallel()

	t.Run("empty prompts", func(t *testing.T) {
		t.Parallel()
		model, err := Ollama(context.Background(), ModelConfig{
			ModelID: "llama3.2",
			ProviderKwargs: map[string]any{
				"base_url": "http://localhost:11434",
			},
		})
		if err != nil {
			t.Fatalf("ollama constructor failed: %v", err)
		}
		out, err := model.Infer(context.Background(), nil, nil)
		if err != nil {
			t.Fatalf("expected nil error for empty prompts, got %v", err)
		}
		if len(out) != 0 {
			t.Fatalf("expected empty output for empty prompts")
		}
	})

	t.Run("non-2xx status", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "bad gateway", http.StatusBadGateway)
		}))
		defer server.Close()

		model, err := Ollama(context.Background(), ModelConfig{
			ModelID: "llama3.2",
			ProviderKwargs: map[string]any{
				"base_url": server.URL,
			},
		})
		if err != nil {
			t.Fatalf("ollama constructor failed: %v", err)
		}
		_, err = model.Infer(context.Background(), []string{"hi"}, nil)
		if err == nil || !strings.Contains(err.Error(), "status 502") {
			t.Fatalf("expected status error, got %v", err)
		}
	})

	t.Run("invalid json response", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{broken"))
		}))
		defer server.Close()

		model, err := Ollama(context.Background(), ModelConfig{
			ModelID: "llama3.2",
			ProviderKwargs: map[string]any{
				"base_url": server.URL,
			},
		})
		if err != nil {
			t.Fatalf("ollama constructor failed: %v", err)
		}
		_, err = model.Infer(context.Background(), []string{"hi"}, nil)
		if err == nil {
			t.Fatalf("expected unmarshal error")
		}
	})

	t.Run("empty response", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"choices":[]}`))
		}))
		defer server.Close()

		model, err := Ollama(context.Background(), ModelConfig{
			ModelID: "llama3.2",
			ProviderKwargs: map[string]any{
				"base_url": server.URL,
			},
		})
		if err != nil {
			t.Fatalf("ollama constructor failed: %v", err)
		}
		_, err = model.Infer(context.Background(), []string{"hi"}, nil)
		if err == nil || !strings.Contains(err.Error(), "empty choices") {
			t.Fatalf("expected empty choices error, got %v", err)
		}
	})
}

func TestProviderConstructorsRequireAPIKeys(t *testing.T) {
	t.Parallel()

	if _, err := OpenAI(context.Background(), ModelConfig{ModelID: "gpt-4o-mini"}); err == nil {
		t.Fatalf("expected openai api_key config error")
	}
	if _, err := Gemini(context.Background(), ModelConfig{ModelID: "gemini-2.5-flash"}); err == nil {
		t.Fatalf("expected gemini api_key config error")
	}
}
