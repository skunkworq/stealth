package extract

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestE2EGemini(t *testing.T) {
	if os.Getenv("LANGEXTRACT_E2E_GEMINI") != "1" {
		t.Skip("set LANGEXTRACT_E2E_GEMINI=1 to run Gemini e2e")
	}

	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		t.Skip("GEMINI_API_KEY is not set")
	}

	modelID := os.Getenv("GEMINI_MODEL")
	if modelID == "" {
		modelID = "gemini-2.5-flash"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	raw, err := ExtractRaw(
		ctx,
		"Alice Johnson is a software engineer at Acme Corp.",
		WithExamples(testExamples()...),
		WithModelConfig(ModelConfig{
			ModelID:  modelID,
			Provider: "gemini",
			ProviderKwargs: map[string]any{
				"api_key": apiKey,
			},
		}),
	)
	if err != nil {
		t.Fatalf("gemini e2e extraction failed: %v", err)
	}
	if raw.Provider != "gemini" {
		t.Fatalf("expected provider gemini, got %q", raw.Provider)
	}
	if len(raw.Extractions) == 0 {
		t.Fatalf("gemini e2e returned no extractions")
	}
}

func TestE2EGeminiFullFlow(t *testing.T) {
	if os.Getenv("LANGEXTRACT_E2E_GEMINI") != "1" {
		t.Skip("set LANGEXTRACT_E2E_GEMINI=1 to run Gemini full-flow e2e")
	}

	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		t.Skip("GEMINI_API_KEY is not set")
	}

	modelID := os.Getenv("GEMINI_MODEL")
	if modelID == "" {
		modelID = "gemini-2.5-flash"
	}

	text := "Alice Johnson is an engineer at Acme Corp. " +
		"She collaborates with Bob Lee on backend systems. " +
		"Alice and Bob both work in Adelaide."

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	raw, err := ExtractRaw(
		ctx,
		text,
		WithPromptDescription("Extract people and organizations with concise attributes."),
		WithExamples(testExamples()...),
		WithModelConfig(ModelConfig{
			ModelID:  modelID,
			Provider: "gemini",
			ProviderKwargs: map[string]any{
				"api_key": apiKey,
			},
		}),
		WithMaxCharBuffer(80),
		WithBatchLength(2),
		WithExtractionPasses(2),
		WithContextWindowChars(80),
		WithUseSchemaConstraints(true),
		WithResolverParams(map[string]any{
			"enable_fuzzy_alignment":    true,
			"accept_match_lesser":       true,
			"fuzzy_alignment_threshold": 0.7,
		}),
	)
	if err != nil {
		t.Fatalf("gemini full-flow extraction failed: %v", err)
	}
	if raw.Provider != "gemini" {
		t.Fatalf("expected provider gemini, got %q", raw.Provider)
	}
	if raw.PassesPerformed != 2 {
		t.Fatalf("expected 2 passes, got %d", raw.PassesPerformed)
	}
	if raw.DocumentCount != 1 {
		t.Fatalf("expected document count 1, got %d", raw.DocumentCount)
	}
	if len(raw.Extractions) == 0 {
		t.Fatalf("gemini full-flow returned no extractions")
	}
}

func TestE2EOpenAI(t *testing.T) {
	if os.Getenv("LANGEXTRACT_E2E_OPENAI") != "1" {
		t.Skip("set LANGEXTRACT_E2E_OPENAI=1 to run OpenAI e2e")
	}

	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		t.Skip("OPENAI_API_KEY is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	raw, err := ExtractRaw(
		ctx,
		"Alice Johnson is a software engineer at Acme Corp.",
		WithExamples(testExamples()...),
		WithModelConfig(ModelConfig{
			ModelID:  "gpt-4o-mini",
			Provider: "openai",
			ProviderKwargs: map[string]any{
				"api_key": apiKey,
			},
		}),
	)
	if err != nil {
		t.Fatalf("openai e2e extraction failed: %v", err)
	}
	if len(raw.Extractions) == 0 {
		t.Fatalf("openai e2e returned no extractions")
	}
}

func TestE2EOllama(t *testing.T) {
	if os.Getenv("LANGEXTRACT_E2E_OLLAMA") != "1" {
		t.Skip("set LANGEXTRACT_E2E_OLLAMA=1 to run Ollama e2e")
	}

	modelID := os.Getenv("OLLAMA_MODEL")
	if modelID == "" {
		modelID = "llama3.2"
	}
	baseURL := os.Getenv("OLLAMA_BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	raw, err := ExtractRaw(
		ctx,
		"Alice Johnson is a software engineer at Acme Corp.",
		WithExamples(testExamples()...),
		WithModelConfig(ModelConfig{
			ModelID:  modelID,
			Provider: "ollama",
			ProviderKwargs: map[string]any{
				"base_url": baseURL,
			},
		}),
	)
	if err != nil {
		t.Fatalf("ollama e2e extraction failed: %v", err)
	}
	if len(raw.Extractions) == 0 {
		t.Fatalf("ollama e2e returned no extractions")
	}
}
