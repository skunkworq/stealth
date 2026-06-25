package langextract

import (
	"context"
	"strings"
	"testing"
)

func TestExtractRawWithConfigAlias(t *testing.T) {
	resetProviderRegistryForTests()
	t.Cleanup(func() {
		resetProviderRegistryForTests()
	})

	if err := RegisterProvider("cfg-provider", func(_ context.Context, _ ModelConfig) (Extractor, error) {
		return newFakeExtractor(`{"extractions":[{"person":"Alice"}]}`), nil
	}); err != nil {
		t.Fatalf("register provider failed: %v", err)
	}

	raw, err := ExtractRaw(
		context.Background(),
		"Alice works at Acme.",
		WithExamples(testExamples()...),
		WithModelID("ignored-model-id"),
		WithConfig(ModelConfig{
			ModelID:  "config-model-id",
			Provider: "cfg-provider",
		}),
	)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if raw.Provider != "cfg-provider" {
		t.Fatalf("expected cfg-provider, got %q", raw.Provider)
	}
	if raw.ModelID != "config-model-id" {
		t.Fatalf("expected config model id, got %q", raw.ModelID)
	}
}

func TestExtractRawOptionSurfaceAndContextFlow(t *testing.T) {
	t.Parallel()

	model := newCaptureOptionsExtractor(`{"extractions":[{"person":"Alice"}]}`)
	text := "Alice joined Acme. She now leads backend systems."

	raw, err := ExtractRaw(
		context.Background(),
		text,
		WithPromptDescription("Extract people and organizations."),
		WithExamples(testExamples()...),
		WithModel(model),
		WithFormat(FormatTypeJSON),
		WithFenceOutput(false),
		WithAdditionalContext("Prefer concise attributes."),
		WithTemperature(0.2),
		WithContextWindowChars(16),
		WithMaxCharBuffer(24),
		WithBatchLength(1),
		WithFetchURLs(false),
		WithTokenizer(&UnicodeTokenizer{}),
		WithNoSchemaConstraints(),
		WithFetchTimeoutSeconds(1),
		WithProviderHint("gemini"),
		WithProvider("openai"),
		WithShowProgress(true),
		WithDebug(true),
		WithUseSchemaConstraints(true),
	)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if len(raw.Extractions) == 0 {
		t.Fatalf("expected extraction output")
	}
	if model.lastOptions["temperature"] != 0.2 {
		t.Fatalf("expected temperature option passthrough, got %v", model.lastOptions["temperature"])
	}
	if model.lastSchema == nil {
		t.Fatalf("expected schema to be applied when enabled")
	}

	var prompts []string
	for _, call := range model.calls {
		prompts = append(prompts, call...)
	}
	if len(prompts) < 2 {
		t.Fatalf("expected multiple prompts due chunking, got %d", len(prompts))
	}
	if !strings.Contains(prompts[0], "Prefer concise attributes.") {
		t.Fatalf("expected additional context in first prompt")
	}
	if !strings.Contains(prompts[1], "[Previous text]: ...") {
		t.Fatalf("expected previous context window in second prompt")
	}
}
