package langextract

import (
	"context"
	"testing"
)

type captureOptionsExtractor struct {
	*fakeExtractor
	lastOptions map[string]any
}

func newCaptureOptionsExtractor(outputs ...string) *captureOptionsExtractor {
	return &captureOptionsExtractor{
		fakeExtractor: newFakeExtractor(outputs...),
		lastOptions:   map[string]any{},
	}
}

func (c *captureOptionsExtractor) Infer(ctx context.Context, prompts []string, options map[string]any) ([][]ScoredOutput, error) {
	c.lastOptions = map[string]any{}
	for k, v := range options {
		c.lastOptions[k] = v
	}
	return c.fakeExtractor.Infer(ctx, prompts, options)
}

func testExamples() []ExampleData {
	return []ExampleData{
		{
			Text: "Alice is an engineer.",
			Extractions: []Extraction{
				{
					ExtractionClass: "person",
					ExtractionText:  "Alice",
				},
			},
		},
	}
}

func TestExtractModelOverridesConfig(t *testing.T) {
	ctx := context.Background()
	model := newFakeExtractor(`{"extractions":[{"person":"Alice"}]}`)

	raw, err := ExtractRaw(
		ctx,
		"Alice works at Acme Corp.",
		WithExamples(testExamples()...),
		WithModel(model),
		WithModelConfig(ModelConfig{
			ModelID:  "ignored-config-model",
			Provider: "unknown-provider",
		}),
	)
	if err != nil {
		t.Fatalf("extract raw failed: %v", err)
	}
	if raw.Provider != "custom" {
		t.Fatalf("expected custom provider for explicit model, got %q", raw.Provider)
	}
	if model.callCount() == 0 {
		t.Fatalf("expected fake model to be called")
	}
}

func TestExtractConfigOverridesModelID(t *testing.T) {
	resetProviderRegistryForTests()
	t.Cleanup(func() {
		resetProviderRegistryForTests()
	})

	if err := RegisterProvider("test-provider", func(_ context.Context, cfg ModelConfig) (Extractor, error) {
		_ = cfg
		return newFakeExtractor(`{"extractions":[{"person":"Alice"}]}`), nil
	}); err != nil {
		t.Fatalf("register provider failed: %v", err)
	}

	raw, err := ExtractRaw(
		context.Background(),
		"Alice works at Acme Corp.",
		WithExamples(testExamples()...),
		WithModelID("ignored-model-id"),
		WithModelConfig(ModelConfig{
			ModelID:  "config-model-id",
			Provider: "test-provider",
		}),
	)
	if err != nil {
		t.Fatalf("extract raw failed: %v", err)
	}
	if raw.ModelID != "config-model-id" {
		t.Fatalf("expected config model id to win, got %q", raw.ModelID)
	}
	if raw.Provider != "test-provider" {
		t.Fatalf("expected config provider to win, got %q", raw.Provider)
	}
}

func TestExtractPassMergeNonOverlapping(t *testing.T) {
	ctx := context.Background()
	model := newFakeExtractor(
		`{"extractions":[{"person":"Alice"}]}`,
		`{"extractions":[{"person":"Alice"}]}`,
	)

	raw, err := ExtractRaw(
		ctx,
		"Alice met Bob yesterday.",
		WithExamples(testExamples()...),
		WithModel(model),
		WithExtractionPasses(2),
	)
	if err != nil {
		t.Fatalf("extract raw failed: %v", err)
	}

	if raw.PassesPerformed != 2 {
		t.Fatalf("expected 2 passes, got %d", raw.PassesPerformed)
	}
	if len(raw.Extractions) != 1 {
		t.Fatalf("expected merged extraction count 1, got %d", len(raw.Extractions))
	}
}

func TestExtractReturnsSemanticResult(t *testing.T) {
	t.Parallel()

	model := newFakeExtractor(`{"extractions":[{"person":"Alice"}]}`)
	semanticResult, err := Extract(
		context.Background(),
		"Alice works at Acme Corp.",
		WithExamples(testExamples()...),
		WithModel(model),
	)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if len(semanticResult.Extractions) != 1 {
		t.Fatalf("expected 1 semantic extraction, got %d", len(semanticResult.Extractions))
	}
	if semanticResult.Extractions[0].Class != "person" {
		t.Fatalf("unexpected semantic class: %q", semanticResult.Extractions[0].Class)
	}
}

func TestExtractOptionAliasesAndWorkerClamp(t *testing.T) {
	t.Parallel()

	model := newCaptureOptionsExtractor(`{"extractions":[{"person":"Alice"}]}`)

	_, err := ExtractRaw(
		context.Background(),
		"Alice works at Acme Corp.",
		WithExamples(testExamples()...),
		WithModel(model),
		WithLanguageModelParams(map[string]any{"top_p": 0.5}),
		WithAPIKey("test-key"),
		WithModelURL("http://localhost:8080"),
		WithBatchLength(2),
		WithMaxWorkers(8),
	)
	if err != nil {
		t.Fatalf("extract raw failed: %v", err)
	}

	if got := model.lastOptions["top_p"]; got != 0.5 {
		t.Fatalf("expected top_p=0.5, got %v", got)
	}
	if got := model.lastOptions["api_key"]; got != "test-key" {
		t.Fatalf("expected api_key alias to propagate, got %v", got)
	}
	if got := model.lastOptions["model_url"]; got != "http://localhost:8080" {
		t.Fatalf("expected model_url alias to propagate, got %v", got)
	}
	if got := model.lastOptions["base_url"]; got != "http://localhost:8080" {
		t.Fatalf("expected base_url alias to propagate, got %v", got)
	}
	if got := model.lastOptions["max_workers"]; got != 2 {
		t.Fatalf("expected max_workers clamped to batch_length=2, got %v", got)
	}
}

func TestResolverParametersAliasSuppressParseErrors(t *testing.T) {
	t.Parallel()

	raw, err := ExtractRaw(
		context.Background(),
		"Alice works at Acme Corp.",
		WithExamples(testExamples()...),
		WithModel(newFakeExtractor("not valid json")),
		WithResolverParameters(map[string]any{
			"suppress_parse_errors": true,
		}),
	)
	if err != nil {
		t.Fatalf("expected suppress_parse_errors alias to avoid parse failure: %v", err)
	}
	if len(raw.Extractions) != 0 {
		t.Fatalf("expected no extractions when parse errors are suppressed, got %d", len(raw.Extractions))
	}
}
