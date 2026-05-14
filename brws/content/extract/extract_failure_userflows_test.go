package extract

import (
	"context"
	"strings"
	"testing"
)

type scriptedExtractor struct {
	formatType  FormatType
	fenceOutput bool
	outputs     [][]ScoredOutput
}

func (s *scriptedExtractor) Infer(_ context.Context, _ []string, _ map[string]any) ([][]ScoredOutput, error) {
	return s.outputs, nil
}
func (s *scriptedExtractor) RequiresFenceOutput() bool   { return s.fenceOutput }
func (s *scriptedExtractor) SetFenceOutput(enabled bool) { s.fenceOutput = enabled }
func (s *scriptedExtractor) FormatType() FormatType {
	if s.formatType == "" {
		return FormatTypeJSON
	}
	return s.formatType
}
func (s *scriptedExtractor) SetFormatType(ft FormatType) { s.formatType = ft }
func (s *scriptedExtractor) SetSchema(schema any)        { _ = schema }

func TestExtractRawFailsWhenProviderReturnsNoOutputs(t *testing.T) {
	t.Parallel()

	_, err := ExtractRaw(
		context.Background(),
		"Alice works at Acme Corp.",
		WithExamples(testExamples()...),
		WithModel(&scriptedExtractor{
			outputs: [][]ScoredOutput{},
		}),
	)
	if err == nil {
		t.Fatalf("expected inference output error for no outputs")
	}
	if !strings.Contains(err.Error(), "no scored outputs") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractRawFailsWhenProviderReturnsEmptyChoiceEntry(t *testing.T) {
	t.Parallel()

	_, err := ExtractRaw(
		context.Background(),
		"Alice works at Acme Corp.",
		WithExamples(testExamples()...),
		WithModel(&scriptedExtractor{
			outputs: [][]ScoredOutput{{}},
		}),
	)
	if err == nil {
		t.Fatalf("expected inference output error for empty choice entry")
	}
	if !strings.Contains(err.Error(), "empty scored output entry") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractRawAllowsShortProviderBatchOutput(t *testing.T) {
	t.Parallel()

	longText := "Alice joined Acme. Bob joined Acme. Carol joined Acme."
	raw, err := ExtractRaw(
		context.Background(),
		longText,
		WithExamples(testExamples()...),
		WithMaxCharBuffer(12),
		WithBatchLength(4),
		WithModel(&scriptedExtractor{
			outputs: [][]ScoredOutput{
				{{Score: 1, Output: `{"extractions":[{"person":"Alice"}]}`}},
			},
		}),
	)
	if err != nil {
		t.Fatalf("expected success even with short scored output batch: %v", err)
	}
	if len(raw.Extractions) == 0 {
		t.Fatalf("expected at least one extraction")
	}
}

func TestExtractRawUnknownModelProviderResolutionError(t *testing.T) {
	t.Parallel()

	clearProviderRegistryForTests()
	registerBuiltins()
	t.Cleanup(func() {
		clearProviderRegistryForTests()
		registerBuiltins()
	})

	_, err := ExtractRaw(
		context.Background(),
		"Alice works at Acme Corp.",
		WithExamples(testExamples()...),
		WithModelID("unknown-provider-model-id"),
	)
	if err == nil {
		t.Fatalf("expected provider resolution error")
	}
	if !strings.Contains(err.Error(), "no provider registered") {
		t.Fatalf("unexpected error: %v", err)
	}
}
