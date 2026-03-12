package langextract

import (
	"math"
	"strings"
	"testing"
)

func TestParseResponsePropagatesFormatHandlerConfigError(t *testing.T) {
	t.Parallel()

	_, err := ParseResponse(
		`{"extractions":[{"person":"Alice"}]}`,
		WithResolverParameters(map[string]any{
			"format_handler": "not-a-handler",
		}),
	)
	if err == nil {
		t.Fatalf("expected format_handler type error")
	}
	if !strings.Contains(err.Error(), "format_handler must be *FormatHandler") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExtractRawToJSONMarshalError(t *testing.T) {
	t.Parallel()

	raw := &RawExtractionResult{
		DocumentID: "doc-err",
		Metadata: map[string]any{
			"bad_float": math.NaN(),
		},
	}
	if _, err := ExtractRawToJSON(raw); err == nil {
		t.Fatalf("expected json marshal error for NaN metadata")
	}
}
