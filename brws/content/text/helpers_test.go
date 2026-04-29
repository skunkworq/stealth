package langextract

import "testing"

func TestParseResponse(t *testing.T) {
	t.Parallel()

	extractions, err := ParseResponse(`{"extractions":[{"person":"Alice"}]}`)
	if err != nil {
		t.Fatalf("parse response failed: %v", err)
	}
	if len(extractions) != 1 {
		t.Fatalf("expected 1 extraction, got %d", len(extractions))
	}
	if extractions[0].ExtractionClass != "person" {
		t.Fatalf("unexpected extraction class: %q", extractions[0].ExtractionClass)
	}
}

func TestExtractRawToJSON(t *testing.T) {
	t.Parallel()
	raw := &RawExtractionResult{DocumentID: "doc-1", Text: "hello"}
	str, err := ExtractRawToJSON(raw)
	if err != nil {
		t.Fatalf("json conversion failed: %v", err)
	}
	if str == "" {
		t.Fatalf("expected non-empty json output")
	}
}

func TestParseResponseSuppressParseErrors(t *testing.T) {
	t.Parallel()

	extractions, err := ParseResponse(
		"not-json",
		WithResolverParameters(map[string]any{
			"suppress_parse_errors": true,
		}),
	)
	if err != nil {
		t.Fatalf("expected suppressed parse error, got %v", err)
	}
	if len(extractions) != 0 {
		t.Fatalf("expected empty extraction list, got %d", len(extractions))
	}
}
