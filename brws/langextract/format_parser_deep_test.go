package langextract

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFormatExtractionExampleYAMLNoFencesAndNilAttrs(t *testing.T) {
	t.Parallel()

	h := NewFormatHandler()
	h.FormatType = FormatTypeYAML
	h.UseFences = false
	h.UseWrapper = false

	out, err := h.FormatExtractionExample([]Extraction{
		{
			ExtractionClass: "person",
			ExtractionText:  "Alice",
			Attributes:      nil,
		},
	})
	if err != nil {
		t.Fatalf("format extraction example failed: %v", err)
	}
	if strings.Contains(out, "```") {
		t.Fatalf("did not expect fenced output")
	}
	if !strings.Contains(out, "person: Alice") {
		t.Fatalf("expected yaml body with extraction text, got %q", out)
	}
	if !strings.Contains(out, "person_attributes: {}") {
		t.Fatalf("expected empty attributes object in output, got %q", out)
	}
}

func TestParseJSONOrderedValueUnsupportedDelimiter(t *testing.T) {
	t.Parallel()

	dec := json.NewDecoder(strings.NewReader("]"))
	_, err := parseJSONOrderedValue(dec)
	if err == nil {
		t.Fatalf("expected parse error for invalid leading token")
	}
	// Decoder wording varies by Go version; validate error class, not exact phrase.
	msg := err.Error()
	if !strings.Contains(msg, "unsupported json delimiter") &&
		!strings.Contains(msg, "invalid character") &&
		!strings.Contains(msg, "unexpected") {
		t.Fatalf("expected delimiter/token parse error, got %v", err)
	}
}
