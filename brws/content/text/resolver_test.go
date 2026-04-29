package langextract

import "testing"

func TestResolverExtractOrderedExtractionsWithIndex(t *testing.T) {
	t.Parallel()

	handler := NewFormatHandler()
	resolver := NewResolver(handler)
	resolver.ExtractionIndexSuffix = DefaultIndexSuffix

	parsed := []map[string]any{
		{
			"medication":       "Naprosyn",
			"medication_index": 2,
			"dosage":           "400mg",
			"dosage_index":     1,
		},
	}

	extractions, err := resolver.ExtractOrderedExtractions(parsed)
	if err != nil {
		t.Fatalf("extract ordered failed: %v", err)
	}
	if len(extractions) != 2 {
		t.Fatalf("expected 2 extractions, got %d", len(extractions))
	}
	if extractions[0].ExtractionClass != "dosage" || extractions[1].ExtractionClass != "medication" {
		t.Fatalf("unexpected extraction order: %+v", extractions)
	}
}

func TestResolverResolveSuppressParseErrors(t *testing.T) {
	t.Parallel()

	handler := NewFormatHandler()
	handler.StrictFences = true
	resolver := NewResolver(handler)
	_, err := resolver.Resolve("invalid", true)
	if err != nil {
		t.Fatalf("expected suppressed parse errors, got %v", err)
	}
}

func TestResolverAlignExactAndLesser(t *testing.T) {
	t.Parallel()

	handler := NewFormatHandler()
	resolver := NewResolver(handler)
	source := "Patient is prescribed Naprosyn and high glucose."

	extractions := []Extraction{
		{ExtractionClass: "medication", ExtractionText: "Naprosyn"},
		{ExtractionClass: "condition", ExtractionText: "high blood pressure"},
	}
	aligned := resolver.Align(extractions, source, 0, 0, DefaultAlignOptions())

	if aligned[0].Alignment != AlignmentExact {
		t.Fatalf("expected first extraction exact alignment, got %s", aligned[0].Alignment)
	}
	if aligned[1].Alignment != AlignmentLesser {
		t.Fatalf("expected second extraction lesser alignment, got %s", aligned[1].Alignment)
	}
}

func TestResolverAlignFuzzy(t *testing.T) {
	t.Parallel()

	handler := NewFormatHandler()
	resolver := NewResolver(handler)
	source := "Patient has severe cardiac issues today."

	extractions := []Extraction{
		{ExtractionClass: "condition", ExtractionText: "heart issues"},
	}
	opts := DefaultAlignOptions()
	opts.FuzzyAlignmentThreshold = 0.5
	opts.AcceptMatchLesser = false

	aligned := resolver.Align(extractions, source, 0, 0, opts)
	if aligned[0].Alignment != AlignmentFuzzy {
		t.Fatalf("expected fuzzy alignment, got %s", aligned[0].Alignment)
	}
}
