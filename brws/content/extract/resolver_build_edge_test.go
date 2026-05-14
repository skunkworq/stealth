package extract

import (
	"math"
	"testing"
)

func TestBuildResolverParsesAndValidatesParams(t *testing.T) {
	t.Parallel()

	handler := NewFormatHandler()
	resolver, align, suppress, err := buildResolver(
		handler,
		map[string]any{
			"extraction_index_suffix":   "_index",
			"strict":                    true,
			"enable_fuzzy_alignment":    false,
			"accept_match_lesser":       false,
			"fuzzy_alignment_threshold": float32(0.6),
			"suppress_parse_errors":     true,
		},
		DefaultTokenizer,
	)
	if err != nil {
		t.Fatalf("unexpected buildResolver error: %v", err)
	}
	if resolver.ExtractionIndexSuffix != "_index" || !resolver.Strict {
		t.Fatalf("resolver params not applied: %+v", resolver)
	}
	if align.EnableFuzzyAlignment || align.AcceptMatchLesser {
		t.Fatalf("expected alignment flags to be false: %+v", align)
	}
	if math.Abs(align.FuzzyAlignmentThreshold-0.6) > 1e-6 {
		t.Fatalf("expected fuzzy threshold 0.6, got %v", align.FuzzyAlignmentThreshold)
	}
	if !suppress {
		t.Fatalf("expected suppress_parse_errors=true")
	}
}

func TestBuildResolverRejectsInvalidParams(t *testing.T) {
	t.Parallel()

	handler := NewFormatHandler()
	if _, _, _, err := buildResolver(
		handler,
		map[string]any{"extraction_index_suffix": 123},
		DefaultTokenizer,
	); err == nil {
		t.Fatalf("expected extraction_index_suffix type error")
	}

	if _, _, _, err := buildResolver(
		handler,
		map[string]any{"fuzzy_alignment_threshold": "bad"},
		DefaultTokenizer,
	); err == nil {
		t.Fatalf("expected fuzzy_alignment_threshold type error")
	}

	if _, _, _, err := buildResolver(
		handler,
		map[string]any{"unknown_param": true},
		DefaultTokenizer,
	); err == nil {
		t.Fatalf("expected unknown resolver param error")
	}
}

func TestResolverExtractOrderedExtractionsNumericAndInvalidTypes(t *testing.T) {
	t.Parallel()

	resolver := NewResolver(NewFormatHandler())
	resolver.ExtractionIndexSuffix = "_index"

	parsed := []map[string]any{
		{
			"count":       int64(3),
			"count_index": float64(1),
			"ratio":       float32(1.5),
			"ratio_index": int32(2),
			"whole":       float64(2),
			"whole_index": int(3),
		},
	}

	extractions, err := resolver.ExtractOrderedExtractions(parsed)
	if err != nil {
		t.Fatalf("unexpected extraction parse error: %v", err)
	}
	if len(extractions) != 3 {
		t.Fatalf("expected 3 extractions, got %d", len(extractions))
	}
	if extractions[0].ExtractionText != "3" {
		t.Fatalf("expected int64 to render as 3, got %q", extractions[0].ExtractionText)
	}
	if extractions[1].ExtractionText != "1.5" {
		t.Fatalf("expected float32 to render as 1.5, got %q", extractions[1].ExtractionText)
	}
	if extractions[2].ExtractionText != "2" {
		t.Fatalf("expected integral float64 to render as 2, got %q", extractions[2].ExtractionText)
	}

	_, err = resolver.ExtractOrderedExtractions([]map[string]any{
		{"item": "x", "item_index": 1.25},
	})
	if err == nil {
		t.Fatalf("expected non-integral index error")
	}

	_, err = resolver.ExtractOrderedExtractions([]map[string]any{
		{"flag": true, "flag_index": 1},
	})
	if err == nil {
		t.Fatalf("expected invalid extraction value type error")
	}
}
