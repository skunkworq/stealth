package extract

import "testing"

func TestToSemantic(t *testing.T) {
	t.Parallel()

	raw := &RawExtractionResult{
		DocumentID:      "doc-1",
		Text:            "Alice met Bob.",
		DocumentCount:   1,
		PassesPerformed: 1,
		ModelID:         "gpt-4o-mini",
		Provider:        "openai",
		Extractions: []Extraction{
			{
				ExtractionClass: "person",
				ExtractionText:  "Alice",
				ExtractionIndex: 1,
				GroupIndex:      0,
				Alignment:       AlignmentExact,
				CharInterval:    &CharInterval{StartPos: 0, EndPos: 5},
				TokenInterval:   &TokenInterval{StartIndex: 0, EndIndex: 1},
				Attributes: map[string]any{
					"role": "engineer",
				},
			},
		},
	}

	result := ToSemantic(raw)
	if result.DocumentID != "doc-1" {
		t.Fatalf("unexpected document id: %q", result.DocumentID)
	}
	if len(result.Extractions) != 1 {
		t.Fatalf("expected 1 extraction, got %d", len(result.Extractions))
	}
	if result.Extractions[0].Span.CharStart != 0 || result.Extractions[0].Span.CharEnd != 5 {
		t.Fatalf("unexpected span: %+v", result.Extractions[0].Span)
	}
}

func TestToSemanticNilInput(t *testing.T) {
	t.Parallel()

	result := ToSemantic(nil)
	if result.DocumentID != "" {
		t.Fatalf("expected zero-value semantic result for nil input")
	}
	if len(result.Extractions) != 0 {
		t.Fatalf("expected no extractions for nil input")
	}
}

func TestMustToSemanticPanicsOnNil(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic for nil raw result")
		}
	}()
	_ = MustToSemantic(nil)
}
