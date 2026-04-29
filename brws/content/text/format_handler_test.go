package langextract

import "testing"

func TestFormatHandlerRoundTripJSON(t *testing.T) {
	t.Parallel()

	handler := NewFormatHandler()
	handler.FormatType = FormatTypeJSON
	handler.UseWrapper = true
	handler.WrapperKey = ExtractionKey
	handler.UseFences = true

	formatted, err := handler.FormatExtractionExample([]Extraction{
		{
			ExtractionClass: "person",
			ExtractionText:  "Alice",
			Attributes: map[string]any{
				"role": "engineer",
			},
		},
	})
	if err != nil {
		t.Fatalf("format failed: %v", err)
	}

	parsed, err := handler.ParseOutput(formatted, false)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if got := len(parsed); got != 1 {
		t.Fatalf("expected 1 parsed item, got %d", got)
	}
	if parsed[0]["person"] != "Alice" {
		t.Fatalf("expected person Alice, got %v", parsed[0]["person"])
	}
}

func TestFormatHandlerThinkTagFallback(t *testing.T) {
	t.Parallel()

	handler := NewFormatHandler()
	handler.FormatType = FormatTypeJSON
	handler.UseWrapper = true
	handler.WrapperKey = ExtractionKey
	handler.UseFences = false

	input := `<think>Reasoning output</think>{"extractions":[{"person":"Alice"}]}`
	parsed, err := handler.ParseOutput(input, false)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("expected 1 parsed item, got %d", len(parsed))
	}
	if parsed[0]["person"] != "Alice" {
		t.Fatalf("expected Alice, got %v", parsed[0]["person"])
	}
}

func TestFormatHandlerTopLevelListFallback(t *testing.T) {
	t.Parallel()

	handler := NewFormatHandler()
	handler.FormatType = FormatTypeJSON
	handler.UseWrapper = true
	handler.WrapperKey = ExtractionKey
	handler.UseFences = false

	parsed, err := handler.ParseOutput(`[{"person":"Bob"},{"person":"Carol"}]`, false)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(parsed) != 2 {
		t.Fatalf("expected 2 parsed items, got %d", len(parsed))
	}
}

func TestFormatHandlerStrictFenceValidation(t *testing.T) {
	t.Parallel()

	handler := NewFormatHandler()
	handler.FormatType = FormatTypeJSON
	handler.UseWrapper = true
	handler.UseFences = true
	handler.StrictFences = true

	_, err := handler.ParseOutput(`{"extractions":[{"person":"Alice"}]}`, false)
	if err == nil {
		t.Fatalf("expected strict fence parse error")
	}
}
