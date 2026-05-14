package extract

import (
	"context"
	"strings"
	"testing"
)

func TestValidatePromptExamples(t *testing.T) {
	t.Parallel()

	report := ValidatePromptExamples([]ExampleData{
		{
			Text: "No matching person here.",
			Extractions: []Extraction{
				{
					ExtractionClass: "person",
					ExtractionText:  "Alice",
				},
			},
		},
	}, DefaultTokenizer)

	if !report.HasIssues() {
		t.Fatalf("expected prompt validation issues")
	}
	if !report.HasFailed() {
		t.Fatalf("expected failed alignment issue")
	}
	if report.HasNonExact() {
		t.Fatalf("did not expect non-exact issue for missing extraction")
	}
}

func TestExtractRawPromptValidationError(t *testing.T) {
	t.Parallel()

	_, err := ExtractRaw(
		context.Background(),
		"Alice works at Acme.",
		WithExamples(ExampleData{
			Text: "No matching person here.",
			Extractions: []Extraction{
				{ExtractionClass: "person", ExtractionText: "Alice"},
			},
		}),
		WithModel(newFakeExtractor(`{"extractions":[{"person":"Alice"}]}`)),
		WithPromptValidationLevel(PromptValidationError),
	)
	if err == nil {
		t.Fatalf("expected prompt validation error")
	}
}

func TestExtractRawPromptValidationWarning(t *testing.T) {
	t.Parallel()

	raw, err := ExtractRaw(
		context.Background(),
		"Alice works at Acme.",
		WithExamples(ExampleData{
			Text: "No matching person here.",
			Extractions: []Extraction{
				{ExtractionClass: "person", ExtractionText: "Alice"},
			},
		}),
		WithModel(newFakeExtractor(`{"extractions":[{"person":"Alice"}]}`)),
		WithPromptValidationLevel(PromptValidationWarning),
	)
	if err != nil {
		t.Fatalf("expected warning mode to continue, got error: %v", err)
	}
	if len(raw.Extractions) == 0 {
		t.Fatalf("expected extraction output in warning mode")
	}
}

func TestExtractRawPromptValidationStrictNonExact(t *testing.T) {
	t.Parallel()

	example := ExampleData{
		Text: "Patient is prescribed Naprosyn and high glucose.",
		Extractions: []Extraction{
			{ExtractionClass: "condition", ExtractionText: "high blood pressure"},
		},
	}

	report := ValidatePromptExamples([]ExampleData{example}, DefaultTokenizer)
	if !report.HasNonExact() {
		t.Fatalf("expected non-exact prompt validation issue")
	}
	if report.HasFailed() {
		t.Fatalf("expected non-exact issue without failed alignment")
	}

	if _, err := ExtractRaw(
		context.Background(),
		"Alice works at Acme.",
		WithExamples(example),
		WithModel(newFakeExtractor(`{"extractions":[{"person":"Alice"}]}`)),
		WithPromptValidationLevel(PromptValidationError),
	); err != nil {
		t.Fatalf("expected non-strict error mode to continue on non-exact issues: %v", err)
	}

	if _, err := ExtractRaw(
		context.Background(),
		"Alice works at Acme.",
		WithExamples(example),
		WithModel(newFakeExtractor(`{"extractions":[{"person":"Alice"}]}`)),
		WithPromptValidationLevel(PromptValidationError),
		WithPromptValidationStrict(true),
	); err == nil {
		t.Fatalf("expected strict non-exact prompt validation error")
	}
}

func TestPromptValidationReportErrorModes(t *testing.T) {
	t.Parallel()

	report := PromptValidationReport{
		Issues: []PromptValidationIssue{
			{
				ExampleIndex:    0,
				ExtractionClass: "condition",
				ExtractionText:  "high blood pressure",
				Alignment:       AlignmentLesser,
			},
		},
	}
	if err := report.ErrorForMode(false); err != nil {
		t.Fatalf("expected non-strict mode to allow non-exact issues, got %v", err)
	}
	if err := report.Error(); err == nil || !strings.Contains(err.Error(), "strict mode") {
		t.Fatalf("expected strict-mode error from Error(), got %v", err)
	}
}
