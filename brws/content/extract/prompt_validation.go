package extract

import "fmt"

// PromptValidationIssue captures a non-exact prompt example alignment.
type PromptValidationIssue struct {
	ExampleIndex    int
	ExtractionClass string
	ExtractionText  string
	Alignment       AlignmentStatus
}

// PromptValidationReport summarizes prompt/example alignment quality.
type PromptValidationReport struct {
	Issues []PromptValidationIssue
}

// HasIssues reports whether any validation issue was found.
func (r PromptValidationReport) HasIssues() bool { return len(r.Issues) > 0 }

// HasFailed reports whether any extraction could not be aligned at all.
func (r PromptValidationReport) HasFailed() bool {
	for _, issue := range r.Issues {
		if issue.Alignment == "" {
			return true
		}
	}
	return false
}

// HasNonExact reports whether any extraction aligned as lesser/fuzzy.
func (r PromptValidationReport) HasNonExact() bool {
	for _, issue := range r.Issues {
		if issue.Alignment != "" && issue.Alignment != AlignmentExact {
			return true
		}
	}
	return false
}

// Error is equivalent to ErrorForMode(true).
func (r PromptValidationReport) Error() error {
	return r.ErrorForMode(true)
}

// ErrorForMode returns a mode-aware error representation of this report.
//
// When strictNonExact is false, non-exact alignments do not produce an error
// unless there are failed alignments.
// When strictNonExact is true, non-exact alignments are also treated as errors.
func (r PromptValidationReport) ErrorForMode(strictNonExact bool) error {
	if !r.HasIssues() {
		return nil
	}
	failed := make([]PromptValidationIssue, 0)
	nonExact := make([]PromptValidationIssue, 0)
	for _, issue := range r.Issues {
		if issue.Alignment == "" {
			failed = append(failed, issue)
			continue
		}
		if issue.Alignment != AlignmentExact {
			nonExact = append(nonExact, issue)
		}
	}
	if len(failed) > 0 {
		first := failed[0]
		return fmt.Errorf(
			"prompt validation failed: %d extraction(s) could not be aligned (e.g., example[%d] %q=%q)",
			len(failed),
			first.ExampleIndex,
			first.ExtractionClass,
			first.ExtractionText,
		)
	}
	if strictNonExact && len(nonExact) > 0 {
		first := nonExact[0]
		return fmt.Errorf(
			"prompt validation failed under strict mode: %d non-exact match(es) found (e.g., example[%d] %q=%q aligned as %q)",
			len(nonExact),
			first.ExampleIndex,
			first.ExtractionClass,
			first.ExtractionText,
			first.Alignment,
		)
	}
	return nil
}

// ValidatePromptExamples validates that few-shot examples align cleanly to their source text.
func ValidatePromptExamples(examples []ExampleData, tokenizer Tokenizer) PromptValidationReport {
	if tokenizer == nil {
		tokenizer = DefaultTokenizer
	}
	resolver := NewResolver(NewFormatHandler())
	alignOpts := DefaultAlignOptions()
	alignOpts.Tokenizer = tokenizer

	report := PromptValidationReport{Issues: []PromptValidationIssue{}}
	for i, ex := range examples {
		for _, extraction := range ex.Extractions {
			aligned := resolver.Align([]Extraction{extraction}, ex.Text, 0, 0, alignOpts)
			status := AlignmentStatus("")
			if len(aligned) > 0 {
				status = aligned[0].Alignment
			}
			if status != AlignmentExact {
				report.Issues = append(report.Issues, PromptValidationIssue{
					ExampleIndex:    i,
					ExtractionClass: extraction.ExtractionClass,
					ExtractionText:  extraction.ExtractionText,
					Alignment:       status,
				})
			}
		}
	}
	return report
}
