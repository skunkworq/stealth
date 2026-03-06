//go:build go1.18

package langextract

import "testing"

func FuzzFormatHandlerParseOutput(f *testing.F) {
	handler := NewFormatHandler()
	handler.FormatType = FormatTypeJSON
	handler.UseWrapper = true
	handler.WrapperKey = ExtractionKey
	handler.UseFences = true
	handler.AllowTopLevelList = true

	seeds := []string{
		"```json\n{\"extractions\":[{\"person\":\"Alice\"}]}\n```",
		"{\"extractions\":[{\"person\":\"Bob\"}]}",
		"<think>reasoning</think>{\"extractions\":[{\"person\":\"Carol\"}]}",
		"```yaml\nextractions:\n  - person: Dana\n```",
		"[{\"person\":\"Eve\"}]",
		"invalid output",
		"",
	}
	for _, seed := range seeds {
		f.Add(seed, false)
		f.Add(seed, true)
	}

	f.Fuzz(func(t *testing.T, input string, strict bool) {
		parsed, err := handler.ParseOutput(input, strict)
		if err != nil {
			return
		}

		resolver := NewResolver(handler)
		extractions, err := resolver.ExtractOrderedExtractions(parsed)
		if err != nil {
			t.Fatalf("extract ordered failed after successful parse: %v", err)
		}

		for i := range extractions {
			if extractions[i].ExtractionClass == "" {
				t.Fatalf("extraction class should not be empty for parsed extraction %d", i)
			}
		}
	})
}
