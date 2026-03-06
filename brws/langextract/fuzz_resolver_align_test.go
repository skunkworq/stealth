//go:build go1.18

package langextract

import "testing"

func FuzzResolverAlign(f *testing.F) {
	seeds := []struct {
		source     string
		class      string
		text       string
		threshold  float64
		acceptLess bool
	}{
		{"Patient is prescribed Naprosyn and prednisone.", "medication", "Naprosyn", 0.75, true},
		{"Patient has severe cardiac issues today.", "condition", "heart issues", 0.5, false},
		{"", "entity", "anything", 0.75, true},
		{"Symbols: @@@ !!! ###", "token", "@@@", 0.6, true},
	}
	for _, seed := range seeds {
		f.Add(seed.source, seed.class, seed.text, seed.threshold, seed.acceptLess)
	}

	f.Fuzz(func(t *testing.T, source, class, text string, threshold float64, acceptLess bool) {
		if threshold < 0 {
			threshold = 0
		}
		if threshold > 1 {
			threshold = 1
		}

		resolver := NewResolver(NewFormatHandler())
		opts := DefaultAlignOptions()
		opts.FuzzyAlignmentThreshold = threshold
		opts.AcceptMatchLesser = acceptLess

		extractions := []Extraction{
			{
				ExtractionClass: class,
				ExtractionText:  text,
			},
		}
		aligned := resolver.Align(extractions, source, 0, 0, opts)
		if len(aligned) != 1 {
			t.Fatalf("expected 1 aligned extraction, got %d", len(aligned))
		}

		tokenized := opts.Tokenizer.Tokenize(source)
		if aligned[0].TokenInterval != nil {
			ti := aligned[0].TokenInterval
			if ti.StartIndex < 0 || ti.EndIndex < ti.StartIndex || ti.EndIndex > len(tokenized.Tokens) {
				t.Fatalf("invalid token interval: %+v token_len=%d", *ti, len(tokenized.Tokens))
			}
		}
		if aligned[0].CharInterval != nil {
			ci := aligned[0].CharInterval
			if ci.StartPos < 0 || ci.EndPos < ci.StartPos || ci.EndPos > len(source) {
				t.Fatalf("invalid char interval: %+v source_len=%d", *ci, len(source))
			}
		}
	})
}
