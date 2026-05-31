package extract

import (
	"context"

	"github.com/skunkworq/stealth/brws/langextract"
)

// knownKeys is the set of extraction classes the LLM extractor maps to fields.
// An extraction whose class isn't a known FieldKey is dropped.
var knownKeys = map[FieldKey]bool{
	KeyLegalName: true, KeyABN: true, KeyACN: true, KeyLicence: true,
	KeyPhone: true, KeyEmail: true, KeyAddress: true, KeyWebsite: true,
	KeySocialFB: true, KeySocialIG: true, KeySocialLI: true, KeyLogoURL: true,
	KeyService: true, KeyHours: true, KeyIndustry: true,
}

func candidatesFromExtractions(exs []langextract.Extraction) []Candidate {
	out := make([]Candidate, 0, len(exs))
	for _, e := range exs {
		key := FieldKey(e.ExtractionClass)
		if !knownKeys[key] {
			continue
		}
		c := Candidate{Key: key, Value: e.ExtractionText, Method: MethodLLMLangextract, Conf: 0.6}
		if e.CharInterval != nil {
			c.SpanHint = &Span{Start: e.CharInterval.StartPos, End: e.CharInterval.EndPos}
		}
		out = append(out, c)
	}
	return out
}

// LLMExtractor runs langextract over a document and maps grounded extractions
// to candidates. Options (model config, examples, prompt) are injected by the
// caller so stealth owns no API keys.
type LLMExtractor struct {
	Opts []langextract.Option
}

func (LLMExtractor) Name() string { return "llm_langextract" }

func (l LLMExtractor) Extract(ctx context.Context, doc *SourceDocument) ([]Candidate, error) {
	if doc == nil || doc.Text == "" {
		return nil, nil
	}
	// Disable URL fetching: we extract from the supplied text only.
	opts := append([]langextract.Option{langextract.WithFetchURLs(false)}, l.Opts...)
	raw, err := langextract.ExtractRaw(ctx, doc.Text, opts...)
	if err != nil {
		return nil, err
	}
	return candidatesFromExtractions(raw.Extractions), nil
}
