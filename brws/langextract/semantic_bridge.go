package langextract

import (
	"github.com/skunkworq/stealth/brws/semantic"
)

// SemanticResult is semantic-first extraction output.
type SemanticResult = semantic.ExtractionResult

// ToSemantic converts raw extraction results into semantic result shape.
func ToSemantic(raw *RawExtractionResult) SemanticResult {
	if raw == nil {
		return SemanticResult{}
	}
	out := SemanticResult{
		DocumentID:      raw.DocumentID,
		Text:            raw.Text,
		DocumentCount:   raw.DocumentCount,
		PassesPerformed: raw.PassesPerformed,
		ModelID:         raw.ModelID,
		Provider:        raw.Provider,
		Metadata:        cloneMap(raw.Metadata),
		Extractions:     make([]semantic.ExtractionItem, 0, len(raw.Extractions)),
	}
	// Only populate Usage when something material was reported. An empty
	// struct still renders as `"usage":{}` in JSON which would clutter
	// callers that never enabled a usage-reporting provider.
	if raw.Usage.TotalTokens > 0 || raw.Usage.LatencyMs > 0 || raw.Usage.Provider != "" {
		out.Usage = &semantic.ExtractionUsage{
			Provider:          raw.Usage.Provider,
			Model:             raw.Usage.Model,
			InputTokens:       raw.Usage.InputTokens,
			OutputTokens:      raw.Usage.OutputTokens,
			TotalTokens:       raw.Usage.TotalTokens,
			CachedInputTokens: raw.Usage.CachedInputTokens,
			ReasoningTokens:   raw.Usage.ReasoningTokens,
			LatencyMs:         raw.Usage.LatencyMs,
			CostUSD:           raw.Usage.CostUSD,
		}
	}

	for _, ext := range raw.Extractions {
		item := semantic.ExtractionItem{
			Class:           ext.ExtractionClass,
			Text:            ext.ExtractionText,
			Description:     ext.Description,
			Attributes:      cloneMap(ext.Attributes),
			Alignment:       semantic.ExtractionAlignment(ext.Alignment),
			ExtractionIndex: ext.ExtractionIndex,
			GroupIndex:      ext.GroupIndex,
			DocumentID:      raw.DocumentID,
			Span: semantic.ExtractionSpan{
				CharStart:  ext.CharStart(),
				CharEnd:    ext.CharEnd(),
				TokenStart: ext.TokenStart(),
				TokenEnd:   ext.TokenEnd(),
			},
		}
		out.Extractions = append(out.Extractions, item)
	}

	return out
}

// MustToSemantic converts raw extraction results and panics on nil input.
func MustToSemantic(raw *RawExtractionResult) SemanticResult {
	if raw == nil {
		panic("raw extraction result is nil")
	}
	return ToSemantic(raw)
}

func cloneMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
