package extract

import (
	"fmt"

	"github.com/skunkworq/stealth/brws/content/understand"
)

// SemanticResult is semantic-first extraction output.
type SemanticResult = understand.ExtractionResult

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
		Extractions:     make([]understand.ExtractionItem, 0, len(raw.Extractions)),
	}

	for _, ext := range raw.Extractions {
		item := understand.ExtractionItem{
			Class:           ext.ExtractionClass,
			Text:            ext.ExtractionText,
			Description:     ext.Description,
			Attributes:      cloneMap(ext.Attributes),
			Alignment:       understand.ExtractionAlignment(ext.Alignment),
			ExtractionIndex: ext.ExtractionIndex,
			GroupIndex:      ext.GroupIndex,
			DocumentID:      raw.DocumentID,
			Span: understand.ExtractionSpan{
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

// ToSemanticSafe converts raw extraction results and returns an error on nil input.
func ToSemanticSafe(raw *RawExtractionResult) (SemanticResult, error) {
	if raw == nil {
		return SemanticResult{}, fmt.Errorf("raw extraction result is nil")
	}
	return ToSemantic(raw), nil
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
