package semantic

// ExtractionAlignment describes how extracted text aligned to source text.
type ExtractionAlignment string

const (
	ExtractionAlignmentExact   ExtractionAlignment = "match_exact"
	ExtractionAlignmentGreater ExtractionAlignment = "match_greater"
	ExtractionAlignmentLesser  ExtractionAlignment = "match_lesser"
	ExtractionAlignmentFuzzy   ExtractionAlignment = "match_fuzzy"
)

// ExtractionSpan stores character and token boundaries.
type ExtractionSpan struct {
	CharStart  int `json:"char_start"`
	CharEnd    int `json:"char_end"`
	TokenStart int `json:"token_start"`
	TokenEnd   int `json:"token_end"`
}

// ExtractionItem is one extraction in semantic result form.
type ExtractionItem struct {
	Class           string              `json:"class"`
	Text            string              `json:"text"`
	Description     string              `json:"description,omitempty"`
	Attributes      map[string]any      `json:"attributes,omitempty"`
	Alignment       ExtractionAlignment `json:"alignment,omitempty"`
	Span            ExtractionSpan      `json:"span"`
	ExtractionIndex int                 `json:"extraction_index"`
	GroupIndex      int                 `json:"group_index"`
	DocumentID      string              `json:"document_id,omitempty"`
}

// ExtractionResult is semantic-first output for langextract.
type ExtractionResult struct {
	DocumentID      string           `json:"document_id"`
	Text            string           `json:"text"`
	Extractions     []ExtractionItem `json:"extractions"`
	DocumentCount   int              `json:"document_count"`
	PassesPerformed int              `json:"passes_performed"`
	ModelID         string           `json:"model_id,omitempty"`
	Provider        string           `json:"provider,omitempty"`
	Metadata        map[string]any   `json:"metadata,omitempty"`
}
