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
	// Usage carries aggregate token-and-timing telemetry for the entire
	// extraction (sum across passes, batches, chunks). Nil when no provider
	// in the chain reported usage (e.g. Ollama, custom test stubs). Per-call
	// detail is in Metadata["usage_history"] when available. Pointer rather
	// than value so the JSON encoding omits the field cleanly when there's
	// nothing to report — keeps existing golden fixtures stable.
	Usage *ExtractionUsage `json:"usage,omitempty"`
}

// ExtractionUsage is the aggregated token-and-timing telemetry for an
// extraction call. Same shape as langextract.InferenceUsage, restated here
// to keep the semantic package free of langextract import (the langextract
// package converts at the bridge).
type ExtractionUsage struct {
	Provider          string  `json:"provider,omitempty"`
	Model             string  `json:"model,omitempty"`
	InputTokens       int64   `json:"input_tokens,omitempty"`
	OutputTokens      int64   `json:"output_tokens,omitempty"`
	TotalTokens       int64   `json:"total_tokens,omitempty"`
	CachedInputTokens int64   `json:"cached_input_tokens,omitempty"`
	ReasoningTokens   int64   `json:"reasoning_tokens,omitempty"`
	LatencyMs         int64   `json:"latency_ms,omitempty"`
	CostUSD           float64 `json:"cost_usd,omitempty"`
}
