package extract

import "context"

// Extractor proposes candidates from a single document. Extractors never
// emit Fields directly — every candidate must pass the Validator.
type Extractor interface {
	Name() string
	Extract(ctx context.Context, doc *SourceDocument) ([]Candidate, error)
}
