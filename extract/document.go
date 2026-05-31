package extract

import "time"

// SourceDocument is a normalised unit of source text with provenance. The
// engine indexes spans into Text.
type SourceDocument struct {
	ID          string
	Ref         string // "https://acme.com.au/contact" or "record:sa-licence:BLD-100245"
	ContentType string
	Text        string
	FetchedAt   time.Time
}
