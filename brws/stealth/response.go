package stealth

import (
	"sync"

	"golang.org/x/net/html"

	"github.com/skunkworq/stealth/brws/browser/engine"
	"github.com/skunkworq/stealth/brws/content/understand"
)

// Response represents the result of a navigation.
// It embeds engine.Response so all transport fields (Status, Headers, Body,
// FinalURL, Trace, Protocol, Timing) are promoted directly onto this type.
type Response struct {
	engine.Response

	// ChallengeSolved is true if an anti-bot challenge was detected and
	// successfully solved during this request.
	ChallengeSolved bool

	// semanticTree, when non-nil, is used by extraction methods instead of
	// re-parsing the raw HTML body.
	semanticTree *understand.SemanticTree

	// Lazy-parsing fields for extraction methods.
	parseOnce sync.Once
	doc       *html.Node
	bodyStr   string
}
