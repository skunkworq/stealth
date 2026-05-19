package stealth

import (
	"sync"

	"golang.org/x/net/html"

	"github.com/skunkworq/stealth/brws/browser/engine"
	"github.com/skunkworq/stealth/brws/content/understand"
)

// Type aliases so existing code that constructs stealth.PageMeta{…} etc. continues to compile.
type (
	PageMeta         = understand.PageMeta
	SocialLinks      = understand.SocialLinks
	Link             = understand.Link
	ColorInfo        = understand.ColorInfo
	FontInfo         = understand.FontInfo
	ImageWithContext = understand.ImageWithContext
)

// Response represents the result of a navigation.
// It embeds engine.Response so all transport fields (Status, Headers, Body,
// FinalURL, Trace, Protocol, Timing) are promoted directly onto this type.
type Response struct {
	engine.Response

	Tree *understand.SemanticTree

	// ChallengeSolved is true if an anti-bot challenge was detected and
	// successfully solved during this request.
	ChallengeSolved bool

	// Lazy-parsing fields for extraction methods.
	parseOnce sync.Once
	doc       *html.Node
	bodyStr   string
}

// AttachSemanticTree associates a pre-built semantic tree with this response,
// enabling extraction methods to delegate to the tree instead of regex.
func (r *Response) AttachSemanticTree(tree *understand.SemanticTree) {
	r.Tree = tree
}
