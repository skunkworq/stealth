package collect

import (
	"context"
	"time"

	"github.com/skunkworq/stealth/extract"
)

// Collector turns a URL into extract.SourceDocuments using a Renderer.
type Collector struct {
	renderer Renderer
	now      func() time.Time
}

func NewCollector(r Renderer) *Collector {
	return &Collector{renderer: r, now: time.Now}
}

// Collect renders the URL and emits two views of the page: a cleaned visible-
// text document (for LLM/freetext/regex extraction) and a raw-HTML document
// (for structured extractors that need markup). Both carry the final URL as Ref.
func (c *Collector) Collect(ctx context.Context, url string) ([]extract.SourceDocument, error) {
	page, err := c.renderer.Render(ctx, url)
	if err != nil {
		return nil, err
	}
	if len(page.HTML) == 0 {
		return nil, nil
	}
	at := c.now()
	ref := page.FinalURL
	if ref == "" {
		ref = url
	}
	return []extract.SourceDocument{
		{Ref: ref, ContentType: "text/plain", Text: visibleText(string(page.HTML)), FetchedAt: at},
		{Ref: ref, ContentType: "text/html", Text: string(page.HTML), FetchedAt: at},
	}, nil
}
