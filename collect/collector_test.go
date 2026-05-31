package collect

import (
	"context"
	"testing"
	"time"
)

type fakeRenderer struct {
	html  string
	final string
}

func (f fakeRenderer) Render(_ context.Context, _ string) (*RawPage, error) {
	return &RawPage{HTML: []byte(f.html), FinalURL: f.final}, nil
}

func TestCollectorEmitsTwoViews(t *testing.T) {
	fixed := time.Date(2026, 5, 31, 0, 0, 0, 0, time.UTC)
	c := NewCollector(fakeRenderer{
		html:  `<html><body><h1>Acme</h1><p>0412 345 678</p></body></html>`,
		final: "https://acme.com.au/",
	})
	c.now = func() time.Time { return fixed }

	docs, err := c.Collect(context.Background(), "https://acme.com.au")
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 2 {
		t.Fatalf("want 2 docs, got %d", len(docs))
	}
	byType := map[string]string{}
	for _, d := range docs {
		byType[d.ContentType] = d.Text
		if d.Ref != "https://acme.com.au/" {
			t.Errorf("ref should be FinalURL, got %q", d.Ref)
		}
		if !d.FetchedAt.Equal(fixed) {
			t.Errorf("FetchedAt not injected clock")
		}
	}
	if _, ok := byType["text/plain"]; !ok {
		t.Error("missing text/plain view")
	}
	if raw, ok := byType["text/html"]; !ok || raw == "" {
		t.Error("missing text/html view")
	}
}
