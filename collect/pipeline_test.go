package collect

import (
	"context"
	"testing"
	"time"

	"github.com/skunkworq/stealth/extract"
)

func TestCollectorThroughEngineExtractsAndDropsForged(t *testing.T) {
	raw := `<html><head><script type="application/ld+json">
	{"@type":"LocalBusiness","name":"Acme","telephone":"0412 345 678","email":"x@acme.com.au"}
	</script></head><body><h1>Acme</h1></body></html>`
	c := NewCollector(fakeRenderer{html: raw, final: "https://acme.com.au/"})
	c.now = func() time.Time { return time.Unix(0, 0).UTC() }
	docs, err := c.Collect(context.Background(), "https://acme.com.au")
	if err != nil {
		t.Fatal(err)
	}
	eng := extract.NewEngine(extract.RegexExtractor{}, extract.TelMailtoExtractor{}, LdJSONExtractor{}, MetaExtractor{})
	fields, _ := eng.Extract(context.Background(), docsToPtrs(docs), []extract.FieldKey{extract.KeyPhone, extract.KeyEmail})
	var phone, email bool
	for _, f := range fields {
		if f.Key == extract.KeyPhone && f.Value != "" {
			phone = true
		}
		if f.Key == extract.KeyEmail {
			email = true
		}
	}
	if !phone || !email {
		t.Fatalf("expected phone+email from ld+json, got %+v", fields)
	}

	// A value not present in the plain text must not be emitted.
	forged := []*extract.SourceDocument{{Ref: "r", ContentType: "text/plain", Text: "Acme Plumbing"}}
	f2, _ := eng.Extract(context.Background(), forged, []extract.FieldKey{extract.KeyPhone})
	for _, f := range f2 {
		if f.Key == extract.KeyPhone {
			t.Fatal("no phone is present in the plain text; none must be emitted")
		}
	}
}

func docsToPtrs(in []extract.SourceDocument) []*extract.SourceDocument {
	out := make([]*extract.SourceDocument, len(in))
	for i := range in {
		out[i] = &in[i]
	}
	return out
}
