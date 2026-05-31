package collect

import (
	"context"
	"testing"

	"github.com/skunkworq/stealth/extract"
)

func TestLdJSONExtractor(t *testing.T) {
	raw := `<html><head><script type="application/ld+json">
	{"@type":"LocalBusiness","name":"Acme Plumbing Pty Ltd","telephone":"0412 345 678",
	 "email":"bob@acme.com.au","url":"https://acme.com.au",
	 "address":{"@type":"PostalAddress","streetAddress":"12 High St","addressLocality":"Maitland"}}
	</script></head><body>x</body></html>`
	doc := &extract.SourceDocument{Ref: "https://acme.com.au/", ContentType: "text/html", Text: raw}
	cands, err := LdJSONExtractor{}.Extract(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	got := map[extract.FieldKey]string{}
	for _, c := range cands {
		if c.Method != extract.MethodLdJSON {
			t.Errorf("wrong method %q", c.Method)
		}
		got[c.Key] = c.Value
	}
	if got[extract.KeyPhone] != "0412 345 678" {
		t.Errorf("phone %q", got[extract.KeyPhone])
	}
	if got[extract.KeyEmail] != "bob@acme.com.au" {
		t.Errorf("email %q", got[extract.KeyEmail])
	}
	if got[extract.KeyLegalName] != "Acme Plumbing Pty Ltd" {
		t.Errorf("name %q", got[extract.KeyLegalName])
	}
	if got[extract.KeyAddress] != "12 High St" {
		t.Errorf("address %q", got[extract.KeyAddress])
	}
}

func TestLdJSONExtractorSkipsNonHTML(t *testing.T) {
	doc := &extract.SourceDocument{ContentType: "text/plain", Text: `{"telephone":"0412 345 678"}`}
	cands, _ := LdJSONExtractor{}.Extract(context.Background(), doc)
	if len(cands) != 0 {
		t.Fatalf("must skip non-html docs, got %d", len(cands))
	}
}
