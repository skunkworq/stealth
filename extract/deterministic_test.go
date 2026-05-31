package extract

import (
	"context"
	"testing"
)

func TestRegexExtractorABNPhoneEmail(t *testing.T) {
	doc := &SourceDocument{Ref: "r", ContentType: "text/html",
		Text: `Acme Plumbing. ABN 50 629 080 842. Call 0412 345 678 or email bob@acme.com.au`}
	cands, err := RegexExtractor{}.Extract(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	got := map[FieldKey]string{}
	for _, c := range cands {
		got[c.Key] = c.Value
	}
	if digitsOnly(got[KeyABN]) != "50629080842" {
		t.Errorf("abn: %q", got[KeyABN])
	}
	if got[KeyEmail] != "bob@acme.com.au" {
		t.Errorf("email: %q", got[KeyEmail])
	}
	if digitsOnly(got[KeyPhone]) == "" {
		t.Errorf("phone missing")
	}
}

func TestTelMailtoExtractor(t *testing.T) {
	doc := &SourceDocument{Ref: "r", ContentType: "text/html",
		Text: `<a href="tel:+61412345678">call</a> <a href="mailto:hi@acme.com.au">mail</a>`}
	cands, _ := TelMailtoExtractor{}.Extract(context.Background(), doc)
	var sawPhone, sawEmail bool
	for _, c := range cands {
		if c.Key == KeyPhone {
			sawPhone = true
		}
		if c.Key == KeyEmail && c.Value == "hi@acme.com.au" {
			sawEmail = true
		}
	}
	if !sawPhone || !sawEmail {
		t.Fatalf("tel/mailto: phone=%v email=%v", sawPhone, sawEmail)
	}
}
