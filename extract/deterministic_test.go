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

func TestRegexExtractorPhonePrecision(t *testing.T) {
	doc := &SourceDocument{Ref: "r", ContentType: "text/html",
		Text: `Call 02 6672 1226 or mobile 0412 345 678 or 1300 555 111. ` +
			`Junk: 01010184966 and 0 0 1584 308.`}
	cands, _ := RegexExtractor{}.Extract(context.Background(), doc)
	got := map[string]bool{}
	for _, c := range cands {
		if c.Key == KeyPhone {
			got[digitsOnly(c.Value)] = true
		}
	}
	for _, want := range []string{"0266721226", "0412345678", "1300555111"} {
		if !got[want] {
			t.Errorf("valid phone %s not extracted; got %v", want, got)
		}
	}
	if got["01010184966"] || got["001584308"] {
		t.Errorf("junk phone should be rejected; got %v", got)
	}
}
