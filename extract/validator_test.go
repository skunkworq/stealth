package extract

import "testing"

func TestValidatorIdentifierDigitNormalised(t *testing.T) {
	doc := &SourceDocument{Ref: "r", Text: "Call us. ABN 50 629 080 842 today."}
	v := NewValidator()
	f, ok := v.Validate(doc, Candidate{Key: KeyABN, Value: "50629080842", Method: MethodRegex})
	if !ok {
		t.Fatal("spaced ABN should validate against digit-normalised text")
	}
	if f.Span.Start < 0 || f.Span.End <= f.Span.Start {
		t.Fatalf("bad span %+v", f.Span)
	}
}

func TestValidatorRejectsAbsent(t *testing.T) {
	doc := &SourceDocument{Ref: "r", Text: "ABN 11 222 333 444"}
	v := NewValidator()
	if _, ok := v.Validate(doc, Candidate{Key: KeyABN, Value: "50629080842", Method: MethodLLMLangextract}); ok {
		t.Fatal("absent ABN must be rejected (zero-hallucination)")
	}
}

func TestValidatorEmailCaseInsensitive(t *testing.T) {
	doc := &SourceDocument{Ref: "r", Text: "Email: Info@Acme.COM.au"}
	v := NewValidator()
	if _, ok := v.Validate(doc, Candidate{Key: KeyEmail, Value: "info@acme.com.au"}); !ok {
		t.Fatal("email should match case-insensitively")
	}
}

func TestValidatorURLSchemeInsensitive(t *testing.T) {
	doc := &SourceDocument{Ref: "r", Text: "visit acme.com.au/contact for details"}
	v := NewValidator()
	if _, ok := v.Validate(doc, Candidate{Key: KeyWebsite, Value: "https://acme.com.au/contact"}); !ok {
		t.Fatal("url should match ignoring scheme")
	}
}

func TestValidatorFreeTextWhitespaceCollapsed(t *testing.T) {
	doc := &SourceDocument{Ref: "r", Text: "285A   Richmond Rd,\nWEST RICHMOND SA 5033"}
	v := NewValidator()
	if _, ok := v.Validate(doc, Candidate{Key: KeyAddress, Value: "285A Richmond Rd, West Richmond SA 5033"}); !ok {
		t.Fatal("address should match modulo whitespace/casing")
	}
}
