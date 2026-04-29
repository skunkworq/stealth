package langextract

import "testing"

func TestTokensTextAndCharIntervalValidation(t *testing.T) {
	t.Parallel()

	tokenized := TokenizeWithDefault("Alice works.")

	if _, err := TokensText(tokenized, TokenInterval{StartIndex: 1, EndIndex: 1}); err == nil {
		t.Fatalf("expected invalid token interval error for zero-length span")
	}
	if _, err := CharIntervalFromTokens(tokenized, TokenInterval{StartIndex: -1, EndIndex: 1}); err == nil {
		t.Fatalf("expected invalid token interval error for negative start")
	}

	text, err := TokensText(tokenized, TokenInterval{StartIndex: 0, EndIndex: 2})
	if err != nil {
		t.Fatalf("unexpected valid token interval error: %v", err)
	}
	if text != "Alice works" {
		t.Fatalf("unexpected token text: %q", text)
	}

	ci, err := CharIntervalFromTokens(tokenized, TokenInterval{StartIndex: 0, EndIndex: 1})
	if err != nil {
		t.Fatalf("unexpected valid char interval error: %v", err)
	}
	if ci.StartPos != 0 || ci.EndPos <= ci.StartPos {
		t.Fatalf("unexpected char interval: %+v", ci)
	}
}
