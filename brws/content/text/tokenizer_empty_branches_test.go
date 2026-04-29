package langextract

import "testing"

func TestTokensAndCharIntervalsEmptyTokenizedBranch(t *testing.T) {
	t.Parallel()

	tokenized := TokenizedText{Text: "", Tokens: nil}
	if _, err := TokensText(tokenized, TokenInterval{StartIndex: 0, EndIndex: 0}); err == nil {
		t.Fatalf("expected invalid interval error for zero-length range")
	}
	if _, err := CharIntervalFromTokens(tokenized, TokenInterval{StartIndex: 0, EndIndex: 0}); err == nil {
		t.Fatalf("expected invalid interval error for zero-length range")
	}
}

func TestFindSentenceRangeNoTokensAndOutOfRange(t *testing.T) {
	t.Parallel()

	empty, err := FindSentenceRange("", nil, 0)
	if err != nil {
		t.Fatalf("expected empty token sentence range success, got %v", err)
	}
	if empty.StartIndex != 0 || empty.EndIndex != 0 {
		t.Fatalf("unexpected empty sentence range: %+v", empty)
	}

	tokenized := TokenizeWithDefault("Alice works.")
	if _, err := FindSentenceRange(tokenized.Text, tokenized.Tokens, -1); err == nil {
		t.Fatalf("expected out-of-range error for negative start")
	}
}
