package extract

import "testing"

func TestSentenceBreakAfterNewlineBranching(t *testing.T) {
	t.Parallel()

	lowerText := "alpha\nbeta"
	lower := TokenizeWithDefault(lowerText)
	if isSentenceBreakAfterNewline(lowerText, lower.Tokens, len(lower.Tokens)-1) {
		t.Fatalf("expected false when next token index is out of range")
	}
	if isSentenceBreakAfterNewline(lowerText, lower.Tokens, 0) {
		t.Fatalf("expected false for lowercase token after newline")
	}

	upperText := "alpha\nBeta"
	upper := TokenizeWithDefault(upperText)
	if !isSentenceBreakAfterNewline(upperText, upper.Tokens, 0) {
		t.Fatalf("expected true for uppercase token after newline")
	}
}
