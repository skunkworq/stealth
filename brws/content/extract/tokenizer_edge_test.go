package extract

import "testing"

func TestUnicodeTokenizerDelegatesToDefault(t *testing.T) {
	t.Parallel()

	text := "Hello 世界!"
	defaultTokens := DefaultTokenizer.Tokenize(text)
	unicodeTokens := (&UnicodeTokenizer{}).Tokenize(text)

	if len(unicodeTokens.Tokens) != len(defaultTokens.Tokens) {
		t.Fatalf("expected unicode tokenizer to mirror default token count")
	}
}

func TestNormalizeTokenPluralHandling(t *testing.T) {
	t.Parallel()

	if got := NormalizeToken("Cats"); got != "cat" {
		t.Fatalf("expected singular stem for cats, got %q", got)
	}
	if got := NormalizeToken("boss"); got != "boss" {
		t.Fatalf("expected words ending in ss to remain unchanged, got %q", got)
	}
}

func TestTokenizeAndNormalizeDefaults(t *testing.T) {
	t.Parallel()

	got := tokenizeAndNormalize("Cats run fast.", nil)
	if len(got) == 0 {
		t.Fatalf("expected normalized tokens")
	}
	if got[0] != "cat" {
		t.Fatalf("expected first normalized token to be cat, got %q", got[0])
	}
}

func TestClosingPunctuationAndRuneDecodeHelpers(t *testing.T) {
	t.Parallel()

	if !isClosingPunctuation(")") {
		t.Fatalf("expected closing punctuation for ')'")
	}
	if isClosingPunctuation("x") {
		t.Fatalf("did not expect closing punctuation for 'x'")
	}

	r, _ := utf8DecodeRune("abc")
	if r != 'a' {
		t.Fatalf("expected first rune 'a', got %q", r)
	}
	r, _ = utf8DecodeRune("")
	if r != 0 {
		t.Fatalf("expected zero rune for empty string, got %q", r)
	}
}
