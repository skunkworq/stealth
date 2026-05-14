package extract

import "testing"

func TestTokenizerGroupsRepeatedSymbolsButSplitsMixed(t *testing.T) {
	t.Parallel()

	tokenized := TokenizeWithDefault("!!!@# ?! __")
	got := make([]string, 0, len(tokenized.Tokens))
	for _, tok := range tokenized.Tokens {
		got = append(got, tokenized.Text[tok.StartPos:tok.EndPos])
	}

	expected := []string{"!!!", "@", "#", "?", "!", "__"}
	if len(got) != len(expected) {
		t.Fatalf("unexpected token length: got %d expected %d (%v)", len(got), len(expected), got)
	}
	for i := range expected {
		if got[i] != expected[i] {
			t.Fatalf("unexpected token[%d]: got %q expected %q", i, got[i], expected[i])
		}
	}
}

func TestTokenizerFirstTokenAfterNewline(t *testing.T) {
	t.Parallel()

	text := "Line1\nLine2\nLine3"
	tokenized := TokenizeWithDefault(text)
	if len(tokenized.Tokens) < 5 {
		t.Fatalf("unexpected token length: %d", len(tokenized.Tokens))
	}
	if !tokenized.Tokens[2].FirstTokenAfterNewline {
		t.Fatalf("expected token 2 to be first after newline")
	}
	if !tokenized.Tokens[4].FirstTokenAfterNewline {
		t.Fatalf("expected token 4 to be first after newline")
	}
}
