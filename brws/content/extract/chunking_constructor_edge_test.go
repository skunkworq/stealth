package extract

import "testing"

func TestChunkIteratorConstructorAdditionalBranches(t *testing.T) {
	t.Parallel()

	if _, err := NewChunkIterator("text", 0, DefaultTokenizer, nil); err == nil {
		t.Fatalf("expected max_char_buffer validation error")
	}

	doc := &Document{Text: "Alice works at Acme."}
	iter, err := NewChunkIterator(nil, 16, nil, doc)
	if err != nil {
		t.Fatalf("unexpected constructor error for nil text with document: %v", err)
	}
	chunk, ok, err := iter.Next()
	if err != nil || !ok || chunk == nil {
		t.Fatalf("expected chunk from document-only iterator, err=%v ok=%v", err, ok)
	}

	var tokenizedPtr *TokenizedText
	iter, err = NewChunkIterator(tokenizedPtr, 16, DefaultTokenizer, &Document{Text: "Bob leads platform."})
	if err != nil {
		t.Fatalf("unexpected constructor error for nil tokenized pointer with document: %v", err)
	}
	if _, ok, err := iter.Next(); err != nil || !ok {
		t.Fatalf("expected iterator output, err=%v ok=%v", err, ok)
	}

	emptyTokenized := TokenizedText{Text: "Carol manages infra.", Tokens: nil}
	iter, err = NewChunkIterator(emptyTokenized, 16, DefaultTokenizer, nil)
	if err != nil {
		t.Fatalf("unexpected constructor error for empty tokenized input: %v", err)
	}
	chunk, ok, err = iter.Next()
	if err != nil || !ok || chunk == nil {
		t.Fatalf("expected chunk after tokenizer backfill, err=%v ok=%v", err, ok)
	}
}

func TestTokenIntervalHelpersErrorBranches(t *testing.T) {
	t.Parallel()

	tokenized := TokenizeWithDefault("Alice works.")
	if _, err := CreateTokenInterval(-1, 1); err == nil {
		t.Fatalf("expected negative start error")
	}
	if _, err := CreateTokenInterval(1, 1); err == nil {
		t.Fatalf("expected start>=end error")
	}
	if _, err := GetTokenIntervalText(tokenized, TokenInterval{StartIndex: 1, EndIndex: 1}); err == nil {
		t.Fatalf("expected invalid interval error")
	}
	if _, err := GetCharInterval(tokenized, TokenInterval{StartIndex: 1, EndIndex: 1}); err == nil {
		t.Fatalf("expected invalid char interval error")
	}
}
