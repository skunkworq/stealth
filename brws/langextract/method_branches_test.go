package langextract

import "testing"

func TestTextChunkDocumentAccessorsNilDocument(t *testing.T) {
	t.Parallel()

	chunk := &TextChunk{}
	if got := chunk.DocumentID(); got != "" {
		t.Fatalf("expected empty document id for nil document, got %q", got)
	}
	if chunk.DocumentText() != nil {
		t.Fatalf("expected nil document text for nil document")
	}
	if got := chunk.AdditionalContext(); got != "" {
		t.Fatalf("expected empty context for nil document, got %q", got)
	}
	if _, err := chunk.CharInterval(); err == nil {
		t.Fatalf("expected char interval error for nil document text")
	}
}

func TestNewSentenceIteratorOutOfRangeError(t *testing.T) {
	t.Parallel()

	tokenized := TokenizeWithDefault("Alice works at Acme.")
	if _, err := NewSentenceIterator(tokenized, len(tokenized.Tokens)+1); err == nil {
		t.Fatalf("expected out-of-range sentence iterator error")
	}
}
