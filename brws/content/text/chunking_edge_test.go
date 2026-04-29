package langextract

import (
	"strings"
	"testing"
)

func TestTextChunkSanitizedChunkTextCaching(t *testing.T) {
	t.Parallel()

	text := "Alice   works\nat   Acme."
	tokenized := TokenizeWithDefault(text)
	chunk := &TextChunk{
		TokenInterval: TokenInterval{StartIndex: 0, EndIndex: len(tokenized.Tokens)},
		Document: &Document{
			Text:          text,
			TokenizedText: &tokenized,
		},
	}

	got, err := chunk.SanitizedChunkText()
	if err != nil {
		t.Fatalf("sanitized chunk text failed: %v", err)
	}
	if got != "Alice works at Acme." {
		t.Fatalf("unexpected sanitized text: %q", got)
	}

	got2, err := chunk.SanitizedChunkText()
	if err != nil {
		t.Fatalf("second sanitized chunk text call failed: %v", err)
	}
	if got2 != got {
		t.Fatalf("expected cached sanitized text %q, got %q", got, got2)
	}
}

func TestTextChunkSanitizedChunkTextRequiresDocumentText(t *testing.T) {
	t.Parallel()

	chunk := &TextChunk{
		TokenInterval: TokenInterval{StartIndex: 0, EndIndex: 1},
		Document:      &Document{},
	}

	_, err := chunk.SanitizedChunkText()
	if err == nil {
		t.Fatalf("expected error when document text is missing")
	}
	if !strings.Contains(err.Error(), "document_text must be set") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSanitizeTextWhitespaceOnly(t *testing.T) {
	t.Parallel()

	if got := sanitizeText(" \n\t "); got != "" {
		t.Fatalf("expected empty sanitized text, got %q", got)
	}
}

func TestNewChunkIteratorInputValidation(t *testing.T) {
	t.Parallel()

	if _, err := NewChunkIterator(123, 20, DefaultTokenizer, nil); err == nil {
		t.Fatalf("expected unsupported text type error")
	}
	if _, err := NewChunkIterator(nil, 20, DefaultTokenizer, nil); err == nil {
		t.Fatalf("expected missing text/document error")
	}
}
