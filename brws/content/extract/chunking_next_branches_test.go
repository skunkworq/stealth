package extract

import (
	"strings"
	"testing"
)

func TestChunkIteratorFirstTokenExceedsBufferFlow(t *testing.T) {
	t.Parallel()

	text := "Supercalifragilisticexpialidocious next"
	iter, err := NewChunkIterator(text, 5, DefaultTokenizer, nil)
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}

	ch1, ok, err := iter.Next()
	if err != nil || !ok {
		t.Fatalf("expected first chunk, err=%v ok=%v", err, ok)
	}
	ch1Text, err := ch1.ChunkText()
	if err != nil {
		t.Fatalf("chunk text error: %v", err)
	}
	if !strings.Contains(ch1Text, "Supercalifragilisticexpialidocious") {
		t.Fatalf("expected first long token chunk, got %q", ch1Text)
	}

	ch2, ok, err := iter.Next()
	if err != nil || !ok {
		t.Fatalf("expected second chunk, err=%v ok=%v", err, ok)
	}
	ch2Text, err := ch2.ChunkText()
	if err != nil {
		t.Fatalf("chunk text error: %v", err)
	}
	if !strings.Contains(ch2Text, "next") {
		t.Fatalf("expected remaining token chunk, got %q", ch2Text)
	}
}

func TestChunkIteratorUsesNewlineBoundaryWhenBreaking(t *testing.T) {
	t.Parallel()

	text := "alpha beta\ngamma delta epsilon zeta"
	iter, err := NewChunkIterator(text, 14, DefaultTokenizer, nil)
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}

	ch1, ok, err := iter.Next()
	if err != nil || !ok {
		t.Fatalf("expected first chunk, err=%v ok=%v", err, ok)
	}
	ch1Text, err := ch1.ChunkText()
	if err != nil {
		t.Fatalf("chunk text error: %v", err)
	}
	if strings.TrimSpace(ch1Text) != "alpha beta" {
		t.Fatalf("expected break at newline boundary, got %q", ch1Text)
	}
}
