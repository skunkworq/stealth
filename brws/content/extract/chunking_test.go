package extract

import "testing"

func TestSentenceIteratorBasic(t *testing.T) {
	t.Parallel()

	text := "This is a sentence. This is another sentence.\nMr. Bond asks why?"
	tokenized := TokenizeWithDefault(text)

	iter, err := NewSentenceIterator(tokenized, 0)
	if err != nil {
		t.Fatalf("failed to create sentence iterator: %v", err)
	}

	first, ok, err := iter.Next()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("expected first sentence")
	}
	firstText, err := GetTokenIntervalText(tokenized, first)
	if err != nil {
		t.Fatalf("failed to extract first sentence text: %v", err)
	}
	if firstText != "This is a sentence." {
		t.Fatalf("unexpected first sentence: %q", firstText)
	}
}

func TestChunkIteratorBreaksWithoutEmptyIntervals(t *testing.T) {
	t.Parallel()

	text := "First sentence.\nSecond sentence that is longer.\nThird sentence."
	tokenized := TokenizeWithDefault(text)
	iter, err := NewChunkIterator(tokenized, 20, DefaultTokenizer, nil)
	if err != nil {
		t.Fatalf("failed to create chunk iterator: %v", err)
	}

	var chunks []*TextChunk
	for {
		chunk, ok, err := iter.Next()
		if err != nil {
			t.Fatalf("chunk iteration failed: %v", err)
		}
		if !ok {
			break
		}
		chunks = append(chunks, chunk)
		if chunk.TokenInterval.StartIndex >= chunk.TokenInterval.EndIndex {
			t.Fatalf("chunk has empty interval: %+v", chunk.TokenInterval)
		}
	}
	if len(chunks) == 0 {
		t.Fatalf("expected at least one chunk")
	}
}

func TestChunkIteratorMultiSentenceChunk(t *testing.T) {
	t.Parallel()

	text := "Roses are red. Violets are blue. Flowers are nice."
	tokenized := TokenizeWithDefault(text)
	iter, err := NewChunkIterator(tokenized, 50, DefaultTokenizer, nil)
	if err != nil {
		t.Fatalf("failed to create chunk iterator: %v", err)
	}

	chunk, ok, err := iter.Next()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("expected first chunk")
	}
	chunkText, err := chunk.ChunkText()
	if err != nil {
		t.Fatalf("failed to get chunk text: %v", err)
	}
	if chunkText != "Roses are red. Violets are blue. Flowers are nice." {
		t.Fatalf("unexpected chunk text: %q", chunkText)
	}
}
