package extract

import (
	"fmt"
	"strings"
)

// TextChunk stores chunk interval and source document metadata.
type TextChunk struct {
	TokenInterval TokenInterval
	Document      *Document

	chunkText          *string
	sanitizedChunkText *string
	charInterval       *CharInterval
}

// DocumentID returns the chunk's source document ID.
func (c *TextChunk) DocumentID() string {
	if c.Document == nil {
		return ""
	}
	return c.Document.id()
}

// DocumentText returns the tokenized source text for the chunk.
func (c *TextChunk) DocumentText() *TokenizedText {
	if c.Document == nil {
		return nil
	}
	return c.Document.TokenizedText
}

// AdditionalContext returns document-level context configured for prompting.
func (c *TextChunk) AdditionalContext() string {
	if c.Document == nil {
		return ""
	}
	return c.Document.AdditionalContext
}

// ChunkText returns the source substring represented by the chunk token interval.
func (c *TextChunk) ChunkText() (string, error) {
	if c.DocumentText() == nil {
		return "", fmt.Errorf("document_text must be set to access chunk_text")
	}
	if c.chunkText == nil {
		txt, err := GetTokenIntervalText(*c.DocumentText(), c.TokenInterval)
		if err != nil {
			return "", err
		}
		c.chunkText = &txt
	}
	return *c.chunkText, nil
}

// SanitizedChunkText returns a whitespace-normalized chunk text variant.
func (c *TextChunk) SanitizedChunkText() (string, error) {
	if c.sanitizedChunkText != nil {
		return *c.sanitizedChunkText, nil
	}
	txt, err := c.ChunkText()
	if err != nil {
		return "", err
	}
	sanitized := sanitizeText(txt)
	if sanitized == "" {
		return "", fmt.Errorf("sanitized text is empty")
	}
	c.sanitizedChunkText = &sanitized
	return sanitized, nil
}

// CharInterval maps the chunk token interval to source character offsets.
func (c *TextChunk) CharInterval() (CharInterval, error) {
	if c.charInterval != nil {
		return *c.charInterval, nil
	}
	if c.DocumentText() == nil {
		return CharInterval{}, fmt.Errorf("document_text must be set to compute char_interval")
	}
	ci, err := GetCharInterval(*c.DocumentText(), c.TokenInterval)
	if err != nil {
		return CharInterval{}, err
	}
	c.charInterval = &ci
	return ci, nil
}

func sanitizeText(text string) string {
	out := strings.Join(strings.Fields(strings.TrimSpace(text)), " ")
	return out
}

// CreateTokenInterval validates and returns a token interval.
func CreateTokenInterval(startIndex, endIndex int) (TokenInterval, error) {
	if startIndex < 0 {
		return TokenInterval{}, fmt.Errorf("start index %d must be positive", startIndex)
	}
	if startIndex >= endIndex {
		return TokenInterval{}, fmt.Errorf("start index %d must be < end index %d", startIndex, endIndex)
	}
	return TokenInterval{StartIndex: startIndex, EndIndex: endIndex}, nil
}

// GetTokenIntervalText returns source substring for token interval.
func GetTokenIntervalText(tokenizedText TokenizedText, tokenInterval TokenInterval) (string, error) {
	if tokenInterval.StartIndex >= tokenInterval.EndIndex {
		return "", fmt.Errorf("start index %d must be < end index %d", tokenInterval.StartIndex, tokenInterval.EndIndex)
	}
	return TokensText(tokenizedText, tokenInterval)
}

// GetCharInterval maps token interval to character interval.
func GetCharInterval(tokenizedText TokenizedText, tokenInterval TokenInterval) (CharInterval, error) {
	if tokenInterval.StartIndex >= tokenInterval.EndIndex {
		return CharInterval{}, fmt.Errorf("start index %d must be < end index %d", tokenInterval.StartIndex, tokenInterval.EndIndex)
	}
	return CharIntervalFromTokens(tokenizedText, tokenInterval)
}

// SentenceIterator iterates through sentence token intervals.
type SentenceIterator struct {
	tokenizedText TokenizedText
	tokenLen      int
	currTokenPos  int
}

// NewSentenceIterator creates a sentence iterator at a specific token position.
func NewSentenceIterator(tokenizedText TokenizedText, currTokenPos int) (*SentenceIterator, error) {
	if currTokenPos < 0 {
		return nil, fmt.Errorf("current token position %d can not be negative", currTokenPos)
	}
	if currTokenPos > len(tokenizedText.Tokens) {
		return nil, fmt.Errorf("current token position %d is past the length of the document %d", currTokenPos, len(tokenizedText.Tokens))
	}
	return &SentenceIterator{
		tokenizedText: tokenizedText,
		tokenLen:      len(tokenizedText.Tokens),
		currTokenPos:  currTokenPos,
	}, nil
}

// Next returns the next sentence token interval.
//
// The boolean return is false when iteration is complete.
func (s *SentenceIterator) Next() (TokenInterval, bool, error) {
	if s.currTokenPos == s.tokenLen {
		return TokenInterval{}, false, nil
	}
	sentenceRange, err := FindSentenceRange(s.tokenizedText.Text, s.tokenizedText.Tokens, s.currTokenPos)
	if err != nil {
		return TokenInterval{}, false, err
	}
	sentenceRange, err = CreateTokenInterval(s.currTokenPos, sentenceRange.EndIndex)
	if err != nil {
		return TokenInterval{}, false, err
	}
	s.currTokenPos = sentenceRange.EndIndex
	return sentenceRange, true, nil
}

// ChunkIterator iterates through chunk intervals respecting max_char_buffer.
type ChunkIterator struct {
	tokenizedText  TokenizedText
	maxCharBuffer  int
	sentenceIter   *SentenceIterator
	brokenSentence bool
	document       *Document
	tokenizerImpl  Tokenizer
}

// NewChunkIterator creates a chunk iterator over text/tokenized text/document input.
func NewChunkIterator(
	text any,
	maxCharBuffer int,
	tokenizerImpl Tokenizer,
	document *Document,
) (*ChunkIterator, error) {
	if tokenizerImpl == nil {
		tokenizerImpl = DefaultTokenizer
	}
	if maxCharBuffer <= 0 {
		return nil, fmt.Errorf("max_char_buffer must be > 0")
	}

	var tokenized TokenizedText
	switch t := text.(type) {
	case nil:
		if document == nil {
			return nil, fmt.Errorf("either text or document must be provided")
		}
		tokenized = tokenizerImpl.Tokenize(document.Text)
	case string:
		tokenized = tokenizerImpl.Tokenize(t)
	case TokenizedText:
		tokenized = t
		if len(tokenized.Tokens) == 0 {
			tokenized = tokenizerImpl.Tokenize(tokenized.Text)
		}
	case *TokenizedText:
		if t == nil {
			if document == nil {
				return nil, fmt.Errorf("either text or document must be provided")
			}
			tokenized = tokenizerImpl.Tokenize(document.Text)
		} else {
			tokenized = *t
			if len(tokenized.Tokens) == 0 {
				tokenized = tokenizerImpl.Tokenize(tokenized.Text)
			}
		}
	default:
		return nil, fmt.Errorf("unsupported chunk text input type %T", text)
	}

	if document == nil {
		document = &Document{Text: tokenized.Text}
	}
	document.TokenizedText = &tokenized

	si, err := NewSentenceIterator(tokenized, 0)
	if err != nil {
		return nil, err
	}

	return &ChunkIterator{
		tokenizedText: tokenized,
		maxCharBuffer: maxCharBuffer,
		sentenceIter:  si,
		document:      document,
		tokenizerImpl: tokenizerImpl,
	}, nil
}

func (c *ChunkIterator) tokensExceedBuffer(tokenInterval TokenInterval) (bool, error) {
	charInterval, err := GetCharInterval(c.tokenizedText, tokenInterval)
	if err != nil {
		return false, err
	}
	return (charInterval.EndPos - charInterval.StartPos) > c.maxCharBuffer, nil
}

// Next returns the next chunk that fits within maxCharBuffer constraints.
//
// The boolean return is false when iteration is complete.
func (c *ChunkIterator) Next() (*TextChunk, bool, error) {
	sentence, ok, err := c.sentenceIter.Next()
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, nil
	}

	currChunk, err := CreateTokenInterval(sentence.StartIndex, sentence.StartIndex+1)
	if err != nil {
		return nil, false, err
	}
	exceeds, err := c.tokensExceedBuffer(currChunk)
	if err != nil {
		return nil, false, err
	}
	if exceeds {
		c.sentenceIter, err = NewSentenceIterator(c.tokenizedText, sentence.StartIndex+1)
		if err != nil {
			return nil, false, err
		}
		c.brokenSentence = currChunk.EndIndex < sentence.EndIndex
		return &TextChunk{TokenInterval: currChunk, Document: c.document}, true, nil
	}

	startOfNewLine := -1
	for tokenIndex := currChunk.StartIndex; tokenIndex < sentence.EndIndex; tokenIndex++ {
		if c.tokenizedText.Tokens[tokenIndex].FirstTokenAfterNewline {
			startOfNewLine = tokenIndex
		}

		testChunk, err := CreateTokenInterval(currChunk.StartIndex, tokenIndex+1)
		if err != nil {
			return nil, false, err
		}
		exceeds, err := c.tokensExceedBuffer(testChunk)
		if err != nil {
			return nil, false, err
		}
		if exceeds {
			if startOfNewLine > 0 && startOfNewLine > currChunk.StartIndex {
				currChunk, err = CreateTokenInterval(currChunk.StartIndex, startOfNewLine)
				if err != nil {
					return nil, false, err
				}
			}
			c.sentenceIter, err = NewSentenceIterator(c.tokenizedText, currChunk.EndIndex)
			if err != nil {
				return nil, false, err
			}
			c.brokenSentence = true
			return &TextChunk{TokenInterval: currChunk, Document: c.document}, true, nil
		}
		currChunk = testChunk
	}

	if c.brokenSentence {
		c.brokenSentence = false
	} else {
		for {
			nextSentence, more, err := c.sentenceIter.Next()
			if err != nil {
				return nil, false, err
			}
			if !more {
				break
			}
			testChunk, err := CreateTokenInterval(currChunk.StartIndex, nextSentence.EndIndex)
			if err != nil {
				return nil, false, err
			}
			exceeds, err := c.tokensExceedBuffer(testChunk)
			if err != nil {
				return nil, false, err
			}
			if exceeds {
				c.sentenceIter, err = NewSentenceIterator(c.tokenizedText, currChunk.EndIndex)
				if err != nil {
					return nil, false, err
				}
				return &TextChunk{TokenInterval: currChunk, Document: c.document}, true, nil
			}
			currChunk = testChunk
		}
	}

	return &TextChunk{TokenInterval: currChunk, Document: c.document}, true, nil
}

// MakeBatchesOfTextChunk batches chunks for inference.
func MakeBatchesOfTextChunk(chunkIter *ChunkIterator, batchLength int) ([][]*TextChunk, error) {
	if batchLength <= 0 {
		batchLength = 1
	}
	var batches [][]*TextChunk
	curr := make([]*TextChunk, 0, batchLength)

	for {
		chunk, ok, err := chunkIter.Next()
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		curr = append(curr, chunk)
		if len(curr) == batchLength {
			batches = append(batches, curr)
			curr = make([]*TextChunk, 0, batchLength)
		}
	}
	if len(curr) > 0 {
		batches = append(batches, curr)
	}
	return batches, nil
}
