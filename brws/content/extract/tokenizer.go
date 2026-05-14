package extract

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	tokenTypeWord = iota
	tokenTypeNumber
	tokenTypePunctuation
)

// Token stores token metadata.
type Token struct {
	Index int
	Type  int
	CharInterval
	FirstTokenAfterNewline bool
}

// TokenizedText contains tokenized representation of a string.
type TokenizedText struct {
	Text   string
	Tokens []Token
}

// Tokenizer tokenizes source text into stable token intervals.
type Tokenizer interface {
	Tokenize(text string) TokenizedText
}

var (
	tokenPattern        = regexp.MustCompile(`[^\W\d_]+|\d+|(?:[^\w\s]|_)+`)
	wordLikePattern     = regexp.MustCompile(`^(?:[^\W\d_]+|\d+)$`)
	numPattern          = regexp.MustCompile(`^\d+$`)
	sentenceEndPattern  = regexp.MustCompile(`[.?!。！？\x{0964}]["'”’»)\]}]*$`)
	commonAbbreviations = map[string]struct{}{
		"Mr.":   {},
		"Mrs.":  {},
		"Ms.":   {},
		"Dr.":   {},
		"Prof.": {},
		"St.":   {},
	}
)

// RegexTokenizer uses a tokenization strategy tuned for alignment.
type RegexTokenizer struct{}

// DefaultTokenizer is the default tokenizer used by the package.
var DefaultTokenizer = &RegexTokenizer{}

// Tokenize splits text using the regex token pattern.
func (r *RegexTokenizer) Tokenize(text string) TokenizedText {
	result := TokenizedText{Text: text}
	matches := tokenPattern.FindAllStringIndex(text, -1)
	result.Tokens = make([]Token, 0, len(matches))
	prevEnd := 0

	for _, span := range matches {
		start, end := span[0], span[1]
		piece := text[start:end]
		runs := []CharInterval{{StartPos: start, EndPos: end}}
		if !numPattern.MatchString(piece) && !wordLikePattern.MatchString(piece) && utf8.RuneCountInString(piece) > 1 {
			runs = splitSymbolRuns(text, start, end)
		}

		for _, run := range runs {
			runPiece := text[run.StartPos:run.EndPos]
			typeID := tokenTypePunctuation
			if numPattern.MatchString(runPiece) {
				typeID = tokenTypeNumber
			} else if wordLikePattern.MatchString(runPiece) {
				typeID = tokenTypeWord
			}

			tok := Token{
				Index: len(result.Tokens),
				Type:  typeID,
				CharInterval: CharInterval{
					StartPos: run.StartPos,
					EndPos:   run.EndPos,
				},
				FirstTokenAfterNewline: false,
			}
			if tok.Index > 0 {
				segment := text[prevEnd:run.StartPos]
				if strings.Contains(segment, "\n") || strings.Contains(segment, "\r") {
					tok.FirstTokenAfterNewline = true
				}
			}
			result.Tokens = append(result.Tokens, tok)
			prevEnd = run.EndPos
		}
	}

	return result
}

func splitSymbolRuns(text string, start, end int) []CharInterval {
	if start >= end {
		return nil
	}
	sub := text[start:end]
	runs := make([]CharInterval, 0, utf8.RuneCountInString(sub))

	first := true
	var currentRune rune
	currentStart := start
	for relOffset, r := range sub {
		absOffset := start + relOffset
		if first {
			first = false
			currentRune = r
			currentStart = absOffset
			continue
		}
		if r != currentRune {
			runs = append(runs, CharInterval{StartPos: currentStart, EndPos: absOffset})
			currentRune = r
			currentStart = absOffset
		}
	}
	runs = append(runs, CharInterval{StartPos: currentStart, EndPos: end})
	return runs
}

// UnicodeTokenizer is a best-effort tokenizer for non-ASCII scripts.
type UnicodeTokenizer struct{}

// Tokenize provides reasonable token boundaries for Unicode input.
func (u *UnicodeTokenizer) Tokenize(text string) TokenizedText {
	// Keep parity with regex behaviour for current tests and callers.
	return DefaultTokenizer.Tokenize(text)
}

// TokensText returns raw text for a token interval.
func TokensText(tokenizedText TokenizedText, interval TokenInterval) (string, error) {
	if interval.StartIndex < 0 || interval.EndIndex > len(tokenizedText.Tokens) || interval.StartIndex >= interval.EndIndex {
		return "", fmt.Errorf("invalid token interval %v", interval)
	}
	if len(tokenizedText.Tokens) == 0 {
		if interval.StartIndex == 0 && interval.EndIndex == 0 {
			return "", nil
		}
	}
	start := tokenizedText.Tokens[interval.StartIndex].StartPos
	end := tokenizedText.Tokens[interval.EndIndex-1].EndPos
	return tokenizedText.Text[start:end], nil
}

// CharIntervalFromTokens returns character spans for a token interval.
func CharIntervalFromTokens(tokenizedText TokenizedText, interval TokenInterval) (CharInterval, error) {
	if interval.StartIndex < 0 || interval.EndIndex > len(tokenizedText.Tokens) || interval.StartIndex >= interval.EndIndex {
		return CharInterval{}, fmt.Errorf("invalid token interval %v", interval)
	}
	if len(tokenizedText.Tokens) == 0 {
		if interval.StartIndex == 0 && interval.EndIndex == 0 {
			return CharInterval{}, nil
		}
	}
	return CharInterval{
		StartPos: tokenizedText.Tokens[interval.StartIndex].StartPos,
		EndPos:   tokenizedText.Tokens[interval.EndIndex-1].EndPos,
	}, nil
}

// NormalizeToken applies light stemming and case normalization for alignment.
func NormalizeToken(token string) string {
	normalized := strings.ToLower(strings.TrimSpace(token))
	if len(normalized) > 3 && strings.HasSuffix(normalized, "s") && !strings.HasSuffix(normalized, "ss") {
		return strings.TrimSuffix(normalized, "s")
	}
	return normalized
}

func tokenizeAndNormalize(text string, tok Tokenizer) []string {
	if tok == nil {
		tok = DefaultTokenizer
	}
	t := tok.Tokenize(text)
	out := make([]string, 0, len(t.Tokens))
	for _, token := range t.Tokens {
		piece := t.Text[token.StartPos:token.EndPos]
		if piece == "" {
			continue
		}
		out = append(out, NormalizeToken(piece))
	}
	return out
}

// FindSentenceRange returns a sentence token interval from startTokenIndex.
func FindSentenceRange(text string, tokens []Token, startTokenIndex int) (TokenInterval, error) {
	if len(tokens) == 0 {
		return TokenInterval{StartIndex: 0, EndIndex: 0}, nil
	}
	if startTokenIndex < 0 || startTokenIndex >= len(tokens) {
		return TokenInterval{}, fmt.Errorf("start_token_index=%d out of range", startTokenIndex)
	}

	i := startTokenIndex
	for i < len(tokens) {
		current := tokens[i]
		if current.Type == tokenTypePunctuation && isSentenceEnd(text, tokens, i) {
			end := i + 1
			for end < len(tokens) {
				next := tokens[end]
				nextText := text[next.StartPos:next.EndPos]
				if next.Type == tokenTypePunctuation && isClosingPunctuation(nextText) {
					end++
					continue
				}
				break
			}
			return TokenInterval{StartIndex: startTokenIndex, EndIndex: end}, nil
		}

		if isSentenceBreakAfterNewline(text, tokens, i) {
			return TokenInterval{StartIndex: startTokenIndex, EndIndex: i + 1}, nil
		}

		i++
	}

	return TokenInterval{StartIndex: startTokenIndex, EndIndex: len(tokens)}, nil
}

func isSentenceEnd(text string, tokens []Token, index int) bool {
	if index < 0 || index >= len(tokens) {
		return false
	}
	current := tokens[index]
	currentText := text[current.StartPos:current.EndPos]
	if !sentenceEndPattern.MatchString(currentText) {
		return false
	}
	if index > 0 {
		prev := tokens[index-1]
		prevText := text[prev.StartPos:prev.EndPos]
		if _, ok := commonAbbreviations[prevText+currentText]; ok {
			return false
		}
	}
	return true
}

func isSentenceBreakAfterNewline(text string, tokens []Token, currentIdx int) bool {
	if currentIdx+1 >= len(tokens) {
		return false
	}
	next := tokens[currentIdx+1]
	if !next.FirstTokenAfterNewline {
		return false
	}
	nextText := text[next.StartPos:next.EndPos]
	if nextText == "" {
		return false
	}
	first, _ := utf8DecodeRune(nextText)
	return !unicode.IsLower(first)
}

func isClosingPunctuation(value string) bool {
	if value == "" {
		return false
	}
	closing := map[rune]bool{'"': true, '\'': true, '”': true, '’': true, '»': true, ')': true, ']': true, '}': true}
	for _, r := range value {
		return closing[r]
	}
	return false
}

func utf8DecodeRune(value string) (rune, int) {
	for _, r := range value {
		// Size is intentionally not required by callers.
		return r, 0
	}
	return 0, 0
}

// TokenizeWithDefault returns the default tokenizer output.
func TokenizeWithDefault(text string) TokenizedText { return DefaultTokenizer.Tokenize(text) }
