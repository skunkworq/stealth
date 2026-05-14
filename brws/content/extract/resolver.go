package extract

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

const (
	// DefaultIndexSuffix is used for optional index-based extraction ordering.
	DefaultIndexSuffix = "_index"
)

const defaultFuzzyAlignmentThreshold = 0.75

// AlignmentParamKeys identifies resolver alignment parameters.
var AlignmentParamKeys = map[string]struct{}{
	"enable_fuzzy_alignment":    {},
	"fuzzy_alignment_threshold": {},
	"accept_match_lesser":       {},
	"suppress_parse_errors":     {},
}

// AlignOptions configures text alignment behavior.
type AlignOptions struct {
	EnableFuzzyAlignment    bool
	FuzzyAlignmentThreshold float64
	AcceptMatchLesser       bool
	Tokenizer               Tokenizer
}

// DefaultAlignOptions returns default alignment options.
func DefaultAlignOptions() AlignOptions {
	return AlignOptions{
		EnableFuzzyAlignment:    true,
		FuzzyAlignmentThreshold: defaultFuzzyAlignmentThreshold,
		AcceptMatchLesser:       true,
		Tokenizer:               DefaultTokenizer,
	}
}

// Resolver parses model output and aligns extractions to source text.
type Resolver struct {
	FormatHandler         *FormatHandler
	ExtractionIndexSuffix string
	Strict                bool
}

// NewResolver builds a resolver with defaults.
func NewResolver(handler *FormatHandler) *Resolver {
	if handler == nil {
		handler = NewFormatHandler()
	}
	return &Resolver{
		FormatHandler:         handler,
		ExtractionIndexSuffix: "",
	}
}

// Resolve parses model output and returns ordered extractions.
func (r *Resolver) Resolve(inputText string, suppressParseErrors bool) ([]Extraction, error) {
	if strings.TrimSpace(inputText) == "" {
		return nil, &ResolverParsingError{newErr("resolve", "input string must be a non-empty string")}
	}
	if r == nil {
		r = NewResolver(nil)
	}

	extractionData, err := r.FormatHandler.ParseOutputOrdered(inputText, r.Strict)
	if err != nil {
		if suppressParseErrors {
			return []Extraction{}, nil
		}
		return nil, &ResolverParsingError{newErr("resolve", err.Error())}
	}

	processed, err := r.extractOrderedExtractionsOrdered(extractionData)
	if err != nil {
		return nil, err
	}
	return processed, nil
}

// StringToExtractionData parses text output to extraction mappings.
func (r *Resolver) StringToExtractionData(inputString string) ([]map[string]any, error) {
	if strings.TrimSpace(inputString) == "" {
		return nil, fmt.Errorf("input string must be a non-empty string")
	}
	if r == nil {
		r = NewResolver(nil)
	}
	return r.FormatHandler.ParseOutput(inputString, r.Strict)
}

// ExtractOrderedExtractions converts parsed maps to extraction entries.
func (r *Resolver) ExtractOrderedExtractions(extractionData []map[string]any) ([]Extraction, error) {
	ordered := make([]orderedObject, 0, len(extractionData))
	for _, group := range extractionData {
		ordered = append(ordered, orderedObjectFromMap(group))
	}
	return r.extractOrderedExtractionsOrdered(ordered)
}

func (r *Resolver) extractOrderedExtractionsOrdered(extractionData []orderedObject) ([]Extraction, error) {
	if r == nil {
		r = NewResolver(nil)
	}

	type indexedExtraction struct {
		Extraction
		seq int
	}

	processed := make([]indexedExtraction, 0)
	seq := 0
	indexSuffix := r.ExtractionIndexSuffix
	attributesSuffix := r.FormatHandler.AttributeSuffix
	nextIndex := 0

	for groupIndex, group := range extractionData {
		for _, pair := range group.Pairs {
			extractionClass := pair.Key
			extractionValue := pair.Value

			if indexSuffix != "" && strings.HasSuffix(extractionClass, indexSuffix) {
				if _, ok := asInt(extractionValue); !ok {
					return nil, fmt.Errorf("index must be an integer")
				}
				continue
			}

			if attributesSuffix != "" && strings.HasSuffix(extractionClass, attributesSuffix) {
				if extractionValue != nil {
					switch extractionValue.(type) {
					case map[string]any, orderedObject:
						// valid attribute mapping shapes
					default:
						return nil, fmt.Errorf("extraction value must be a dict or nil for attributes")
					}
				}
				continue
			}

			text, ok := extractionValueToString(extractionValue)
			if !ok {
				return nil, fmt.Errorf("extraction text must be a string, integer, or float")
			}

			index := 0
			if indexSuffix != "" {
				indexKey := extractionClass + indexSuffix
				rawIndex, ok := group.get(indexKey)
				if !ok {
					continue
				}
				intIndex, ok := asInt(rawIndex)
				if !ok {
					return nil, fmt.Errorf("index must be an integer")
				}
				index = intIndex
			} else {
				nextIndex++
				index = nextIndex
			}

			var attributes map[string]any
			if attributesSuffix != "" {
				attributesKey := extractionClass + attributesSuffix
				if rawAttributes, ok := group.get(attributesKey); ok && rawAttributes != nil {
					if cast, ok := rawAttributes.(map[string]any); ok {
						attributes = cast
					} else if cast, ok := rawAttributes.(orderedObject); ok {
						attributes = cast.asMap()
					}
				}
			}

			processed = append(processed, indexedExtraction{
				Extraction: Extraction{
					ExtractionClass: extractionClass,
					ExtractionText:  text,
					ExtractionIndex: index,
					GroupIndex:      groupIndex,
					Attributes:      attributes,
				},
				seq: seq,
			})
			seq++
		}
	}

	sort.SliceStable(processed, func(i, j int) bool {
		if processed[i].ExtractionIndex != processed[j].ExtractionIndex {
			return processed[i].ExtractionIndex < processed[j].ExtractionIndex
		}
		if processed[i].GroupIndex != processed[j].GroupIndex {
			return processed[i].GroupIndex < processed[j].GroupIndex
		}
		return processed[i].seq < processed[j].seq
	})

	out := make([]Extraction, 0, len(processed))
	for _, p := range processed {
		out = append(out, p.Extraction)
	}
	return out, nil
}

func extractionValueToString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case int:
		return fmt.Sprintf("%d", t), true
	case int64:
		return fmt.Sprintf("%d", t), true
	case float64:
		if math.Trunc(t) == t {
			return fmt.Sprintf("%.0f", t), true
		}
		return fmt.Sprintf("%v", t), true
	case float32:
		ft := float64(t)
		if math.Trunc(ft) == ft {
			return fmt.Sprintf("%.0f", ft), true
		}
		return fmt.Sprintf("%v", t), true
	default:
		return "", false
	}
}

func asInt(v any) (int, bool) {
	switch t := v.(type) {
	case int:
		return t, true
	case int32:
		return int(t), true
	case int64:
		return int(t), true
	case float64:
		if math.Trunc(t) != t {
			return 0, false
		}
		return int(t), true
	default:
		return 0, false
	}
}

// Align aligns extractions against source text.
func (r *Resolver) Align(extractions []Extraction, sourceText string, tokenOffset, charOffset int, options AlignOptions) []Extraction {
	if len(extractions) == 0 {
		return nil
	}
	if strings.TrimSpace(sourceText) == "" {
		return extractions
	}

	if options.Tokenizer == nil {
		options.Tokenizer = DefaultTokenizer
	}
	if options.FuzzyAlignmentThreshold <= 0 {
		options.FuzzyAlignmentThreshold = defaultFuzzyAlignmentThreshold
	}

	tokenized := options.Tokenizer.Tokenize(sourceText)
	sourceTokens := tokenizeWithLowercase(sourceText, options.Tokenizer)
	cursor := 0

	for i := range extractions {
		ex := &extractions[i]
		exTokens := tokenizeWithLowercase(ex.ExtractionText, options.Tokenizer)
		if len(exTokens) == 0 {
			continue
		}

		if start, end, ok := findExactMatch(sourceTokens, exTokens, cursor); ok {
			setAlignedIntervals(ex, &tokenized, start, end, tokenOffset, charOffset, AlignmentExact)
			cursor = end
			continue
		}

		if options.AcceptMatchLesser {
			if start, end, matched, ok := findLesserMatch(sourceTokens, exTokens, cursor); ok && matched > 0 {
				setAlignedIntervals(ex, &tokenized, start, end, tokenOffset, charOffset, AlignmentLesser)
				cursor = end
				continue
			}
		}

		if options.EnableFuzzyAlignment {
			if start, end, ok := fuzzyAlign(sourceTokens, exTokens, cursor, options.FuzzyAlignmentThreshold); ok {
				setAlignedIntervals(ex, &tokenized, start, end, tokenOffset, charOffset, AlignmentFuzzy)
				cursor = end
				continue
			}
		}

		ex.TokenInterval = nil
		ex.CharInterval = nil
		ex.Alignment = ""
	}

	return extractions
}

func setAlignedIntervals(
	extraction *Extraction,
	tokenized *TokenizedText,
	start int,
	end int,
	tokenOffset int,
	charOffset int,
	alignment AlignmentStatus,
) {
	if start < 0 || end <= start || end > len(tokenized.Tokens) {
		extraction.TokenInterval = nil
		extraction.CharInterval = nil
		extraction.Alignment = ""
		return
	}
	extraction.TokenInterval = &TokenInterval{
		StartIndex: start + tokenOffset,
		EndIndex:   end + tokenOffset,
	}
	startToken := tokenized.Tokens[start]
	endToken := tokenized.Tokens[end-1]
	extraction.CharInterval = &CharInterval{
		StartPos: charOffset + startToken.StartPos,
		EndPos:   charOffset + endToken.EndPos,
	}
	extraction.Alignment = alignment
}

func findExactMatch(sourceTokens, extractionTokens []string, cursor int) (int, int, bool) {
	if len(extractionTokens) == 0 || len(sourceTokens) < len(extractionTokens) || cursor >= len(sourceTokens) {
		return 0, 0, false
	}
	limit := len(sourceTokens) - len(extractionTokens)
	for i := cursor; i <= limit; i++ {
		match := true
		for j := range extractionTokens {
			if sourceTokens[i+j] != extractionTokens[j] {
				match = false
				break
			}
		}
		if match {
			return i, i + len(extractionTokens), true
		}
	}
	return 0, 0, false
}

func findLesserMatch(sourceTokens, extractionTokens []string, cursor int) (int, int, int, bool) {
	bestStart := -1
	bestLen := 0

	for i := cursor; i < len(sourceTokens); i++ {
		matched := 0
		for j := 0; j < len(extractionTokens) && i+j < len(sourceTokens); j++ {
			if sourceTokens[i+j] != extractionTokens[j] {
				break
			}
			matched++
		}
		if matched > bestLen {
			bestLen = matched
			bestStart = i
		}
	}

	if bestStart == -1 || bestLen == 0 {
		return 0, 0, 0, false
	}
	return bestStart, bestStart + bestLen, bestLen, true
}

func fuzzyAlign(sourceTokens, extractionTokens []string, cursor int, threshold float64) (int, int, bool) {
	if len(extractionTokens) == 0 || cursor >= len(sourceTokens) {
		return 0, 0, false
	}
	minOverlap := int(math.Ceil(float64(len(extractionTokens)) * threshold))
	bestRatio := 0.0
	bestStart, bestEnd := -1, -1

	for start := cursor; start < len(sourceTokens); start++ {
		for size := len(extractionTokens); start+size <= len(sourceTokens); size++ {
			window := sourceTokens[start : start+size]
			if overlapTokenCount(window, extractionTokens) < minOverlap {
				continue
			}
			ratio := float64(lcsLength(window, extractionTokens)) / float64(len(extractionTokens))
			if ratio > bestRatio {
				bestRatio = ratio
				bestStart = start
				bestEnd = start + size
			}
		}
	}

	if bestStart >= 0 && bestRatio >= threshold {
		return bestStart, bestEnd, true
	}
	return 0, 0, false
}

func overlapTokenCount(a, b []string) int {
	counts := map[string]int{}
	for _, tok := range a {
		counts[tok]++
	}
	overlap := 0
	for _, tok := range b {
		if counts[tok] > 0 {
			overlap++
			counts[tok]--
		}
	}
	return overlap
}

func lcsLength(a, b []string) int {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	dp := make([]int, len(b)+1)
	for i := 1; i <= len(a); i++ {
		prev := 0
		for j := 1; j <= len(b); j++ {
			tmp := dp[j]
			if a[i-1] == b[j-1] {
				dp[j] = prev + 1
			} else if dp[j-1] > dp[j] {
				dp[j] = dp[j-1]
			}
			prev = tmp
		}
	}
	return dp[len(b)]
}

func tokenizeWithLowercase(text string, tokenizerInst Tokenizer) []string {
	if tokenizerInst == nil {
		tokenizerInst = DefaultTokenizer
	}
	tokenized := tokenizerInst.Tokenize(text)
	out := make([]string, 0, len(tokenized.Tokens))
	for _, token := range tokenized.Tokens {
		out = append(out, strings.ToLower(tokenized.Text[token.StartPos:token.EndPos]))
	}
	return out
}
