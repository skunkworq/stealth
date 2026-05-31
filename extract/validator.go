package extract

import (
	"regexp"
	"strings"
)

// Validator is the single authority that gates every candidate. A value that
// is not present (after class normalisation) in the document text is rejected —
// the zero-hallucination guarantee.
type Validator struct{}

func NewValidator() *Validator { return &Validator{} }

var wsRE = regexp.MustCompile(`\s+`)

func collapseWS(s string) string { return strings.TrimSpace(wsRE.ReplaceAllString(s, " ")) }

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Validate confirms cand.Value occurs in doc.Text under the field's class
// normalisation. On success it returns a Field with the matched raw span.
func (v *Validator) Validate(doc *SourceDocument, cand Candidate) (Field, bool) {
	val := strings.TrimSpace(cand.Value)
	if val == "" || doc == nil {
		return Field{}, false
	}
	class := ClassOf(cand.Key)
	start, end, ok := locate(doc.Text, val, class)
	if !ok {
		return Field{}, false
	}
	return Field{
		Key:        cand.Key,
		Class:      class,
		Value:      val,
		SourceRef:  doc.Ref,
		Span:       Span{Start: start, End: end},
		Method:     cand.Method,
		Confidence: cand.Conf,
	}, true
}

// locate finds val in text under the class normalisation and returns the raw
// [start,end) span in the ORIGINAL text, or ok=false.
func locate(text, val string, class FieldClass) (int, int, bool) {
	switch class {
	case ClassIdentifier:
		needle := digitsOnly(val)
		if len(needle) < 4 {
			return 0, 0, false
		}
		return locateDigits(text, needle)
	case ClassEmail:
		return locateFold(text, val)
	case ClassURL:
		return locateFold(text, stripScheme(val))
	default: // FreeText
		return locateCollapsed(text, val)
	}
}

func stripScheme(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	return s
}

// locateFold: case-insensitive substring; returns span in original text.
func locateFold(text, needle string) (int, int, bool) {
	needle = strings.TrimSpace(needle)
	if needle == "" {
		return 0, 0, false
	}
	i := strings.Index(strings.ToLower(text), strings.ToLower(needle))
	if i < 0 {
		return 0, 0, false
	}
	return i, i + len(needle), true
}

// locateCollapsed: whitespace-collapsed, case-insensitive substring. Maps the
// match back to a span in the original text. Span offsets are exact for ASCII
// text (the common case); for multi-byte runes the span is best-effort while
// the presence/absence decision stays correct.
func locateCollapsed(text, needle string) (int, int, bool) {
	nNorm := strings.ToLower(collapseWS(needle))
	if nNorm == "" {
		return 0, 0, false
	}
	var b strings.Builder
	idxMap := make([]int, 0, len(text))
	prevSpace := false
	for i, r := range text {
		if r == ' ' || r == '\n' || r == '\t' || r == '\r' || r == '\v' || r == '\f' {
			if prevSpace {
				continue
			}
			b.WriteByte(' ')
			idxMap = append(idxMap, i)
			prevSpace = true
			continue
		}
		lr := r
		if lr >= 'A' && lr <= 'Z' {
			lr += 'a' - 'A'
		}
		b.WriteRune(lr)
		idxMap = append(idxMap, i)
		prevSpace = false
	}
	hay := strings.ToLower(b.String())
	j := strings.Index(hay, nNorm)
	if j < 0 {
		return 0, 0, false
	}
	if j >= len(idxMap) {
		return 0, 0, false
	}
	start := idxMap[j]
	endCollapsed := j + len(nNorm) - 1
	if endCollapsed >= len(idxMap) {
		endCollapsed = len(idxMap) - 1
	}
	end := idxMap[endCollapsed] + 1
	return start, end, true
}

// locateDigits: find needle (digits) within the digit-stripped projection of
// text and map back to the original [start,end) covering those digits.
func locateDigits(text, needle string) (int, int, bool) {
	var digits strings.Builder
	pos := make([]int, 0, len(text))
	for i, r := range text {
		if r >= '0' && r <= '9' {
			digits.WriteRune(r)
			pos = append(pos, i)
		}
	}
	j := strings.Index(digits.String(), needle)
	if j < 0 {
		return 0, 0, false
	}
	start := pos[j]
	end := pos[j+len(needle)-1] + 1
	return start, end, true
}
