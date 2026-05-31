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
	if class == ClassIdentifier && len(digitsOnly(val)) < minIdentifierDigits(cand.Key) {
		return Field{}, false
	}
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

// minIdentifierDigits is the minimum digit count an identifier must carry to
// be considered. Phones get a higher floor (8) so a short numeric token like a
// 4-digit postcode can't be accepted as a phone number; other identifiers keep
// a permissive floor (licence numbers can be short).
func minIdentifierDigits(k FieldKey) int {
	if k == KeyPhone {
		return 8
	}
	return 4
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

// locateDigits matches needle (digits only) against a whole NUMERIC TOKEN in
// text — not a substring of the global digit projection. A numeric token is a
// maximal run of digits plus internal number separators (space . - ( ) +). The
// candidate's digit content must EQUAL a token's digit content.
//
// Equality (not substring) is load-bearing for the zero-hallucination
// guarantee: it stops a candidate from matching a sub-sequence of a larger
// identifier (e.g. the middle 9 digits of an ABN), or digits that only become
// contiguous because two adjacent record fields were concatenated. Identifiers
// (ABN/ACN/licence/phone) are always whole tokens, so equality is correct.
// All bytes of interest (ASCII digits and separators) are single-byte, so we
// scan bytes directly; any other byte ends the current token.
func locateDigits(text, needle string) (int, int, bool) {
	isDigit := func(b byte) bool { return b >= '0' && b <= '9' }
	isSep := func(b byte) bool {
		return b == ' ' || b == '.' || b == '-' || b == '(' || b == ')' || b == '+'
	}
	n := len(text)
	for i := 0; i < n; {
		if !isDigit(text[i]) {
			i++
			continue
		}
		var digits strings.Builder
		first, last := i, i
		j := i
		for j < n {
			if isDigit(text[j]) {
				last = j
				digits.WriteByte(text[j])
				j++
				continue
			}
			if isSep(text[j]) {
				// A separator is INTERNAL only if a digit follows the
				// separator run; otherwise the token ends here.
				k := j
				for k < n && isSep(text[k]) {
					k++
				}
				if k < n && isDigit(text[k]) {
					j = k
					continue
				}
			}
			break
		}
		if digits.String() == needle {
			return first, last + 1, true
		}
		if j > i {
			i = j
		} else {
			i++
		}
	}
	return 0, 0, false
}
