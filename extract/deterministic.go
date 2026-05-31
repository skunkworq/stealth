package extract

import (
	"context"
	"regexp"
	"strings"
)

// RegexExtractor harvests identifiers/contacts from free text via patterns.
type RegexExtractor struct{}

func (RegexExtractor) Name() string { return "regex" }

var (
	abnRE   = regexp.MustCompile(`\b\d{2}[ ]?\d{3}[ ]?\d{3}[ ]?\d{3}\b`)
	acnRE   = regexp.MustCompile(`\b\d{3}[ ]?\d{3}[ ]?\d{3}\b`)
	emailRE = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`)
	phoneRE = regexp.MustCompile(`(?:\+?61|1[38]00|13|\(?0)[\d ()\-]{4,13}`)
)

var abnWeights = [11]int{10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19}

// validABN verifies the ATO ABN checksum, rejecting 11-digit runs that aren't
// real ABNs (random numbers, concatenated digits, IDs that merely have 11 digits).
func validABN(raw string) bool {
	d := digitsOnly(raw)
	if len(d) != 11 || d[0] == '0' {
		return false
	}
	sum := 0
	for i := 0; i < 11; i++ {
		n := int(d[i] - '0')
		if i == 0 {
			n-- // subtract 1 from the leading digit per the ABN algorithm
		}
		sum += n * abnWeights[i]
	}
	return sum%89 == 0
}

var acnWeights = [8]int{8, 7, 6, 5, 4, 3, 2, 1}

// validACN verifies the ASIC ACN checksum (complement of the weighted sum of
// the first 8 digits, mod 10, equals the 9th).
func validACN(raw string) bool {
	d := digitsOnly(raw)
	if len(d) != 9 {
		return false
	}
	sum := 0
	for i := 0; i < 8; i++ {
		sum += int(d[i]-'0') * acnWeights[i]
	}
	return (10-sum%10)%10 == int(d[8]-'0')
}

// validAUPhone reports whether raw is a plausible Australian phone number. It
// filters the greedy phone regex's false positives — random digit runs that
// merely start with 0 (e.g. "01010184966", "0 0 1584 308"). Accepts: 10-digit
// landline/mobile (0 + area/mobile digit 2-8), 1300/1800, and 13xxxx.
func validAUPhone(raw string) bool {
	d := digitsOnly(raw)
	if strings.HasPrefix(d, "61") && len(d) == 11 {
		d = "0" + d[2:]
	}
	switch {
	case len(d) == 10 && d[0] == '0' && strings.IndexByte("234578", d[1]) >= 0:
		return true
	case len(d) == 10 && (strings.HasPrefix(d, "1300") || strings.HasPrefix(d, "1800")):
		return true
	case len(d) == 6 && strings.HasPrefix(d, "13"):
		return true
	}
	return false
}

func (RegexExtractor) Extract(_ context.Context, doc *SourceDocument) ([]Candidate, error) {
	if doc == nil {
		return nil, nil
	}
	t := doc.Text
	var out []Candidate
	for _, m := range abnRE.FindAllString(t, -1) {
		if validABN(m) {
			out = append(out, Candidate{Key: KeyABN, Value: m, Method: MethodRegex, Conf: 0.9})
		}
	}
	for _, m := range emailRE.FindAllString(t, -1) {
		out = append(out, Candidate{Key: KeyEmail, Value: m, Method: MethodRegex, Conf: 0.9})
	}
	for _, m := range phoneRE.FindAllString(t, -1) {
		if validAUPhone(m) {
			out = append(out, Candidate{Key: KeyPhone, Value: strings.TrimSpace(m), Method: MethodRegex, Conf: 0.7})
		}
	}
	for _, m := range acnRE.FindAllString(t, -1) {
		if validACN(m) {
			out = append(out, Candidate{Key: KeyACN, Value: m, Method: MethodRegex, Conf: 0.6})
		}
	}
	return out, nil
}

// TelMailtoExtractor harvests tel:/mailto: hrefs (high precision).
type TelMailtoExtractor struct{}

func (TelMailtoExtractor) Name() string { return "tel_mailto" }

var (
	telRE    = regexp.MustCompile(`(?i)tel:([+0-9 ()\-]{6,})`)
	mailtoRE = regexp.MustCompile(`(?i)mailto:([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})`)
)

func (TelMailtoExtractor) Extract(_ context.Context, doc *SourceDocument) ([]Candidate, error) {
	if doc == nil {
		return nil, nil
	}
	var out []Candidate
	for _, m := range telRE.FindAllStringSubmatch(doc.Text, -1) {
		v := strings.TrimSpace(m[1])
		if len(digitsOnly(v)) >= 8 {
			out = append(out, Candidate{Key: KeyPhone, Value: v, Method: MethodTelMailto, Conf: 0.95})
		}
	}
	for _, m := range mailtoRE.FindAllStringSubmatch(doc.Text, -1) {
		out = append(out, Candidate{Key: KeyEmail, Value: strings.TrimSpace(m[1]), Method: MethodTelMailto, Conf: 0.95})
	}
	return out, nil
}
