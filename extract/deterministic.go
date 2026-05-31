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
		if len(digitsOnly(m)) == 11 {
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
		if len(digitsOnly(m)) == 9 {
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
