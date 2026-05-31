package extract

import (
	"context"
	"sort"
	"strings"
)

// singleValued keys keep one best value; everything else is multi-valued.
var singleValued = map[FieldKey]bool{
	KeyLegalName: true, KeyABN: true, KeyACN: true, KeyLicence: true,
	KeyAddress: true, KeyWebsite: true, KeyLogoURL: true,
}

type Engine struct {
	extractors []Extractor
	validator  *Validator
}

func NewEngine(extractors ...Extractor) *Engine {
	return &Engine{extractors: extractors, validator: NewValidator()}
}

// Extract runs every extractor over every doc, validates all candidates, and
// merges into a stable []Field. want filters which keys are emitted (nil = all).
func (e *Engine) Extract(ctx context.Context, docs []*SourceDocument, want []FieldKey) ([]Field, error) {
	wantSet := map[FieldKey]bool{}
	for _, k := range want {
		wantSet[k] = true
	}
	keep := func(k FieldKey) bool { return len(wantSet) == 0 || wantSet[k] }

	var validated []Field
	for _, doc := range docs {
		for _, ex := range e.extractors {
			cands, err := ex.Extract(ctx, doc)
			if err != nil {
				continue // isolate extractor failures
			}
			for _, c := range cands {
				if !keep(c.Key) {
					continue
				}
				if f, ok := e.validator.Validate(doc, c); ok {
					validated = append(validated, f)
				}
			}
		}
	}
	return merge(validated), nil
}

// merge dedupes and applies single-valued precedence. Stable ordering by
// (key, source, span).
func merge(in []Field) []Field {
	best := map[FieldKey]Field{}
	var multi []Field
	seen := map[string]bool{}
	for _, f := range in {
		if singleValued[f.Key] {
			cur, ok := best[f.Key]
			if !ok || rankField(f) > rankField(cur) {
				best[f.Key] = f
			}
			continue
		}
		dedupeKey := string(f.Key) + "|" + normValue(f)
		if seen[dedupeKey] {
			continue
		}
		seen[dedupeKey] = true
		multi = append(multi, f)
	}
	out := multi
	for _, f := range best {
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Key != out[j].Key {
			return out[i].Key < out[j].Key
		}
		if out[i].SourceRef != out[j].SourceRef {
			return out[i].SourceRef < out[j].SourceRef
		}
		return out[i].Span.Start < out[j].Span.Start
	})
	return out
}

func rankField(f Field) int { return methodRank(f.Method)*1000 + int(f.Confidence*100) }

func normValue(f Field) string {
	if ClassOf(f.Key) == ClassIdentifier {
		return digitsOnly(f.Value)
	}
	return strings.ToLower(collapseWS(f.Value))
}
