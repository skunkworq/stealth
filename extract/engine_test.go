package extract

import (
	"context"
	"testing"
)

// stubExtractor lets us inject candidates (incl. a hallucinated one).
type stubExtractor struct {
	name  string
	cands []Candidate
}

func (s stubExtractor) Name() string { return s.name }
func (s stubExtractor) Extract(_ context.Context, _ *SourceDocument) ([]Candidate, error) {
	return s.cands, nil
}

func TestEngineDropsHallucinatedValue(t *testing.T) {
	doc := &SourceDocument{Ref: "r", Text: "ABN 50 629 080 842"}
	eng := NewEngine(stubExtractor{name: "llm", cands: []Candidate{
		{Key: KeyABN, Value: "50629080842", Method: MethodLLMLangextract},
		{Key: KeyPhone, Value: "0499 999 999", Method: MethodLLMLangextract}, // not in text
	}})
	fields, _ := eng.Extract(context.Background(), []*SourceDocument{doc}, []FieldKey{KeyABN, KeyPhone})
	if len(fields) != 1 || fields[0].Key != KeyABN {
		t.Fatalf("hallucinated phone must be dropped; got %+v", fields)
	}
}

func TestEngineDeterministicBeatsLLM(t *testing.T) {
	doc := &SourceDocument{Ref: "r", Text: "ABN 50 629 080 842"}
	eng := NewEngine(
		stubExtractor{name: "llm", cands: []Candidate{{Key: KeyABN, Value: "50629080842", Method: MethodLLMLangextract, Conf: 0.6}}},
		stubExtractor{name: "regex", cands: []Candidate{{Key: KeyABN, Value: "50 629 080 842", Method: MethodRegex, Conf: 0.9}}},
	)
	fields, _ := eng.Extract(context.Background(), []*SourceDocument{doc}, []FieldKey{KeyABN})
	if len(fields) != 1 || fields[0].Method != MethodRegex {
		t.Fatalf("deterministic should win single-valued merge; got %+v", fields)
	}
}

func TestEngineMultiValuedKept(t *testing.T) {
	doc := &SourceDocument{Ref: "r", Text: "phones: 0412 345 678 and 0498 765 432"}
	eng := NewEngine(stubExtractor{name: "regex", cands: []Candidate{
		{Key: KeyPhone, Value: "0412 345 678", Method: MethodRegex},
		{Key: KeyPhone, Value: "0498 765 432", Method: MethodRegex},
	}})
	fields, _ := eng.Extract(context.Background(), []*SourceDocument{doc}, []FieldKey{KeyPhone})
	if len(fields) != 2 {
		t.Fatalf("both phones should survive; got %d", len(fields))
	}
}
