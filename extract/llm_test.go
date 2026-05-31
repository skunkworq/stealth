package extract

import (
	"context"
	"testing"

	"github.com/skunkworq/stealth/brws/langextract"
)

func TestCandidatesFromExtractions(t *testing.T) {
	exs := []langextract.Extraction{
		{ExtractionClass: "phone", ExtractionText: "0412 345 678", CharInterval: &langextract.CharInterval{StartPos: 10, EndPos: 22}},
		{ExtractionClass: "service", ExtractionText: "blocked drains"},
		{ExtractionClass: "not_a_field", ExtractionText: "ignore me"},
	}
	cands := candidatesFromExtractions(exs)
	if len(cands) != 2 {
		t.Fatalf("want 2 mapped candidates, got %d", len(cands))
	}
	if cands[0].Key != KeyPhone || cands[0].Method != MethodLLMLangextract {
		t.Errorf("bad first candidate %+v", cands[0])
	}
	if cands[0].SpanHint == nil || cands[0].SpanHint.Start != 10 {
		t.Errorf("span hint not carried: %+v", cands[0].SpanHint)
	}
}

func TestLLMExtractorSkipsRawHTML(t *testing.T) {
	doc := &SourceDocument{Ref: "r", ContentType: "text/html", Text: "<p>0412 345 678</p>"}
	cands, err := LLMExtractor{}.Extract(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	if cands != nil {
		t.Fatalf("LLM must skip text/html docs, got %d candidates", len(cands))
	}
}
