package langextract

import "testing"

func TestMergeNonOverlappingExtractionsBranches(t *testing.T) {
	t.Parallel()

	if got := mergeNonOverlappingExtractions(nil); got != nil {
		t.Fatalf("expected nil for empty pass list")
	}

	single := []Extraction{{ExtractionClass: "person", ExtractionText: "Alice"}}
	got := mergeNonOverlappingExtractions([][]Extraction{single})
	if len(got) != 1 || got[0].ExtractionText != "Alice" {
		t.Fatalf("unexpected single-pass merge result: %+v", got)
	}
	single[0].ExtractionText = "mutated"
	if got[0].ExtractionText != "Alice" {
		t.Fatalf("expected merge copy to be independent of input slice mutations")
	}

	p1 := []Extraction{
		{
			ExtractionClass: "person",
			ExtractionText:  "Alice",
			CharInterval:    &CharInterval{StartPos: 0, EndPos: 5},
		},
	}
	p2 := []Extraction{
		{
			ExtractionClass: "person",
			ExtractionText:  "Alice Johnson",
			CharInterval:    &CharInterval{StartPos: 0, EndPos: 13}, // overlaps p1
		},
		{
			ExtractionClass: "org",
			ExtractionText:  "Acme",
			CharInterval:    &CharInterval{StartPos: 20, EndPos: 24}, // non-overlap
		},
		{
			ExtractionClass: "note",
			ExtractionText:  "unanchored",
			CharInterval:    nil, // always included
		},
	}
	merged := mergeNonOverlappingExtractions([][]Extraction{p1, p2})
	if len(merged) != 3 {
		t.Fatalf("expected 3 merged extractions (1 overlap dropped), got %d", len(merged))
	}
	if merged[1].ExtractionText != "Acme" {
		t.Fatalf("expected non-overlapping extraction to be retained: %+v", merged[1])
	}
	if merged[2].ExtractionText != "unanchored" {
		t.Fatalf("expected nil-char-interval extraction to be retained")
	}
}

func TestExtractionsOverlapAndFirstNonEmpty(t *testing.T) {
	t.Parallel()

	a := Extraction{CharInterval: &CharInterval{StartPos: 0, EndPos: 5}}
	b := Extraction{CharInterval: &CharInterval{StartPos: 4, EndPos: 8}}
	c := Extraction{CharInterval: &CharInterval{StartPos: 5, EndPos: 9}}
	d := Extraction{}

	if !extractionsOverlap(a, b) {
		t.Fatalf("expected overlap")
	}
	if extractionsOverlap(a, c) {
		t.Fatalf("did not expect overlap for touching boundaries")
	}
	if extractionsOverlap(a, d) {
		t.Fatalf("did not expect overlap with nil interval")
	}
	if got := firstNonEmpty("", "  ", "x", "y"); got != "x" {
		t.Fatalf("expected first non-empty value x, got %q", got)
	}
}
