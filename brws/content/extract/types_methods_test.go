package extract

import "testing"

func TestDocumentIDMethodBranches(t *testing.T) {
	t.Parallel()

	if got := (Document{}).id(); got != "document-1" {
		t.Fatalf("expected default document id, got %q", got)
	}
	if got := (Document{DocumentID: "doc-42"}).id(); got != "doc-42" {
		t.Fatalf("expected explicit document id, got %q", got)
	}
}

func TestExtractionSpanMethodBranches(t *testing.T) {
	t.Parallel()

	ex := Extraction{}
	if ex.CharStart() != -1 || ex.CharEnd() != -1 || ex.TokenStart() != -1 || ex.TokenEnd() != -1 {
		t.Fatalf("expected -1 sentinels when intervals are nil")
	}

	ex.CharInterval = &CharInterval{StartPos: 2, EndPos: 7}
	ex.TokenInterval = &TokenInterval{StartIndex: 1, EndIndex: 3}
	if ex.CharStart() != 2 || ex.CharEnd() != 7 || ex.TokenStart() != 1 || ex.TokenEnd() != 3 {
		t.Fatalf("unexpected interval helper values")
	}
}

func TestMustToSemanticNonNil(t *testing.T) {
	t.Parallel()

	raw := &RawExtractionResult{DocumentID: "doc-1", Text: "hello"}
	out := MustToSemantic(raw)
	if out.DocumentID != "doc-1" {
		t.Fatalf("expected semantic conversion output, got %+v", out)
	}
}
