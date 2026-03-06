package langextract

import "testing"

func TestSetAlignedIntervalsValidationAndOffsets(t *testing.T) {
	t.Parallel()

	tokenized := TokenizeWithDefault("Alice works.")
	ex := &Extraction{}

	setAlignedIntervals(ex, &tokenized, -1, 1, 0, 0, AlignmentExact)
	if ex.TokenInterval != nil || ex.CharInterval != nil || ex.Alignment != "" {
		t.Fatalf("expected invalid range to clear intervals/alignment")
	}

	setAlignedIntervals(ex, &tokenized, 0, 1, 2, 10, AlignmentExact)
	if ex.TokenInterval == nil || ex.CharInterval == nil {
		t.Fatalf("expected intervals for valid range")
	}
	if ex.TokenInterval.StartIndex != 2 || ex.TokenInterval.EndIndex != 3 {
		t.Fatalf("unexpected token interval with offsets: %+v", ex.TokenInterval)
	}
	if ex.CharInterval.StartPos != 10 || ex.CharInterval.EndPos <= ex.CharInterval.StartPos {
		t.Fatalf("unexpected char interval with offsets: %+v", ex.CharInterval)
	}
	if ex.Alignment != AlignmentExact {
		t.Fatalf("expected alignment status to be set")
	}
}

