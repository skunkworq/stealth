package extract

import "testing"

func TestLXErrorFormatting(t *testing.T) {
	t.Parallel()

	var nilErr *LXError
	if got := nilErr.Error(); got != "<nil>" {
		t.Fatalf("expected <nil>, got %q", got)
	}

	if got := (&LXError{Msg: "only-msg"}).Error(); got != "only-msg" {
		t.Fatalf("unexpected msg-only error: %q", got)
	}
	if got := (&LXError{Op: "only-op"}).Error(); got != "only-op" {
		t.Fatalf("unexpected op-only error: %q", got)
	}
	if got := (&LXError{Op: "extract", Msg: "failed"}).Error(); got != "extract: failed" {
		t.Fatalf("unexpected op+msg error: %q", got)
	}
}
