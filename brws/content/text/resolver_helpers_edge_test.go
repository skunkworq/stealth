package langextract

import (
	"strings"
	"testing"
)

func TestNewResolverDefaultsWithNilHandler(t *testing.T) {
	t.Parallel()

	r := NewResolver(nil)
	if r == nil {
		t.Fatalf("expected resolver instance")
	}
	if r.FormatHandler == nil {
		t.Fatalf("expected default format handler")
	}
	if r.ExtractionIndexSuffix != "" {
		t.Fatalf("expected empty default extraction index suffix, got %q", r.ExtractionIndexSuffix)
	}
}

func TestResolverResolveNilReceiverAndEmptyInput(t *testing.T) {
	t.Parallel()

	var r *Resolver

	if _, err := r.Resolve(" \n\t", false); err == nil {
		t.Fatalf("expected non-empty input validation error")
	}

	out, err := r.Resolve(`{"extractions":[{"person":"Alice"}]}`, false)
	if err != nil {
		t.Fatalf("expected nil receiver to resolve with defaults: %v", err)
	}
	if len(out) != 1 || out[0].ExtractionClass != "person" {
		t.Fatalf("unexpected resolved output: %+v", out)
	}
}

func TestResolverResolveUnsuppressedParseError(t *testing.T) {
	t.Parallel()

	handler := NewFormatHandler()
	handler.StrictFences = true
	resolver := NewResolver(handler)

	_, err := resolver.Resolve(`{"extractions":[{"person":"Alice"}]}`, false)
	if err == nil {
		t.Fatalf("expected parse error when strict fences are required")
	}
	if !strings.Contains(err.Error(), "resolve") {
		t.Fatalf("expected wrapped resolver parse error, got %v", err)
	}
}

func TestExtractionValueToStringAndAsIntBranches(t *testing.T) {
	t.Parallel()

	if got, ok := extractionValueToString("alice"); !ok || got != "alice" {
		t.Fatalf("string branch failed: ok=%v got=%q", ok, got)
	}
	if got, ok := extractionValueToString(7); !ok || got != "7" {
		t.Fatalf("int branch failed: ok=%v got=%q", ok, got)
	}
	if got, ok := extractionValueToString(int64(9)); !ok || got != "9" {
		t.Fatalf("int64 branch failed: ok=%v got=%q", ok, got)
	}
	if got, ok := extractionValueToString(10.0); !ok || got != "10" {
		t.Fatalf("float64 integral branch failed: ok=%v got=%q", ok, got)
	}
	if got, ok := extractionValueToString(10.5); !ok || got != "10.5" {
		t.Fatalf("float64 decimal branch failed: ok=%v got=%q", ok, got)
	}
	if got, ok := extractionValueToString(float32(12.0)); !ok || got != "12" {
		t.Fatalf("float32 integral branch failed: ok=%v got=%q", ok, got)
	}
	if got, ok := extractionValueToString(float32(12.25)); !ok || got != "12.25" {
		t.Fatalf("float32 decimal branch failed: ok=%v got=%q", ok, got)
	}
	if got, ok := extractionValueToString(struct{}{}); ok || got != "" {
		t.Fatalf("unsupported type should fail conversion: ok=%v got=%q", ok, got)
	}

	if got, ok := asInt(3); !ok || got != 3 {
		t.Fatalf("int branch failed: ok=%v got=%d", ok, got)
	}
	if got, ok := asInt(int32(4)); !ok || got != 4 {
		t.Fatalf("int32 branch failed: ok=%v got=%d", ok, got)
	}
	if got, ok := asInt(int64(5)); !ok || got != 5 {
		t.Fatalf("int64 branch failed: ok=%v got=%d", ok, got)
	}
	if got, ok := asInt(6.0); !ok || got != 6 {
		t.Fatalf("float64 integral branch failed: ok=%v got=%d", ok, got)
	}
	if _, ok := asInt(6.2); ok {
		t.Fatalf("expected non-integral float64 to fail asInt conversion")
	}
	if _, ok := asInt("7"); ok {
		t.Fatalf("expected unsupported type to fail asInt conversion")
	}
}
