package diff_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/skunkworq/stealth/brws/browser/engine"
	"github.com/skunkworq/stealth/brws/fingerprint/http/diff"
)

func makeEngineResult(name string, status int, body string) diff.EngineResult {
	return diff.EngineResult{
		EngineName: name,
		Response: &engine.Response{
			Status:   status,
			Body:     []byte(body),
			Protocol: "h2",
			Headers:  map[string][]string{"Content-Type": {"text/html"}},
		},
	}
}

func TestCompare_emptyResults(t *testing.T) {
	comp := diff.Compare("https://example.com", nil)
	if comp == nil {
		t.Fatal("Compare returned nil for empty results")
	}
	if comp.URL != "https://example.com" {
		t.Errorf("URL = %q, want %q", comp.URL, "https://example.com")
	}
}

func TestCompare_singleResult(t *testing.T) {
	results := []diff.EngineResult{
		makeEngineResult("native", 200, "hello"),
	}
	comp := diff.Compare("https://example.com", results)
	if comp == nil {
		t.Fatal("Compare returned nil")
	}
	if len(comp.Engines) != 1 {
		t.Errorf("Engines len = %d, want 1", len(comp.Engines))
	}
}

func TestCompare_sameStatus(t *testing.T) {
	results := []diff.EngineResult{
		makeEngineResult("native", 200, "body"),
		makeEngineResult("chromium", 200, "body"),
	}
	comp := diff.Compare("https://example.com", results)
	if comp == nil {
		t.Fatal("Compare returned nil")
	}
	if comp.StatusDiff == nil {
		t.Fatal("StatusDiff is nil")
	}
	// Both engines return 200 — values should be recorded
	if comp.StatusDiff.Values["native"] != 200 {
		t.Errorf("native status = %d, want 200", comp.StatusDiff.Values["native"])
	}
	if comp.StatusDiff.Values["chromium"] != 200 {
		t.Errorf("chromium status = %d, want 200", comp.StatusDiff.Values["chromium"])
	}
}

func TestCompare_differentStatus(t *testing.T) {
	results := []diff.EngineResult{
		makeEngineResult("native", 200, "ok"),
		makeEngineResult("chromium", 403, "forbidden"),
	}
	comp := diff.Compare("https://example.com", results)
	if comp == nil {
		t.Fatal("Compare returned nil")
	}
	if comp.StatusDiff == nil {
		t.Fatal("StatusDiff is nil")
	}
	if comp.StatusDiff.Same {
		t.Error("StatusDiff.Same should be false when status codes differ")
	}
}

func TestCompare_statusValues(t *testing.T) {
	results := []diff.EngineResult{
		makeEngineResult("native", 200, "ok"),
		makeEngineResult("chromium", 301, "redirect"),
	}
	comp := diff.Compare("https://example.com", results)
	if comp.StatusDiff.Values["native"] != 200 {
		t.Errorf("native status = %d, want 200", comp.StatusDiff.Values["native"])
	}
	if comp.StatusDiff.Values["chromium"] != 301 {
		t.Errorf("chromium status = %d, want 301", comp.StatusDiff.Values["chromium"])
	}
}

func TestCompare_withError(t *testing.T) {
	results := []diff.EngineResult{
		makeEngineResult("native", 200, "ok"),
		{EngineName: "chromium", Error: errors.New("connection refused")},
	}
	comp := diff.Compare("https://example.com", results)
	if comp == nil {
		t.Fatal("Compare returned nil")
	}
	if len(comp.Engines) != 2 {
		t.Errorf("Engines len = %d, want 2", len(comp.Engines))
	}
}

func TestCompare_hasSummary(t *testing.T) {
	results := []diff.EngineResult{
		makeEngineResult("native", 200, "ok"),
		makeEngineResult("chromium", 200, "ok"),
	}
	comp := diff.Compare("https://example.com", results)
	if comp.Summary == "" {
		t.Error("Summary should not be empty")
	}
}

func TestCompare_JSON(t *testing.T) {
	results := []diff.EngineResult{
		makeEngineResult("native", 200, "ok"),
	}
	comp := diff.Compare("https://example.com", results)
	data, err := comp.JSON()
	if err != nil {
		t.Fatalf("JSON() error: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("JSON output is not valid JSON: %v", err)
	}
}

func TestCompare_FormatPretty(t *testing.T) {
	results := []diff.EngineResult{
		makeEngineResult("native", 200, "ok"),
		makeEngineResult("chromium", 200, "ok"),
	}
	comp := diff.Compare("https://example.com", results)
	pretty := comp.FormatPretty()
	if pretty == "" {
		t.Error("FormatPretty returned empty string")
	}
}

func TestCompareTraces_empty(t *testing.T) {
	comp := diff.CompareTraces(nil)
	if comp == nil {
		t.Fatal("CompareTraces returned nil for nil input")
	}
}

func TestCompareTraces_withResults(t *testing.T) {
	results := []diff.EngineResult{
		{EngineName: "native", Response: &engine.Response{Status: 200}},
	}
	comp := diff.CompareTraces(results)
	if comp == nil {
		t.Fatal("CompareTraces returned nil")
	}
	if len(comp.Engines) != 1 {
		t.Errorf("Engines len = %d, want 1", len(comp.Engines))
	}
}

func TestNewHeaderSet(t *testing.T) {
	h := http.Header{
		"Content-Type": {"application/json"},
		"Accept":       {"text/html", "application/json"},
	}
	hs := diff.NewHeaderSet(h)
	if hs == nil {
		t.Fatal("NewHeaderSet returned nil")
	}
	if len(hs.Headers) == 0 {
		t.Error("HeaderSet has no headers")
	}
}

func TestHeaderSet_Diff_same(t *testing.T) {
	h1 := http.Header{"Content-Type": {"text/html"}, "Accept": {"*/*"}}
	h2 := http.Header{"Content-Type": {"text/html"}, "Accept": {"*/*"}}
	hs1 := diff.NewHeaderSet(h1)
	hs2 := diff.NewHeaderSet(h2)
	diffs := hs1.Diff(hs2)
	if len(diffs) != 0 {
		t.Errorf("Diff len = %d, want 0 for identical headers", len(diffs))
	}
}

func TestHeaderSet_Diff_different(t *testing.T) {
	h1 := http.Header{"Content-Type": {"text/html"}}
	h2 := http.Header{"Content-Type": {"application/json"}}
	hs1 := diff.NewHeaderSet(h1)
	hs2 := diff.NewHeaderSet(h2)
	diffs := hs1.Diff(hs2)
	if _, ok := diffs["Content-Type"]; !ok {
		t.Error("expected Content-Type in diffs")
	}
}

func TestHeaderSet_Diff_missingKey(t *testing.T) {
	h1 := http.Header{"X-Custom": {"value"}}
	h2 := http.Header{}
	hs1 := diff.NewHeaderSet(h1)
	hs2 := diff.NewHeaderSet(h2)
	diffs := hs1.Diff(hs2)
	if _, ok := diffs["X-Custom"]; !ok {
		t.Error("expected X-Custom in diffs when absent from second set")
	}
}

func TestCompare_protocolDiff(t *testing.T) {
	r1 := makeEngineResult("native", 200, "body")
	r1.Response.Protocol = "h2"
	r2 := makeEngineResult("chromium", 200, "body")
	r2.Response.Protocol = "h3"
	comp := diff.Compare("https://example.com", []diff.EngineResult{r1, r2})
	if comp == nil {
		t.Fatal("Compare returned nil")
	}
	if comp.ProtocolDiff == nil {
		t.Fatal("ProtocolDiff is nil for different protocols")
	}
	if comp.ProtocolDiff.Same {
		t.Error("ProtocolDiff.Same should be false for h2 vs h3")
	}
}
