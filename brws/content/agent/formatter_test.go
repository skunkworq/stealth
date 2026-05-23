package agent_test

import (
	"strings"
	"testing"
	"time"

	"github.com/skunkworq/stealth/brws/content/agent"
)

func makeSnapshot(url, title string) *agent.PageSnapshot {
	return &agent.PageSnapshot{
		URL:       url,
		Title:     title,
		Timestamp: time.Now(),
		Viewport:  agent.Viewport{Width: 1280, Height: 800},
		Scroll:    agent.ScrollState{X: 0, Y: 0, MaxY: 500},
	}
}

func TestDefaultFormatter(t *testing.T) {
	f := agent.DefaultFormatter()
	if f == nil {
		t.Fatal("DefaultFormatter returned nil")
	}
	if f.MaxTokens <= 0 {
		t.Error("MaxTokens should be positive")
	}
	if f.IncludeForms != true {
		t.Error("IncludeForms should be true by default")
	}
	if f.IncludeLinks != false {
		t.Error("IncludeLinks should be false by default")
	}
}

func TestFormatter_Format_returnsString(t *testing.T) {
	f := agent.DefaultFormatter()
	snap := makeSnapshot("https://example.com", "Example")
	ctx := agent.NewContext(snap)
	result := f.Format(ctx)
	if result == "" {
		t.Error("Format returned empty string")
	}
}

func TestFormatter_Format_containsURL(t *testing.T) {
	f := agent.DefaultFormatter()
	snap := makeSnapshot("https://example.com/page", "My Page")
	ctx := agent.NewContext(snap)
	result := f.Format(ctx)
	if !strings.Contains(result, "example.com") {
		t.Errorf("Format output does not contain URL, got: %s", result[:min(200, len(result))])
	}
}

func TestFormatter_Format_containsTitle(t *testing.T) {
	f := agent.DefaultFormatter()
	snap := makeSnapshot("https://example.com", "My Special Title")
	ctx := agent.NewContext(snap)
	result := f.Format(ctx)
	if !strings.Contains(result, "My Special Title") {
		t.Errorf("Format output does not contain title")
	}
}

func TestFormatter_Format_withElements(t *testing.T) {
	f := agent.DefaultFormatter()
	snap := makeSnapshot("https://example.com", "Test")
	snap.Elements = []agent.VisibleElement{
		{
			ID:            "btn-1",
			Tag:           "button",
			Text:          "Click me",
			IsInteractive: true,
			IsVisible:     true,
			ActionTypes:   []agent.ActionType{agent.ActionClick},
		},
	}
	ctx := agent.NewContext(snap)
	result := f.Format(ctx)
	if !strings.Contains(result, "Click me") {
		t.Errorf("Format output does not contain element text")
	}
}

func TestFormatter_FormatCompact_returnsString(t *testing.T) {
	f := agent.DefaultFormatter()
	snap := makeSnapshot("https://example.com", "Test")
	ctx := agent.NewContext(snap)
	result := f.FormatCompact(ctx)
	if result == "" {
		t.Error("FormatCompact returned empty string")
	}
}

func TestFormatter_FormatJSON_validJSON(t *testing.T) {
	f := agent.DefaultFormatter()
	snap := makeSnapshot("https://example.com", "Test")
	ctx := agent.NewContext(snap)
	result := f.FormatJSON(ctx)
	if !strings.HasPrefix(strings.TrimSpace(result), "{") {
		t.Errorf("FormatJSON does not return JSON object: %q", result[:min(100, len(result))])
	}
}

func TestFormatter_IncludeLinks(t *testing.T) {
	f := agent.DefaultFormatter()
	f.IncludeLinks = true
	snap := makeSnapshot("https://example.com", "Test")
	snap.Links = []agent.Link{
		{Text: "Home", Href: "https://example.com/"},
		{Text: "About", Href: "https://example.com/about"},
	}
	ctx := agent.NewContext(snap)
	result := f.Format(ctx)
	if !strings.Contains(result, "Home") {
		t.Error("Format with IncludeLinks should contain link text")
	}
}

func TestFormatter_IncludeLinks_false(t *testing.T) {
	f := agent.DefaultFormatter()
	f.IncludeLinks = false
	snap := makeSnapshot("https://example.com", "Test")
	snap.Links = []agent.Link{
		{Text: "HiddenLink", Href: "https://example.com/hidden"},
	}
	ctx := agent.NewContext(snap)
	result := f.Format(ctx)
	if strings.Contains(result, "HiddenLink") {
		t.Error("Format with IncludeLinks=false should not contain link text")
	}
}

func TestFormatter_scrollActions(t *testing.T) {
	f := agent.DefaultFormatter()
	snap := makeSnapshot("https://example.com", "Test")
	snap.Scroll = agent.ScrollState{X: 0, Y: 100, MaxY: 1000}
	ctx := agent.NewContext(snap)
	result := f.Format(ctx)
	if result == "" {
		t.Error("expected non-empty result")
	}
}

func TestFormatter_Format_withHistory(t *testing.T) {
	f := agent.DefaultFormatter()
	snap := makeSnapshot("https://example.com/page2", "Page 2")
	snap.History = agent.HistoryState{
		Length:       2,
		CurrentIndex: 1,
		CanGoBack:    true,
		CanGoForward: false,
	}
	ctx := agent.NewContext(snap)
	result := f.Format(ctx)
	if result == "" {
		t.Error("expected non-empty result with history")
	}
}

func TestFormatter_Format_withTabs(t *testing.T) {
	f := agent.DefaultFormatter()
	snap := makeSnapshot("https://example.com", "Test")
	snap.Tabs = []agent.TabState{
		{TargetID: "tab1", URL: "https://example.com", Title: "Tab 1", IsActive: true, Index: 0},
		{TargetID: "tab2", URL: "https://other.com", Title: "Tab 2", IsActive: false, Index: 1},
	}
	ctx := agent.NewContext(snap)
	result := f.Format(ctx)
	if result == "" {
		t.Error("expected non-empty result with tabs")
	}
}

func TestFormatter_MaxTokens_zero(t *testing.T) {
	f := agent.DefaultFormatter()
	f.MaxTokens = 0 // unlimited
	snap := makeSnapshot("https://example.com", "Test")
	ctx := agent.NewContext(snap)
	result := f.Format(ctx)
	if result == "" {
		t.Error("Format with MaxTokens=0 should still return output")
	}
}

func TestFormatter_NewContext(t *testing.T) {
	snap := makeSnapshot("https://example.com", "Test")
	ctx := agent.NewContext(snap)
	if ctx == nil {
		t.Fatal("NewContext returned nil")
	}
	if ctx.Snapshot != snap {
		t.Error("NewContext did not preserve snapshot pointer")
	}
	if ctx.ActionSpace == nil {
		t.Error("NewContext should build ActionSpace")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
