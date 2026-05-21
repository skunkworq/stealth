package stealth_test

import (
	"context"
	"testing"

	"github.com/skunkworq/stealth/brws/browser/engine"
	"github.com/skunkworq/stealth/brws/content/understand"
	"github.com/skunkworq/stealth/brws/stealth"
)

func TestNewAdaptiveWithConfig(t *testing.T) {
	cfg := *stealth.DefaultConfig()
	cfg.EngineName = "native"
	cfg.Headless = true
	client, err := stealth.NewAdaptiveWithConfig(&cfg)
	if err != nil {
		t.Fatalf("NewAdaptiveWithConfig failed: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.Config().EngineName != "native" {
		t.Fatalf("expected EngineName 'native', got %s", client.Config().EngineName)
	}
	_ = client.Close()
}

func TestScrapeAlias(t *testing.T) {
	// Scrape is an alias for Navigate; verify it exists and calls through.
	cfg := *stealth.DefaultConfig()
	client, err := stealth.NewAdaptiveWithConfig(&cfg)
	if err != nil {
		t.Fatalf("NewAdaptiveWithConfig failed: %v", err)
	}
	defer client.Close()

	// Scrape method should exist (compile-time check above).
	// We can't meaningfully test navigation without a real server,
	// but we verify the method signature is correct.
	_ = client.Scrape
}

func TestResponseChallengeSolvedField(t *testing.T) {
	resp := &stealth.Response{ChallengeSolved: true}
	if !resp.ChallengeSolved {
		t.Fatal("expected ChallengeSolved to be true")
	}
}

func TestResponseAsHTML(t *testing.T) {
	htmlBody := []byte(`<html><head><title>Test</title></head>
	<body>
		<h1>Hello World</h1>
		<h1>Second Title</h1>
		<div class="content">Some content here</div>
		<div id="main">Main section</div>
	</body></html>`)

	resp := &stealth.Response{Response: engine.Response{Body: htmlBody}}
	doc, err := resp.AsHTML()
	if err != nil {
		t.Fatalf("AsHTML failed: %v", err)
	}
	if doc == nil {
		t.Fatal("expected non-nil document")
	}

	// Test tag selector
	titles := doc.QuerySelectorAll("h1")
	if len(titles) != 2 {
		t.Fatalf("expected 2 h1 elements, got %d", len(titles))
	}
	if titles[0].Text() != "Hello World" {
		t.Fatalf("expected 'Hello World', got %s", titles[0].Text())
	}
	if titles[1].Text() != "Second Title" {
		t.Fatalf("expected 'Second Title', got %s", titles[1].Text())
	}

	// Test class selector
	content := doc.QuerySelector(".content")
	if content == nil {
		t.Fatal("expected to find .content element")
	}
	if content.Text() != "Some content here" {
		t.Fatalf("expected 'Some content here', got %s", content.Text())
	}

	// Test ID selector
	main := doc.QuerySelector("#main")
	if main == nil {
		t.Fatal("expected to find #main element")
	}
	if main.Text() != "Main section" {
		t.Fatalf("expected 'Main section', got %s", main.Text())
	}

	// Test Attr
	if content.Attr("class") != "content" {
		t.Fatalf("expected class='content', got %s", content.Attr("class"))
	}
}

func TestResponseAsHTMLEmptyBody(t *testing.T) {
	resp := &stealth.Response{Response: engine.Response{Body: []byte("")}}
	doc, err := resp.AsHTML()
	if err != nil {
		t.Fatalf("AsHTML failed: %v", err)
	}
	if doc == nil {
		t.Fatal("expected non-nil document even for empty body")
	}
	results := doc.QuerySelectorAll("h1")
	if len(results) != 0 {
		t.Fatalf("expected 0 h1 elements for empty body, got %d", len(results))
	}
}

// Compile-time check that Scrape matches the expected signature.
var _ func(context.Context, string) (*stealth.Response, error) = (*stealth.Adaptive)(nil).Scrape

// ---------------------------------------------------------------------------
// Stealth client persistent tab & semantic integration tests
// ---------------------------------------------------------------------------

func TestClientNewTabNativeEngine(t *testing.T) {
	// With a native engine, NewTab should return false.
	cfg := *stealth.DefaultConfig()
	cfg.EngineName = "native"
	client, err := stealth.NewAdaptiveWithConfig(&cfg)
	if err != nil {
		t.Fatalf("NewAdaptiveWithConfig failed: %v", err)
	}
	defer client.Close()

	_, _, ok := client.NewTab()
	if ok {
		t.Fatal("expected NewTab to return false for native engine")
	}
}

func TestClientBrowserContextNativeEngine(t *testing.T) {
	cfg := *stealth.DefaultConfig()
	cfg.EngineName = "native"
	client, err := stealth.NewAdaptiveWithConfig(&cfg)
	if err != nil {
		t.Fatalf("NewAdaptiveWithConfig failed: %v", err)
	}
	defer client.Close()

	_, ok := client.BrowserContext()
	if ok {
		t.Fatal("expected BrowserContext to return false for native engine")
	}
}

func TestClientEngineReturnsActiveEngine(t *testing.T) {
	cfg := *stealth.DefaultConfig()
	cfg.EngineName = "native"
	client, err := stealth.NewAdaptiveWithConfig(&cfg)
	if err != nil {
		t.Fatalf("NewAdaptiveWithConfig failed: %v", err)
	}
	defer client.Close()

	eng := client.ActiveEngine()
	if eng == nil {
		t.Fatal("expected non-nil engine")
	}
	if eng.Name() != "native" {
		t.Fatalf("expected engine name 'native', got %s", eng.Name())
	}
}

func TestClientNewSemanticExtractor(t *testing.T) {
	cfg := *stealth.DefaultConfig()
	cfg.EngineName = "native"
	client, err := stealth.NewAdaptiveWithConfig(&cfg)
	if err != nil {
		t.Fatalf("NewAdaptiveWithConfig failed: %v", err)
	}
	defer client.Close()

	extractor := client.NewSemanticExtractor(&understand.PipelineConfig{})
	if extractor == nil {
		t.Fatal("expected non-nil semantic extractor")
	}
}

// Compile-time checks for new method signatures.
var _ func() (context.Context, context.CancelFunc, bool) = (*stealth.Adaptive)(nil).NewTab
var _ func() (context.Context, bool) = (*stealth.Adaptive)(nil).BrowserContext
var _ func() engine.Engine = (*stealth.Adaptive)(nil).ActiveEngine
var _ func(*understand.PipelineConfig) *understand.SemanticExtractor = (*stealth.Adaptive)(nil).NewSemanticExtractor
