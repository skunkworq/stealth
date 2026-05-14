package understand

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"golang.org/x/net/html"
)

func TestCleanHTML(t *testing.T) {
	htmlStr := `<!DOCTYPE html>
<html>
<head>
	<title>Test Page</title>
	<script>console.log('remove me')</script>
	<style>.remove { display: none; }</style>
</head>
<body>
	<header>
		<nav><a href="/">Home</a></nav>
	</header>
	<main>
		<div class="hidden">Should be removed</div>
		<div class="content">Keep this content</div>
		<div style="display: none">Hidden element</div>
	</main>
	<footer>
		<noscript>Enable JavaScript</noscript>
	</footer>
</body>
</html>`

	cleaned, doc, _, err := cleanAndParseHTML(htmlStr)
	if err != nil {
		t.Fatalf("cleanAndParseHTML failed: %v", err)
	}

	if strings.Contains(cleaned, "console.log") {
		t.Error("script should be removed")
	}
	if strings.Contains(cleaned, ".remove {") {
		t.Error("style should be removed")
	}
	if strings.Contains(cleaned, "Should be removed") {
		t.Error("hidden elements should be removed")
	}
	if !strings.Contains(cleaned, "Keep this content") {
		t.Error("visible content should be preserved")
	}
	if strings.Contains(cleaned, "Enable JavaScript") {
		t.Error("noscript should be removed")
	}

	if doc == nil {
		t.Error("expected parsed document")
	}
}

func TestExtractTitle(t *testing.T) {
	tests := []struct {
		html     string
		expected string
	}{
		{
			html:     `<html><head><title>Test Title</title></head><body></body></html>`,
			expected: "Test Title",
		},
		{
			html:     `<html><body>No title here</body></html>`,
			expected: "",
		},
	}

	for _, tt := range tests {
		_, doc, got, err := cleanAndParseHTML(tt.html)
		if err != nil {
			t.Errorf("parse error: %v", err)
			continue
		}
		_ = doc
		if got != tt.expected {
			t.Errorf("expected %q, got %q", tt.expected, got)
		}
	}
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		url      string
		expected string
	}{
		{"https://example.com/path", "example.com"},
		{"https://subdomain.example.com:8080/path", "subdomain.example.com:8080"},
		{"http://localhost:3000", "localhost:3000"},
		{"https://www.google.com/search?q=test", "www.google.com"},
		{"invalid-url", "invalid-url"},
	}

	for _, tt := range tests {
		got := ExtractDomain(tt.url)
		if got != tt.expected {
			t.Errorf("ExtractDomain(%q) = %q, want %q", tt.url, got, tt.expected)
		}
	}
}

func TestChunkDOM(t *testing.T) {
	htmlStr := `<!DOCTYPE html>
<html>
<body>
	<header><nav><a href="/">Home</a><a href="/about">About</a></nav></header>
	<main>
		<section class="grid">
			<div class="item">Item 1</div>
			<div class="item">Item 2</div>
			<div class="item">Item 3</div>
			<div class="item">Item 4</div>
		</section>
	</main>
	<footer><p>Footer text</p></footer>
</body>
</html>`

	_, doc, _, err := cleanAndParseHTML(htmlStr)
	if err != nil {
		t.Fatalf("cleanAndParseHTML failed: %v", err)
	}

	chunks := chunkDOM(doc, "https://example.com")

	if len(chunks) < 2 {
		t.Errorf("expected at least 2 chunks, got %d", len(chunks))
	}

	if chunks[0].Tag != "header" {
		t.Errorf("expected first chunk to be header, got %s", chunks[0].Tag)
	}

	for _, chunk := range chunks {
		if chunk.Selector == "" {
			t.Error("expected non-empty selector")
		}
		if chunk.StructuralHash == "" {
			t.Error("expected non-empty structural hash")
		}
	}
}

func TestCountChunks(t *testing.T) {
	chunks := []DomChunk{
		{Selector: "body > header"},
		{
			Selector: "body > main",
			Children: []DomChunk{
				{Selector: "body > main > section"},
				{Selector: "body > main > aside"},
			},
		},
		{Selector: "body > footer"},
	}

	count := countChunks(chunks)
	if count != 5 {
		t.Errorf("expected 5 chunks, got %d", count)
	}
}

func TestLimitChunkTree(t *testing.T) {
	chunks := []DomChunk{
		{Selector: "body > header"},
		{
			Selector: "body > main",
			Children: []DomChunk{
				{Selector: "body > main > section"},
				{Selector: "body > main > aside"},
			},
		},
		{Selector: "body > footer"},
	}

	limited := limitChunkTree(chunks, 3)
	if got := countChunks(limited); got != 3 {
		t.Fatalf("expected 3 chunks after limit, got %d", got)
	}

	if len(limited) != 2 {
		t.Fatalf("expected 2 top-level chunks after limit, got %d", len(limited))
	}

	if limited[0].Selector != "body > header" || limited[1].Selector != "body > main" {
		t.Fatalf("unexpected top-level selector order: %q, %q", limited[0].Selector, limited[1].Selector)
	}

	if len(limited[1].Children) != 1 || limited[1].Children[0].Selector != "body > main > section" {
		t.Fatalf("expected only first child of main to remain, got %+v", limited[1].Children)
	}
}

func TestHTMLToSemanticTreeCached_RespectsMaxChunks(t *testing.T) {
	htmlStr := `<!DOCTYPE html><html><body>
<header><nav><a href="/">Home</a></nav></header>
<main>
	<section><p>One</p></section>
	<section><p>Two</p></section>
	<section><p>Three</p></section>
</main>
<footer><p>Footer</p></footer>
</body></html>`

	cfg := &PipelineConfig{
		MaxChunks:        2,
		MaxConcurrentLLM: 2,
	}

	tree, stats, err := HTMLToSemanticTreeCached(context.Background(), htmlStr, "https://example.com", cfg)
	if err != nil {
		t.Fatalf("HTMLToSemanticTreeCached failed: %v", err)
	}

	if tree == nil || len(tree.RootNodes) != 1 {
		t.Fatalf("expected one root node, got %+v", tree)
	}

	if stats.TotalChunks > 2 {
		t.Fatalf("expected TotalChunks <= 2, got %d", stats.TotalChunks)
	}

	if len(tree.RootNodes[0].Children) > 2 {
		t.Fatalf("expected root children <= 2, got %d", len(tree.RootNodes[0].Children))
	}
}

func TestExtractInteractiveElements(t *testing.T) {
	htmlStr := `<!DOCTYPE html>
<html>
<body>
	<nav>
		<a href="/">Home</a>
		<a href="/about" aria-label="About Us">About</a>
	</nav>
	<main>
		<form>
			<input type="text" name="search" placeholder="Search...">
			<button type="submit">Submit</button>
		</form>
		<select name="options">
			<option>Option 1</option>
			<option>Option 2</option>
		</select>
		<textarea name="comments"></textarea>
	</main>
</body>
</html>`

	elements := extractInteractiveElements(htmlStr)

	hasATag := false
	hasInput := false
	hasButton := false
	hasSelect := false
	hasTextarea := false

	for _, el := range elements {
		switch el.Tag {
		case "a":
			hasATag = true
		case "input":
			hasInput = true
		case "button":
			hasButton = true
		case "select":
			hasSelect = true
		case "textarea":
			hasTextarea = true
		}
	}

	if !hasATag {
		t.Error("expected to find <a> elements")
	}
	if !hasInput {
		t.Error("expected to find <input> elements")
	}
	if !hasButton {
		t.Error("expected to find <button> elements")
	}
	if !hasSelect {
		t.Error("expected to find <select> elements")
	}
	if !hasTextarea {
		t.Error("expected to find <textarea> elements")
	}
}

func TestIsGridNode(t *testing.T) {
	gridHTMLStr := `<div>
		<div class="item">1</div>
		<div class="item">2</div>
		<div class="item">3</div>
		<div class="item">4</div>
		<div class="item">5</div>
	</div>`

	gridDoc, err := html.Parse(strings.NewReader(gridHTMLStr))
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	gridParent := findElement(gridDoc, "div")
	if gridParent == nil {
		t.Fatal("could not find parent div")
	}

	if !isGridNode(gridParent) {
		t.Error("expected isGridNode to return true for uniform children")
	}

	singleHTMLStr := `<div><span>only one</span></div>`
	singleDoc, err := html.Parse(strings.NewReader(singleHTMLStr))
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	singleParent := findElement(singleDoc, "div")
	if isGridNode(singleParent) {
		t.Error("expected isGridNode to return false for single child")
	}
}

func TestResolveURL(t *testing.T) {
	tests := []struct {
		src      string
		pageURL  string
		expected string
	}{
		{"https://cdn.example.com/image.png", "https://example.com", "https://cdn.example.com/image.png"},
		{"//cdn.example.com/image.png", "https://example.com", "https://cdn.example.com/image.png"},
		{"/images/photo.jpg", "https://example.com", "https://example.com/images/photo.jpg"},
		{"photo.jpg", "https://example.com", "https://example.com/photo.jpg"},
	}

	for _, tt := range tests {
		got := resolveURL(tt.src, tt.pageURL)
		if got != tt.expected {
			t.Errorf("resolveURL(%q, %q) = %q, want %q", tt.src, tt.pageURL, got, tt.expected)
		}
	}
}

func TestSumTokenCounts(t *testing.T) {
	nodes := []SemanticNode{
		{TokenCount: 10},
		{TokenCount: 20},
		{TokenCount: 5},
	}

	total := sumTokenCounts(nodes)
	if total != 35 {
		t.Errorf("expected 35, got %d", total)
	}
}

func TestSumSubtreeTokenCounts(t *testing.T) {
	nodes := []SemanticNode{
		{SubtreeTokenCount: 100},
		{SubtreeTokenCount: 200},
		{SubtreeTokenCount: 50},
	}

	total := sumSubtreeTokenCounts(nodes)
	if total != 350 {
		t.Errorf("expected 350, got %d", total)
	}
}

func TestCollectSummaries(t *testing.T) {
	nodes := []SemanticNode{
		{
			Summary: "Nav section",
			Children: []SemanticNode{
				{Summary: "Home link"},
				{Summary: "About link"},
			},
		},
		{
			Summary: "Main content",
			Children: []SemanticNode{
				{
					Summary: "Product grid",
					Children: []SemanticNode{
						{Summary: "Product 1"},
						{Summary: "Product 2"},
					},
				},
			},
		},
	}

	summaries := collectSummaries(nodes)

	// Just verify summaries are collected in depth-first order
	if len(summaries) == 0 {
		t.Fatal("expected some summaries")
	}
	if summaries[0] != "Nav section" {
		t.Errorf("first summary = %q, want %q", summaries[0], "Nav section")
	}
}

// MockLLM for testing compression pipeline
type testLLMClient struct { //nolint:unused
	mu        sync.Mutex
	callCount int
}

func (m *testLLMClient) Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error) { //nolint:unused
	m.mu.Lock()
	m.callCount++
	m.mu.Unlock()
	return `{"summary": "Mock summary for testing", "is_dynamic": false, "stable": true, "element_descriptions": ["Mock action"]}`, nil
}

func (m *testLLMClient) CompleteJSON(ctx context.Context, systemPrompt, userPrompt string, v interface{}) error { //nolint:unused
	response := map[string]interface{}{
		"summary":              "Mock summary",
		"is_dynamic":           false,
		"stable":               true,
		"element_descriptions": []string{"Mock action"},
	}
	data, _ := json.Marshal(response) //nolint:errchkjson
	return json.Unmarshal(data, v)
}

func (m *testLLMClient) WithCompressModel(model string) *testLLMClient { return m } //nolint:unused
func (m *testLLMClient) WithVisionModel(model string) *testLLMClient   { return m } //nolint:unused
