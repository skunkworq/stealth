package semantic

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestIntegration_ParseHTML(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <title>Test Page</title>
</head>
<body>
    <header>
        <nav>
            <a href="/">Home</a>
            <a href="/products">Products</a>
            <a href="/cart">Cart</a>
        </nav>
    </header>
    <main>
        <h1>Product Title</h1>
        <div class="price">$99.99</div>
        <form action="/cart/add" method="POST">
            <input type="number" name="quantity" value="1">
            <button type="submit">Add to Cart</button>
        </form>
    </main>
    <footer>
        <a href="/privacy">Privacy Policy</a>
    </footer>
</body>
</html>`

	t.Run("clean_and_chunk", func(t *testing.T) {
		cleanHTML, doc, err := cleanAndParseHTML(html)
		if err != nil {
			t.Fatalf("cleanAndParseHTML failed: %v", err)
		}

		t.Logf("Cleaned: %d bytes → %d bytes", len(html), len(cleanHTML))

		chunks := chunkDOM(doc, "https://example.com/test")
		t.Logf("Chunks: %d", len(chunks))
		for i, c := range chunks {
			t.Logf("  %d: %s (%d bytes)", i, c.Tag, len(c.HTML))
		}
	})

	t.Run("interactive_elements", func(t *testing.T) {
		elements := extractInteractiveElements(html)
		t.Logf("Interactive: %d", len(elements))

		byTag := make(map[string]int)
		for _, el := range elements {
			byTag[el.Tag]++
		}
		for tag, count := range byTag {
			t.Logf("  %s: %d", tag, count)
		}

		if byTag["a"] < 4 {
			t.Errorf("Expected at least 4 links, got %d", byTag["a"])
		}
		if byTag["button"] < 1 {
			t.Errorf("Expected at least 1 button, got %d", byTag["button"])
		}
	})

	t.Run("token_estimation", func(t *testing.T) {
		tokens := EstimateTokens(html)
		t.Logf("Estimated tokens: %d", tokens)
		if tokens == 0 {
			t.Error("Expected non-zero tokens")
		}
	})

	t.Run("cache_roundtrip", func(t *testing.T) {
		ctx := context.Background()
		cache, err := NewCacheStore(ctx, "")
		if err != nil {
			t.Fatalf("NewCacheStore: %v", err)
		}
		defer cache.Close()

		testHash := ContentHash("test content for cache")
		testNode := &SemanticNode{
			ID:         "test-node",
			Summary:    "Test summary",
			TokenCount: 42,
		}

		if err := cache.PutChunk(ctx, testHash, testNode); err != nil {
			t.Fatalf("PutChunk: %v", err)
		}

		retrieved, err := cache.GetChunk(ctx, testHash)
		if err != nil {
			t.Fatalf("GetChunk: %v", err)
		}

		if retrieved.ID != testNode.ID {
			t.Errorf("Expected ID %s, got %s", testNode.ID, retrieved.ID)
		}
		if retrieved.Summary != testNode.Summary {
			t.Errorf("Expected Summary %s, got %s", testNode.Summary, retrieved.Summary)
		}

		t.Logf("Cache roundtrip OK: %s (%d tokens)", retrieved.ID, retrieved.TokenCount)
	})

	t.Run("tree_operations", func(t *testing.T) {
		tree := &SemanticTree{
			URL:   "https://example.com/test",
			Title: "Test Page",
			RootNodes: []SemanticNode{
				{
					ID:         "n1",
					Summary:    "Navigation header",
					TokenCount: 15,
					Actions: []Action{
						{Type: ActionClick, Selector: "nav a", Description: "Navigate"},
					},
				},
				{
					ID:         "n2",
					Summary:    "Main content with form",
					TokenCount: 80,
					Children: []SemanticNode{
						{ID: "n2-1", Summary: "Price display", TokenCount: 20},
						{ID: "n2-2", Summary: "Add to cart form", TokenCount: 30},
					},
				},
			},
		}

		tokens := tree.CompressedTokenCount
		t.Logf("Tree tokens: %d", tokens)

		found := tree.FindNode("n2-1")
		if found == nil {
			t.Error("Expected to find node n2-1")
		} else {
			t.Logf("Found node: %s", found.ID)
		}

		path := tree.AncestorPath("n2-1")
		t.Logf("Path to n2-1: %v", path)
	})
}

func TestIntegration_URLFetch(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping URL fetch")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", "https://example.com", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Skipf("Network error: %v", err)
	}
	defer resp.Body.Close()

	t.Logf("Fetched example.com: %d", resp.StatusCode)
}
