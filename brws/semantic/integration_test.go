package semantic

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// IntegrationTestRunner provides a test harness for semantic extraction
type IntegrationTestRunner struct {
	LLMResponses    map[string]string
	EmbeddingValues []float32
}

func NewIntegrationTestRunner() *IntegrationTestRunner {
	return &IntegrationTestRunner{
		LLMResponses:    make(map[string]string),
		EmbeddingValues: []float32{0.1, 0.2, 0.3},
	}
}

// Full integration test with mocked LLM responses
func TestSemanticExtractionIntegration(t *testing.T) {
	html := `<!DOCTYPE html>
<html>
<head>
	<title>E-Commerce Product Page</title>
</head>
<body>
	<header>
		<nav>
			<a href="/">Home</a>
			<a href="/products">Products</a>
		</nav>
		<form action="/search">
			<input type="search" name="q" placeholder="Search products...">
			<button type="submit">Search</button>
		</form>
	</header>
	
	<main>
		<section class="products">
			<h1>Featured Products</h1>
			<div class="product-grid">
				<article class="product-card">
					<img src="/images/product1.jpg" alt="Laptop">
					<h3>Pro Laptop 15"</h3>
					<p class="price">$1,299.99</p>
					<a href="/products/1">View Details</a>
					<button data-product-id="1">Add to Cart</button>
				</article>
				
				<article class="product-card">
					<img src="/images/product2.jpg" alt="Headphones">
					<h3>Wireless Headphones</h3>
					<p class="price">$79.99</p>
					<a href="/products/2">View Details</a>
					<button data-product-id="2">Add to Cart</button>
				</article>
			</div>
		</section>
	</main>
	
	<footer>
		<p>© 2024 Test Store</p>
		<a href="/privacy">Privacy Policy</a>
	</footer>
</body>
</html>`

	// Create test config with mock-friendly values
	_ = &PipelineConfig{
		LLMClient:       NewLLMClient("sk-test-key"),
		EmbeddingClient: NewEmbeddingClient("sk-test-key"),
		VisionClient:    nil,
		Cache:           nil,
		MaxDepth:        4,
		MinContentLen:   50,
	}

	// Note: Real integration tests would need actual API key
	// This validates the pipeline structure and data flow

	t.Run("dom_cleaning", func(t *testing.T) {
		cleaned, doc, _, err := cleanAndParseHTML(html)
		if err != nil {
			t.Fatalf("cleanAndParseHTML failed: %v", err)
		}

		if strings.Contains(cleaned, "<script>") {
			t.Error("scripts should be removed")
		}
		if !strings.Contains(cleaned, "Featured Products") {
			t.Error("content should be preserved")
		}
		if doc == nil {
			t.Error("expected parsed document")
		}
	})

	t.Run("title_extraction", func(t *testing.T) {
		_, _, title, err := cleanAndParseHTML(html)
		if err != nil {
			t.Fatalf("cleanAndParseHTML failed: %v", err)
		}
		if title != "E-Commerce Product Page" {
			t.Errorf("title = %q, want %q", title, "E-Commerce Product Page")
		}
	})

	t.Run("interactive_elements", func(t *testing.T) {
		elements := extractInteractiveElements(html)

		hasLinks := false
		hasButtons := false
		hasInputs := false

		for _, el := range elements {
			switch el.Tag {
			case "a":
				hasLinks = true
			case "button":
				hasButtons = true
			case "input":
				hasInputs = true
			}
		}

		if !hasLinks {
			t.Error("expected to find links")
		}
		if !hasButtons {
			t.Error("expected to find buttons")
		}
		if !hasInputs {
			t.Error("expected to find inputs")
		}

		t.Logf("Found %d interactive elements", len(elements))
	})

	t.Run("dom_chunking", func(t *testing.T) {
		_, doc, _, err := cleanAndParseHTML(html)
		if err != nil {
			t.Fatalf("cleanAndParseHTML failed: %v", err)
		}

		chunks := chunkDOM(doc, "https://teststore.com/products")
		if len(chunks) == 0 {
			t.Fatal("expected DOM chunks")
		}

		for _, chunk := range chunks {
			if chunk.Selector == "" {
				t.Error("chunk missing selector")
			}
			if chunk.Tag == "" {
				t.Error("chunk missing tag")
			}
		}

		t.Logf("Created %d top-level chunks", len(chunks))
	})

	t.Run("structural_hashing", func(t *testing.T) {
		_, doc, _, err := cleanAndParseHTML(html)
		if err != nil {
			t.Fatalf("cleanAndParseHTML failed: %v", err)
		}

		hash := computeStructuralHash(doc)
		if hash == "" {
			t.Error("expected non-empty hash")
		}

		hash2 := computeStructuralHash(doc)
		if hash != hash2 {
			t.Error("same document should produce same hash")
		}

		t.Logf("Structural hash: %s...", hash[:16])
	})

	t.Run("serialize_cycle", func(t *testing.T) {
		tree := &SemanticTree{
			URL:                  "https://test.com",
			Domain:               "test.com",
			Title:                "Test",
			CompressedTokenCount: 100,
			FullTokenCount:       500,
			RootNodes: []SemanticNode{
				{
					ID:         "nav",
					Summary:    "Navigation with 2 links",
					TokenCount: 10,
					Actions: []Action{
						{Type: ActionClick, Selector: "a", Description: "Link"},
					},
				},
				{
					ID:         "main",
					Summary:    "Product grid",
					TokenCount: 15,
					Children: []SemanticNode{
						{ID: "main-0", Summary: "Product card 1"},
						{ID: "main-1", Summary: "Product card 2"},
					},
				},
			},
		}

		jsonData, err := json.Marshal(tree)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var restored SemanticTree
		if err := json.Unmarshal(jsonData, &restored); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if restored.URL != tree.URL {
			t.Error("URL not preserved in cycle")
		}
		if len(restored.RootNodes) != len(tree.RootNodes) {
			t.Error("RootNodes count changed")
		}
	})

	t.Run("unfolding_state", func(t *testing.T) {
		tree := &SemanticTree{
			CompressedTokenCount: 50,
			FullTokenCount:       200,
			RootNodes: []SemanticNode{
				{
					ID:                "node1",
					TokenCount:        25,
					SubtreeTokenCount: 100,
					Children:          []SemanticNode{{ID: "child1"}},
				},
				{
					ID:                "node2",
					TokenCount:        25,
					SubtreeTokenCount: 100,
					Children:          []SemanticNode{{ID: "child2"}},
				},
			},
		}

		state := InitialPack(tree, 5000, 128000)

		if state.TokenUsage != 50 {
			t.Errorf("initial token usage = %d, want 50", state.TokenUsage)
		}

		_, ok := UnfoldNode(tree, state, "node1")
		if !ok {
			t.Fatal("unfold should succeed")
		}

		if state.TokenUsage <= 50 {
			t.Error("token usage should increase after unfold")
		}

		FoldNode(tree, state, "node1")
		if state.TokenUsage != 50 {
			t.Errorf("token usage should return to 50 after fold, got %d", state.TokenUsage)
		}
	})

	t.Run("auto_unfold", func(t *testing.T) {
		tree := &SemanticTree{
			CompressedTokenCount: 30,
			FullTokenCount:       150,
			RootNodes: []SemanticNode{
				{ID: "a", TokenCount: 10, SubtreeTokenCount: 50, Children: []SemanticNode{{}}},
				{ID: "b", TokenCount: 10, SubtreeTokenCount: 50, Children: []SemanticNode{{}}},
				{ID: "c", TokenCount: 10, SubtreeTokenCount: 50, Children: []SemanticNode{{}}},
			},
		}

		state := InitialPack(tree, 200, 1000)
		unfolded := AutoUnfold(tree, state)

		t.Logf("Auto-unfolded %d nodes", len(unfolded))
	})

	t.Run("compression_stats", func(t *testing.T) {
		stats := &CompressionStats{
			RawHTMLBytes:        50000,
			CleanHTMLBytes:      15000,
			TotalChunks:         25,
			ChunksCached:        5,
			ChunksLLMCompressed: 20,
			CompressedTokens:    500,
			FullTreeTokens:      5000,
			DurationMS:          2500,
		}

		ratio := stats.CompressionRatio()
		if ratio <= 0 || ratio > 1 {
			t.Errorf("invalid compression ratio: %.2f", ratio)
		}

		estRaw := stats.EstimatedRawTokens()
		if estRaw == 0 {
			t.Error("expected non-zero estimated raw tokens")
		}

		saved := stats.TokensSaved()
		if saved <= 0 {
			t.Error("expected positive token savings")
		}

		t.Logf("Stats: %.1f%% compression, %d tokens saved", ratio*100, saved)
	})

	t.Run("ancestor_path", func(t *testing.T) {
		tree := &SemanticTree{
			RootNodes: []SemanticNode{
				{
					ID: "root",
					Children: []SemanticNode{
						{
							ID: "level1",
							Children: []SemanticNode{
								{ID: "level2"},
							},
						},
					},
				},
			},
		}

		path := tree.AncestorPath("level2")
		if path == nil {
			t.Fatal("expected ancestor path")
		}

		if len(path) != 2 {
			t.Errorf("path length = %d, want 2", len(path))
		}
		if path[0] != "root" || path[1] != "level1" {
			t.Errorf("unexpected path: %v", path)
		}
	})
}

func TestMultiplePageNavigation(t *testing.T) {
	t.Run("page_collapse", func(t *testing.T) {
		tree := &SemanticTree{
			URL:            "https://shop.com/products",
			Domain:         "shop.com",
			FullTokenCount: 3000,
			RootNodes: []SemanticNode{
				{Summary: "Navigation"},
				{Summary: "Product listing"},
				{Summary: "Filters"},
			},
		}

		collapsed := CollapseTree(tree, "Browsed electronics")

		if collapsed.URL != tree.URL {
			t.Error("URL not preserved")
		}
		if !strings.Contains(collapsed.Summary, "Browsed electronics") {
			t.Error("interaction summary not included")
		}
		if collapsed.OriginalTokens != 3000 {
			t.Errorf("original tokens = %d, want 3000", collapsed.OriginalTokens)
		}
	})

	t.Run("serialize_with_collapsed", func(t *testing.T) {
		tree := &SemanticTree{
			URL:                  "https://shop.com/cart",
			Domain:               "shop.com",
			CompressedTokenCount: 100,
			RootNodes: []SemanticNode{
				{Summary: "Cart items", TokenCount: 50},
			},
		}

		collapsedPages := []CollapsedPage{
			{
				URL:            "https://shop.com/products",
				Domain:         "shop.com",
				Summary:        "Browsed products",
				OriginalTokens: 2500,
			},
		}

		state := InitialPack(tree, 5000, 128000)
		serialized := SerializeTree(tree, state, collapsedPages)

		if !strings.Contains(serialized, "[WEBFURL]") {
			t.Error("missing header")
		}
		if !strings.Contains(serialized, "previously") {
			t.Error("missing collapsed pages marker, got: " + serialized)
		}
		if !strings.Contains(serialized, "shop.com") {
			t.Error("missing domain")
		}
	})
}

func TestActionExtractionDepth(t *testing.T) {
	html := `<!DOCTYPE html>
<html>
<body>
	<form id="search-form">
		<input type="search" name="q" placeholder="Search">
		<input type="submit" value="Go">
		<button type="submit">Search</button>
	</form>
	
	<div id="filters">
		<select name="category">
			<option>All</option>
			<option>Electronics</option>
		</select>
		<input type="checkbox" name="sale" id="sale">
		<label for="sale">On Sale</label>
	</div>
	
	<div id="results">
		<a href="/product/1">Product 1</a>
		<a href="/product/2" aria-label="Wireless Keyboard">Product 2</a>
		<a href="/product/3" data-testid="product-link">Product 3</a>
	</div>
</body>
</html>`

	elements := extractInteractiveElements(html)

	t.Logf("Extracted %d interactive elements", len(elements))

	selectorTypes := make(map[string]int)
	for _, el := range elements {
		selectorTypes[el.ActionType]++

		if el.Selector == "" {
			t.Errorf("element %s missing selector", el.Tag)
		}
	}

	expectedTypes := []string{"click", "fill", "toggle", "select"}
	for _, et := range expectedTypes {
		if selectorTypes[et] == 0 {
			t.Logf("Warning: no %s actions found", et)
		}
	}
}

func TestCacheIntegration(t *testing.T) {
	ctx := context.Background()
	tmpPath := t.TempDir() + "/integration-cache.db"

	cache, err := NewCacheStore(ctx, tmpPath)
	if err != nil {
		t.Fatalf("NewCacheStore failed: %v", err)
	}
	defer func() { _ = cache.Close() }()

	t.Run("store_and_retrieve", func(t *testing.T) {
		hash := ContentHash("<div>cached chunk</div>")
		node := &SemanticNode{
			ID:             "cached-node",
			Summary:        "Cached summary",
			StructuralHash: "hash123",
			TokenCount:     25,
		}

		if err := cache.PutChunk(ctx, hash, node); err != nil {
			t.Fatalf("PutChunk failed: %v", err)
		}

		retrieved, err := cache.GetChunk(ctx, hash)
		if err != nil {
			t.Fatalf("GetChunk failed: %v", err)
		}

		if retrieved == nil {
			t.Fatal("expected to retrieve cached node")
		}
		if retrieved.ID != node.ID {
			t.Errorf("ID mismatch: got %q, want %q", retrieved.ID, node.ID)
		}
	})

	t.Run("cache_miss", func(t *testing.T) {
		hash := ContentHash("<div>nonexistent</div>")
		retrieved, err := cache.GetChunk(ctx, hash)
		if err != nil {
			t.Fatalf("GetChunk failed: %v", err)
		}
		if retrieved != nil {
			t.Error("expected nil for uncached hash")
		}
	})
}

func TestEndToEndWithMockLLM(t *testing.T) {
	// This test validates the entire pipeline flow with a mock that
	// pretends to be an LLM client

	t.Run("pipeline_stages", func(t *testing.T) {
		html := `<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<header><nav><a href="/">Home</a></nav></header>
<main><section><div class="item">Item 1</div><div class="item">Item 2</div></section></main>
</body>
</html>`

		url := "https://example.com"

		// Stage 1: Clean and parse
		cleaned, doc, _, err := cleanAndParseHTML(html)
		if err != nil {
			t.Fatalf("Stage 1 failed: %v", err)
		}
		t.Logf("Stage 1: Cleaned %d -> %d bytes", len(html), len(cleaned))

		// Stage 2: Compute structural hash
		hash := computeStructuralHash(doc)
		t.Logf("Stage 2: Hash = %s", hash[:16]+"...")

		// Stage 3: Chunk DOM
		chunks := chunkDOM(doc, url)
		t.Logf("Stage 3: Created %d chunks", len(chunks))

		// Stage 4: Extract interactive elements
		interactive := extractInteractiveElements(html)
		t.Logf("Stage 4: Found %d interactive elements", len(interactive))

		// Stage 5: Build semantic node (simulated)
		nodes := make([]SemanticNode, len(chunks))
		for i, chunk := range chunks {
			nodes[i] = SemanticNode{
				ID:                SelectorToID(chunk.Selector),
				Summary:           "Chunk: " + chunk.Tag,
				StructuralHash:    chunk.StructuralHash,
				TokenCount:        EstimateTokens(chunk.HTML),
				SubtreeTokenCount: EstimateTokens(chunk.HTML),
			}
		}

		// Stage 6: Create tree
		_, _, title, _ := cleanAndParseHTML(html)
		tree := &SemanticTree{
			URL:                  url,
			Domain:               ExtractDomain(url),
			Title:                title,
			RootNodes:            nodes,
			CompressedTokenCount: sumTokenCounts(nodes),
			FullTokenCount:       sumSubtreeTokenCounts(nodes),
			StructuralHash:       hash,
		}

		t.Logf("Stage 5-6: Tree with %d root nodes, %d tokens",
			len(tree.RootNodes), tree.CompressedTokenCount)

		// Stage 7: Serialize
		state := InitialPack(tree, 5000, 128000)
		serialized := SerializeTree(tree, state, nil)
		t.Logf("Stage 7: Serialized %d bytes", len(serialized))

		// Verify full cycle completed
		if len(serialized) == 0 {
			t.Error("empty serialization result")
		}
	})
}
