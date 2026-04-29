package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/skunkworq/stealth/brws/content/semantic"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: test_semantic <url>")
		fmt.Println("\nTests semantic extraction against a live URL")
		os.Exit(1)
	}

	testURL := os.Args[1]
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	fmt.Printf("Testing semantic extraction against: %s\n\n", testURL)

	// Step 1: Fetch
	fmt.Println("Step 1: Fetching HTML...")
	client := &http.Client{Timeout: 30 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	html := string(body)
	fmt.Printf("✓ Fetched %d bytes (status %d)\n\n", len(html), resp.StatusCode)

	// Step 2: Token estimation
	fmt.Println("Step 2: Token estimation...")
	tokens := semantic.EstimateTokens(html)
	fmt.Printf("✓ Estimated tokens: %d\n\n", tokens)

	// Step 3: Content hash
	fmt.Println("Step 3: Content hashing...")
	hash := semantic.ContentHash(html)
	fmt.Printf("✓ Content hash: %s...\n\n", hash[:16])

	// Step 4: Domain extraction
	fmt.Println("Step 4: Domain extraction...")
	domain := semantic.ExtractDomain(testURL)
	fmt.Printf("✓ Domain: %s\n\n", domain)

	// Step 5: Cache operations
	fmt.Println("Step 5: Cache operations...")
	cache, err := semantic.NewCacheStore(ctx, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cache error: %v\n", err)
		os.Exit(1)
	}
	defer cache.Close()

	testNode := &semantic.SemanticNode{
		ID:         "test-node",
		Summary:    "Test node from URL extraction",
		TokenCount: 100,
	}
	if err := cache.PutChunk(ctx, hash, testNode); err != nil {
		fmt.Fprintf(os.Stderr, "PutChunk error: %v\n", err)
	} else {
		retrieved, err := cache.GetChunk(ctx, hash)
		if err != nil {
			fmt.Fprintf(os.Stderr, "GetChunk error: %v\n", err)
		} else if retrieved != nil {
			fmt.Printf("✓ Cache roundtrip: %s (%d tokens)\n\n", retrieved.ID, retrieved.TokenCount)
		}
	}

	// Step 6: Build semantic tree (requires LLM API key)
	fmt.Println("Step 6: Building semantic tree...")
	config := &semantic.PipelineConfig{
		Cache:            cache,
		MaxDepth:         4,
		MinContentLen:    100,
		MaxChunks:        200,
		MaxConcurrentLLM: 10,
	}

	apiKey := os.Getenv("OPENROUTER_API_KEY")
	if apiKey != "" {
		llmClient := semantic.NewLLMClient(apiKey)
		embedClient := semantic.NewEmbeddingClient(apiKey)
		config.LLMClient = llmClient
		config.EmbeddingClient = embedClient
		config.VisionClient = semantic.NewVisionClient(llmClient)
		fmt.Println("  Using LLM API key for compression")
	} else {
		fmt.Println("  No LLM API key - skipping compression (set OPENROUTER_API_KEY)")
	}

	start := time.Now()
	tree, stats, err := semantic.HTMLToSemanticTree(ctx, html, testURL, config)
	elapsed := time.Since(start)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Tree error: %v\n", err)
	} else if tree != nil {
		fmt.Printf("✓ Tree built in %v\n", elapsed)
		fmt.Printf("  Title: %s\n", tree.Title)
		fmt.Printf("  Domain: %s\n", tree.Domain)
		fmt.Printf("  Roots: %d nodes\n", len(tree.RootNodes))
		fmt.Printf("  Full tokens: %d\n", tree.FullTokenCount)
		fmt.Printf("  Compressed: %d tokens\n", tree.CompressedTokenCount)
		if tree.FullTokenCount > 0 {
			ratio := float64(tree.CompressedTokenCount) / float64(tree.FullTokenCount) * 100
			saved := tree.FullTokenCount - tree.CompressedTokenCount
			fmt.Printf("  Compression: %.1f%% (%d tokens saved)\n", ratio, saved)
		}

		// Count interactive elements
		interactive := 0
		for _, root := range tree.RootNodes {
			interactive += countActions(&root)
		}
		fmt.Printf("  Interactive: %d elements\n", interactive)

		if stats != nil {
			fmt.Printf("\n  Compression stats:\n")
			fmt.Printf("    Raw HTML: %d bytes\n", stats.RawHTMLBytes)
			fmt.Printf("    Clean: %d bytes\n", stats.CleanHTMLBytes)
			fmt.Printf("    Chunks: %d total, %d cached, %d LLM\n",
				stats.TotalChunks, stats.ChunksCached, stats.ChunksLLMCompressed)
		}
	}

	// Step 7: Extract form schemas
	fmt.Println("\nStep 7: Extracting form schemas...")
	forms := semantic.ExtractFormSchemas(html)
	if len(forms) > 0 {
		fmt.Printf("✓ Found %d forms\n", len(forms))
		for i, form := range forms {
			fmt.Printf("  Form %d: [%s %s] %d fields\n", i+1, form.Method, form.Action, len(form.Fields))
			for _, field := range form.Fields {
				req := ""
				if field.Required {
					req = " [req]"
				}
				fmt.Printf("    - %s (%s)%s\n", field.Name, field.Type, req)
			}
		}
	} else {
		fmt.Println("  No forms found")
	}

	// Summary
	fmt.Println("\n========================================")
	fmt.Println("Test Summary:")
	fmt.Println("========================================")
	fmt.Printf("✓ Fetch:         %d bytes\n", len(html))
	fmt.Printf("✓ Tokens:        %d\n", tokens)
	fmt.Printf("✓ Hash:          %s...\n", hash[:16])
	fmt.Printf("✓ Cache:         OK\n")
	if tree != nil {
		fmt.Printf("✓ Tree:          %d roots, %d tokens\n", len(tree.RootNodes), tree.CompressedTokenCount)
	}
	fmt.Println("========================================")

	// JSON output
	result := map[string]interface{}{
		"url":           testURL,
		"fetched_bytes": len(html),
		"status":        resp.StatusCode,
		"tokens":        tokens,
		"content_hash":  hash,
		"domain":        domain,
		"cache_works":   true,
	}

	if tree != nil {
		result["tree_roots"] = len(tree.RootNodes)
		result["title"] = tree.Title
		result["full_tokens"] = tree.FullTokenCount
		result["compressed_tokens"] = tree.CompressedTokenCount
		result["duration_ms"] = elapsed.Milliseconds()
	}

	jsonOut, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println("\nJSON Output:")
	fmt.Println(string(jsonOut))
}

func countActions(node *semantic.SemanticNode) int {
	count := len(node.Actions)
	for i := range node.Children {
		count += countActions(&node.Children[i])
	}
	return count
}
