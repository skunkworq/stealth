//go:build ignore
// +build ignore

package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/skunkworq/stealth/brws/browser/engine"
	_ "github.com/skunkworq/stealth/brws/browser/engine/browser/chromium"
	_ "github.com/skunkworq/stealth/brws/browser/engine/browser/chromium/stealth"
	_ "github.com/skunkworq/stealth/brws/browser/engine/http/native"
	"github.com/skunkworq/stealth/brws/content/semantic"
)

func main() {
	urls := []string{
		"https://httpbin.org/html",
		"https://httpbin.org/links/10",
		"https://en.wikipedia.org/wiki/Go_(programming_language)",
		"https://example.com",
	}

	fmt.Println("=== Testing with Chromium-Stealth Engine ===")
	fmt.Println("Using Chrome via CDP with stealth flags")
	fmt.Println()

	// Test with chromium-stealth engine
	eng, err := engine.New("chromium-stealth", engine.Options{
		Headless:       true,
		ExecutablePath: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		Timeout:        90 * time.Second,
	})
	if err != nil {
		log.Fatalf("Failed to create native engine: %v", err)
	}
	defer eng.Close()

	fmt.Printf("%-40s %10s %10s %10s\n", "URL", "Status", "Nodes", "Actions")
	fmt.Println(strings.Repeat("-", 75))

	for _, url := range urls {
		resp, err := eng.Do(context.Background(), &engine.Request{
			URL:               url,
			Timeout:           60 * time.Second,
			WaitForNavigation: true,
			WaitForSelector:   "body",
		})
		if err != nil {
			fmt.Printf("%-40s ERROR: %v\n", url, err)
			continue
		}

		// Parse semantic tree
		config := &semantic.PipelineConfig{
			MaxChunks:        50,
			MaxConcurrentLLM: 0,
		}
		tree, stats, _ := semantic.HTMLToSemanticTreeCached(
			context.Background(), string(resp.Body), url, config)

		nodeCount := 0
		actionCount := 0
		if tree != nil {
			nodeCount = len(tree.AllNodes())
			for _, n := range tree.AllNodes() {
				actionCount += len(n.Actions)
			}
		}

		fmt.Printf("%-40s %10d %10d %10d\n", url, resp.Status, nodeCount, actionCount)

		// Check for Cloudflare challenge
		if strings.Contains(string(resp.Body), "Just a moment") || strings.Contains(string(resp.Body), "cloudflare") {
			log.Printf("  WARNING: Cloudflare challenge detected in response!")
			log.Printf("  Body preview: %s", string(resp.Body)[:200])
		}

		if tree != nil && strings.Contains(url, "wikipedia") {
			if stats != nil && stats.FullTreeTokens > 0 {
				ratio := float64(stats.CompressedTokens) / float64(stats.FullTreeTokens) * 100
				log.Printf("Wikipedia: %d -> %d tokens (%.1f%% compression)",
					stats.FullTreeTokens, stats.CompressedTokens, ratio)
			}
		}
	}

	fmt.Println()
	fmt.Println("Done!")
}

func countActions(tree *semantic.SemanticTree) int {
	count := 0
	for _, n := range tree.AllNodes() {
		count += len(n.Actions)
	}
	return count
}
