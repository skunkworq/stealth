package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	semantic "github.com/skunkworq/stealth/brws/content/understand"
	"github.com/skunkworq/stealth/brws/crawl/spider"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: semanticcrawl <start-url> [max-depth] [output.json]")
		fmt.Println("  Crawls pages building semantic trees")
		os.Exit(1)
	}

	startURL := os.Args[1]
	maxDepth := 2
	if len(os.Args) > 2 {
		fmt.Sscanf(os.Args[2], "%d", &maxDepth)
	}
	outputFile := "semantic_crawl.json"
	if len(os.Args) > 3 {
		outputFile = os.Args[3]
	}

	ctx := context.Background()

	config, err := semantic.NewConfigFromEnv()
	if err != nil {
		log.Fatalf("Config error: %v", err)
	}

	cache, err := semantic.NewCacheStore(ctx, "")
	if err != nil {
		log.Fatalf("Cache error: %v", err)
	}
	defer func() { _ = cache.Close() }()

	config.Cache = cache

	fmt.Printf("Starting semantic crawl: %s (max depth: %d)\n", startURL, maxDepth)
	fmt.Printf("Output will be written to: %s\n\n", outputFile)

	start := time.Now()

	semSpider := spider.NewSemanticSpider(
		"semantic-crawler",
		[]string{startURL},
		config,
		spider.WithSemanticMaxDepth(maxDepth),
		spider.WithOnPage(func(url string, tree *semantic.SemanticTree) {
			fmt.Printf("✓ %s\n", url)
			fmt.Printf("  Title: %s\n", tree.Title)
			fmt.Printf("  Tokens: %d → %d (%.1f%% compression)\n",
				tree.FullTokenCount, tree.CompressedTokenCount,
				(1-float64(tree.CompressedTokenCount)/float64(tree.FullTokenCount))*100)
			interactive := 0
			for _, root := range tree.RootNodes {
				interactive += countInteractiveNodes(&root)
			}
			fmt.Printf("  Interactive: %d elements\n", interactive)
		}),
	)

	crawler := spider.NewCrawler(
		spider.NewSpider("semantic", semSpider.Start(), semSpider.Parse),
		spider.WithMaxDepth(maxDepth),
		spider.WithConcurrentRequests(4),
		spider.WithDownloadDelay(500*time.Millisecond),
	)

	if err := crawler.Run(); err != nil {
		log.Printf("Crawl error: %v", err)
	}

	stats := semSpider.GetStats()
	duration := time.Since(start)

	fmt.Printf("\n========================================\n")
	fmt.Printf("Crawl Complete\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Pages visited:    %d\n", stats.PagesVisited)
	fmt.Printf("Total tokens:     %d\n", stats.TotalTokens)
	fmt.Printf("Compressed:       %d\n", stats.CompressedTokens)
	fmt.Printf("Tokens saved:      %d (%.1f%%)\n",
		stats.TokensSaved(), (1-stats.CompressionRatio())*100)
	fmt.Printf("Interactive found: %d\n", stats.InteractiveFound)
	fmt.Printf("LLM calls:        %d\n", stats.LLMCalls)
	fmt.Printf("Cache hits:        %d\n", stats.CacheHits)
	fmt.Printf("Errors:           %d\n", stats.Errors)
	fmt.Printf("Duration:         %v\n", duration.Round(time.Millisecond))
	fmt.Printf("========================================\n")

	trees := semSpider.GetAllSemanticTrees()
	data, _ := json.MarshalIndent(trees, "", "  ")
	if err := os.WriteFile(outputFile, data, 0o644); err != nil {
		log.Printf("Error writing output: %v", err)
	} else {
		fmt.Printf("Results saved to: %s\n", outputFile)
	}
}

func countInteractiveNodes(node *semantic.SemanticNode) int {
	count := len(node.Actions)
	for i := range node.Children {
		count += countInteractiveNodes(&node.Children[i])
	}
	return count
}
