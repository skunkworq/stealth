package main

import (
	"context"
	"fmt"

	semantic "github.com/skunkworq/stealth/brws/content/understand"
	"github.com/skunkworq/stealth/brws/content/understand/index"
)

func runIndexMode(urls []string, query string, k int) error {
	ctx := context.Background()

	config, err := semantic.NewConfigFromEnv()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	cache, err := semantic.NewCacheStore(ctx, "")
	if err != nil {
		return fmt.Errorf("cache: %w", err)
	}
	defer func() { _ = cache.Close() }()

	embedder := config.EmbeddingClient
	vectorIndex := index.NewVectorIndex(embedder)

	fmt.Printf("Indexing %d URLs...\n", len(urls))
	for i, url := range urls {
		tree, _, err := semantic.HTMLToSemanticTreeCached(ctx, "", url, config)
		if err != nil {
			fmt.Printf("  [%d] ERROR: %v\n", i+1, err)
			continue
		}

		if err := vectorIndex.AddTree(ctx, tree); err != nil {
			fmt.Printf("  [%d] INDEX ERROR: %v\n", i+1, err)
			continue
		}
		fmt.Printf("  [%d] %s - %d nodes\n", i+1, url, len(tree.RootNodes))
	}

	stats := vectorIndex.Stats()
	fmt.Printf("\nIndex: %d nodes across %d URLs\n", stats.TotalNodes, stats.UniqueURLs)

	if query != "" {
		fmt.Printf("\nSearching for: %q (top %d)\n", query, k)
		results, err := vectorIndex.Search(ctx, query, k)
		if err != nil {
			return fmt.Errorf("search: %w", err)
		}

		for i, r := range results {
			fmt.Printf("\n[%d] Score: %.3f\n", i+1, r.Score)
			fmt.Printf("  URL: %s\n", r.URL)
			fmt.Printf("  Summary: %s\n", r.Content)
		}
	}

	return nil
}

func runApp(urls []string, budget uint32) error {
	ctx := context.Background()

	config, err := semantic.NewConfigFromEnv()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	graph := semantic.NewPageGraph()

	fmt.Printf("Building semantic graph for %d URLs...\n", len(urls))
	for _, url := range urls {
		tree, _, err := semantic.HTMLToSemanticTreeCached(ctx, "", url, config)
		if err != nil {
			fmt.Printf("ERROR %s: %v\n", url, err)
			continue
		}

		graph.AddPage(tree)
		fmt.Printf("  ✓ %s (%d tokens → %d compressed)\n",
			url, tree.FullTokenCount, tree.CompressedTokenCount)
	}

	stats := graph.Stats()
	fmt.Printf("\n%v\n", stats)

	hubs := graph.GetHubPages(5)
	fmt.Printf("\nTop hub pages:\n")
	for i, p := range hubs {
		fmt.Printf("  [%d] %s (in: %d, out: %d)\n", i+1, p.URL, p.Incoming, p.Outgoing)
	}

	return nil
}
