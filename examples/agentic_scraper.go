//go:build ignore

// Example: agentic_scraper demonstrates the ScrapeGraphAI-style graph execution
// engine operating independently from the CDP-based agent system.
//
// Run with:
//
//	OPENROUTER_API_KEY=sk-... go run examples/agentic_scraper.go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/skunkworq/stealth/brws/content/scrapegraph"
	"github.com/skunkworq/stealth/brws/content/understand"
)

func main() {
	ctx := context.Background()

	// Initialize LLM via the existing semantic pipeline (OpenRouter).
	key := os.Getenv("OPENROUTER_API_KEY")
	if key == "" {
		log.Fatal("OPENROUTER_API_KEY required")
	}
	llm := understand.NewLLMClient(key)

	// -------------------------------------------------------------------------
	// Example 1: SmartScraperGraph — single-page extraction
	// -------------------------------------------------------------------------
	fmt.Println("=== SmartScraperGraph ===")
	graph, err := pipeline.NewSmartScraperGraph(
		"Extract the page title and all heading texts as a JSON object with keys 'title' and 'headings'.",
		"https://example.com",
		map[string]interface{}{
			// Optional flags:
			// "reasoning": true,
			// "reattempt": true,
			// "html_mode": true,
		},
		nil, // optional Pydantic-like schema
		llm,
	)
	if err != nil {
		log.Fatalf("build graph: %v", err)
	}

	state, info, err := graph.Run(ctx)
	if err != nil {
		log.Fatalf("run graph: %v", err)
	}

	fmt.Printf("Answer: %+v\n", state["answer"])
	for _, i := range info {
		fmt.Printf("  %s: %v\n", i.NodeName, i.ExecTime)
	}

	// -------------------------------------------------------------------------
	// Example 2: SearchGraph — search then scrape top results
	// -------------------------------------------------------------------------
	fmt.Println("\n=== SearchGraph ===")
	searchGraph, err := pipeline.NewSearchGraph(
		"What are the latest features in Go 1.24?",
		map[string]interface{}{
			"max_results": 3,
		},
		nil,
		llm,
	)
	if err != nil {
		log.Fatalf("build search graph: %v", err)
	}

	state, info, err = searchGraph.Run(ctx)
	if err != nil {
		log.Fatalf("run search graph: %v", err)
	}

	fmt.Printf("Answer: %+v\n", state["answer"])
	for _, i := range info {
		fmt.Printf("  %s: %v\n", i.NodeName, i.ExecTime)
	}
}
