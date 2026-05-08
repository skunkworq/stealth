// Package agentic provides a directed-graph execution engine for LLM-centric
// web scraping. It is modeled after the ScrapeGraphAI architecture and operates
// independently from the browser-agent system in brws/content/agent.
//
// # Architecture
//
// The system is built around three core abstractions:
//
//   - Node: a processing unit that reads from and writes to a shared State map.
//   - BaseGraph: the execution engine that runs nodes in a loop, passing a
//     mutable State dictionary from one node to the next.
//   - Pipeline: scaffolding that wires nodes into concrete scrapers such as
//     SmartScraperGraph and SearchGraph.
//
// This design makes scraping workflows composable, testable, and easy to extend
// without touching the existing stealth or agent packages.
//
// # Quick Start
//
// Basic usage with the existing semantic LLM client (OpenRouter):
//
//	package main
//
//	import (
//	    "context"
//	    "fmt"
//	    "log"
//
//	    "github.com/skunkworq/stealth/brws/content/agentic"
//	    "github.com/skunkworq/stealth/brws/content/semantic"
//	)
//
//	func main() {
//	    llm := agentic.NewSemanticLLM(semantic.NewLLMClient(os.Getenv("OPENROUTER_API_KEY")))
//
//	    graph, err := agentic.NewSmartScraperGraph(
//	        "Extract all product names and prices",
//	        "https://example.com/products",
//	        map[string]interface{}{},
//	        nil, // schema
//	        llm,
//	    )
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//
//	    state, info, err := graph.Run(context.Background())
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//
//	    fmt.Printf("Answer: %+v\n", state["answer"])
//	    fmt.Printf("Execution: %+v\n", info)
//	}
//
// # Graph Types
//
// SmartScraperGraph — the canonical pipeline (Fetch → Parse → GenerateAnswer).
// Supports optional reasoning and re-attempt nodes via config flags:
//
//	config := map[string]interface{}{
//	    "reasoning": true,   // inject a ReasoningNode before extraction
//	    "reattempt": true,   // retry with regenerated context on NA/empty
//	    "html_mode": true,   // skip ParseNode, feed raw HTML to LLM
//	}
//
// SearchGraph — autonomous search-to-scrape (SearchInternet → GraphIterator → MergeAnswers).
//
// # Key Nodes
//
//   - FetchNode: ingests URLs (HTTP) or local files.
//   - ParseNode: HTML-to-text conversion and token-aware chunking.
//   - GenerateAnswerNode: direct extraction (single chunk) or map-reduce
//     (parallel per-chunk LLM calls + merge synthesis).
//   - ConditionalNode: runtime branching (e.g. retry on empty/NA answer).
//   - ReasoningNode: pre-processes the prompt against a JSON schema.
//   - MergeAnswersNode: synthesizes multiple partial answers.
//   - SearchInternetNode: generates a search query via LLM and scrapes
//     DuckDuckGo results.
//   - GraphIteratorNode: parallel multi-URL scraping with semaphore control.
//
// # LLM Integration
//
// The package defines a minimal LLM interface:
//
//	type LLM interface {
//	    Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error)
//	    CompleteJSON(ctx context.Context, systemPrompt, userPrompt string, v interface{}) error
//	}
//
// A wrapper around the existing semantic.LLMClient is provided out of the box:
//
//	llm, err := agentic.NewLLMFromEnv() // reads OPENROUTER_API_KEY
//
// Custom providers can be plugged in by implementing the LLM interface.
//
// # State Machine
//
// Execution flow:
//
//	1. Initial state is seeded with user_prompt and url/local_dir.
//	2. BaseGraph runs a while-loop, executing the current node and routing
//	   to the next via edges or conditional jumps.
//	3. Each node reads required keys via declarative boolean expressions
//	   (e.g. "user_prompt & (parsed_doc | doc)").
//	4. When there is no next node, the graph returns the final state and
//	   per-node execution telemetry.
//
// # Independence Guarantee
//
// This package has no imports into brws/content/agent or brws/browser/engine.
// It relies only on brws/content/semantic for the default LLM client and
// standard library packages for fetching and parsing. This ensures the existing
// agentic (CDP-based browser agent) and stealth infrastructure remain untouched.
package agentic
