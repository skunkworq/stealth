package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/skunkworq/stealth/brws/browser/engine"
	_ "github.com/skunkworq/stealth/brws/browser/engine/http/native"
	semantic "github.com/skunkworq/stealth/brws/content/understand"
)

var (
	url           = flag.String("url", "", "URL to extract from (required)")
	output        = flag.String("output", "", "Output file (default stdout)")
	format        = flag.String("format", "tree", "Output format: tree, json, serialized, stats")
	cachePath     = flag.String("cache", "", "Cache database path (default ~/.semantic/cache.db)")
	apiKey        = flag.String("api-key", "", "OpenRouter API key (or env OPENROUTER_API_KEY)")
	compressModel = flag.String("model", "openai/gpt-oss-120b", "LLM model for compression")
	embedModel    = flag.String("embed-model", "qwen/qwen3-embedding-8b", "Embedding model")
	visionModel   = flag.String("vision-model", "google/gemini-2.5-flash", "Vision model")
	timeout       = flag.Duration("timeout", 5*time.Minute, "Request timeout")
	initialBudget = flag.Uint("initial-budget", 5000, "Initial token budget per page")
	maxBudget     = flag.Uint("max-budget", 128000, "Maximum token budget")
	noCache       = flag.Bool("no-cache", false, "Disable caching")
	pretty        = flag.Bool("pretty", true, "Pretty JSON output")
	engineName    = flag.String("engine", "native", "Engine to use for fetching HTML")
	stealth       = flag.Bool("stealth", true, "Enable stealth mode for engine")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: semantic [options]

Semantic web extraction tool using LLM-based hierarchical compression.

Examples:
  # Basic extraction with semantic tree
  semantic --url https://example.com --format tree

  # JSON output with caching
  semantic --url https://example.com --format json --cache ./cache.db

  # Full budget usage
  semantic --url https://airbnb.com/s/Mountain-View/homes --initial-budget 8000

Options:
`)
		flag.PrintDefaults()
	}

	flag.Parse()

	if *url == "" {
		fmt.Fprintf(os.Stderr, "Error: --url is required\n")
		flag.Usage()
		os.Exit(1)
	}

	key := *apiKey
	if key == "" {
		key = os.Getenv("OPENROUTER_API_KEY")
	}
	if key == "" {
		fmt.Fprintf(os.Stderr, "Error: OpenRouter API key required (set --api-key or OPENROUTER_API_KEY)\n")
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	llmClient := semantic.NewLLMClient(key).WithCompressModel(*compressModel).WithVisionModel(*visionModel)
	embedClient := semantic.NewEmbeddingClient(key).WithModel(*embedModel)

	var cache *semantic.CacheStore
	if !*noCache {
		var err error
		cache, err = semantic.NewCacheStore(ctx, *cachePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to initialize cache: %v\n", err)
		}
		defer cache.Close()
	}

	eng, err := engine.New(*engineName, engine.Options{
		Stealth: *stealth,
		Timeout: 30 * time.Second,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating engine: %v\n", err)
		os.Exit(1)
	}
	defer eng.Close()

	config := &semantic.PipelineConfig{
		LLMClient:       llmClient,
		EmbeddingClient: embedClient,
		Cache:           cache,
		MaxDepth:        8,
		MinContentLen:   100,
	}

	fmt.Fprintf(os.Stderr, "Fetching %s...\n", *url)
	resp, err := eng.Do(ctx, &engine.Request{
		Method:  "GET",
		URL:     *url,
		Timeout: 30 * time.Second,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching URL: %v\n", err)
		os.Exit(1)
	}

	html := string(resp.Body)
	fetchURL := resp.FinalURL
	if fetchURL == "" {
		fetchURL = *url
	}

	fmt.Fprintf(os.Stderr, "Compressing semantic tree (%d bytes)...\n", len(html))

	tree, stats, err := semantic.HTMLToSemanticTree(ctx, html, fetchURL, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	state := semantic.InitialPack(tree, uint32(*initialBudget), uint32(*maxBudget))
	_ = semantic.AutoUnfold(tree, state)

	var outputData []byte
	switch *format {
	case "json":
		if *pretty {
			outputData, err = json.MarshalIndent(tree, "", "  ")
		} else {
			outputData, err = json.Marshal(tree)
		}
	case "serialized":
		outputData = []byte(semantic.SerializeTree(tree, state, nil))
	case "stats":
		statsData := map[string]interface{}{
			"raw_html_bytes":        stats.RawHTMLBytes,
			"clean_html_bytes":      stats.CleanHTMLBytes,
			"total_chunks":          stats.TotalChunks,
			"chunks_cached":         stats.ChunksCached,
			"chunks_llm_compressed": stats.ChunksLLMCompressed,
			"compressed_tokens":     stats.CompressedTokens,
			"full_tree_tokens":      stats.FullTreeTokens,
			"compression_ratio":     stats.CompressionRatio(),
			"tokens_saved":          stats.TokensSaved(),
			"duration_ms":           stats.DurationMS,
		}
		if *pretty {
			outputData, err = json.MarshalIndent(statsData, "", "  ")
		} else {
			outputData, err = json.Marshal(statsData)
		}
	default:
		outputData = []byte(formatTreeOutput(tree, state))
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error formatting output: %v\n", err)
		os.Exit(1)
	}

	if *output != "" {
		err = os.WriteFile(*output, outputData, 0o644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Written to %s\n", *output)
	} else {
		fmt.Println(string(outputData))
	}

	if stats != nil {
		fmt.Fprintf(os.Stderr, "\n--- Compression Stats ---\n")
		fmt.Fprintf(os.Stderr, "Raw HTML: %d bytes\n", stats.RawHTMLBytes)
		fmt.Fprintf(os.Stderr, "Clean HTML: %d bytes\n", stats.CleanHTMLBytes)
		fmt.Fprintf(os.Stderr, "Total chunks: %d\n", stats.TotalChunks)
		fmt.Fprintf(os.Stderr, "Cached: %d, LLM compressed: %d\n", stats.ChunksCached, stats.ChunksLLMCompressed)
		fmt.Fprintf(os.Stderr, "Compressed tokens: %d / Full: %d (%.1f%% ratio)\n",
			stats.CompressedTokens, stats.FullTreeTokens, stats.CompressionRatio()*100)
		fmt.Fprintf(os.Stderr, "Tokens saved: %d\n", stats.TokensSaved())
		fmt.Fprintf(os.Stderr, "Duration: %dms\n", stats.DurationMS)
	}
}

func formatTreeOutput(tree *semantic.SemanticTree, state *semantic.UnfoldState) string {
	var out string
	out += fmt.Sprintf("=== Semantic Tree: %s ===\n", tree.URL)
	out += fmt.Sprintf("Title: %s\n", tree.Title)
	out += fmt.Sprintf("Domain: %s\n", tree.Domain)
	out += fmt.Sprintf("Tokens: %d compressed / %d full (%.1f%%)\n\n",
		tree.CompressedTokenCount, tree.FullTokenCount, tree.CompressionRatio()*100)

	var walk func(nodes []semantic.SemanticNode, depth int)
	walk = func(nodes []semantic.SemanticNode, depth int) {
		indent := ""
		for i := 0; i < depth; i++ {
			indent += "  "
		}
		for i := range nodes {
			node := &nodes[i]
			out += fmt.Sprintf("%s[#%s] %s", indent, node.ID, node.Summary)
			if len(node.Actions) > 0 {
				actionTypes := make(map[string]bool)
				for _, a := range node.Actions {
					actionTypes[string(a.Type)] = true
				}
				var types []string
				for t := range actionTypes {
					types = append(types, t)
				}
				out += fmt.Sprintf(" (%s)", types)
			}
			out += fmt.Sprintf(" (%d tokens)", node.TokenCount)
			if node.IsDynamic {
				out += " [dynamic]"
			}
			out += "\n"

			if len(node.Children) > 0 && depth < 3 {
				walk(node.Children, depth+1)
			}
		}
	}

	walk(tree.RootNodes, 0)

	out += fmt.Sprintf("\n--- Budget Usage ---\n")
	out += fmt.Sprintf("Used: %d / %d tokens (%.0f%%)\n",
		state.TokenUsage, state.MaxBudget, float32(state.TokenUsage)/float32(state.MaxBudget)*100)

	return out
}
