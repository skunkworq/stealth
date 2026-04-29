package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/skunkworq/stealth/brws/crawl/pipeline"
	"github.com/skunkworq/stealth/brws/content/semantic"
)

func main() {
	urlsFile := flag.String("urls", "", "file with URLs (one per line)")
	urlList := flag.String("url", "", "single URL or comma-separated URLs")
	output := flag.String("output", "json", "output format: json, text, summary")
	metricsAddr := flag.String("metrics", ":8080", "metrics server address")
	concurrency := flag.Int("concurrency", 4, "number of concurrent workers")
	timeout := flag.Duration("timeout", 2*time.Minute, "request timeout")
	noCache := flag.Bool("no-cache", false, "disable caching")
	noIndex := flag.Bool("no-index", false, "disable vector indexing")
	verbose := flag.Bool("v", false, "verbose output")
	flag.Parse()

	apiKey := os.Getenv("OPENROUTER_API_KEY")
	if apiKey == "" || apiKey == "-" {
		fmt.Fprintln(os.Stderr, "Warning: OPENROUTER_API_KEY not set, using no-LLM mode")
	}

	var urls []string
	if *urlsFile != "" {
		data, err := os.ReadFile(*urlsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading URLs file: %v\n", err)
			os.Exit(1)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				urls = append(urls, line)
			}
		}
	} else if *urlList != "" {
		urls = strings.Split(*urlList, ",")
		for i := range urls {
			urls[i] = strings.TrimSpace(urls[i])
		}
	} else {
		fmt.Fprintln(os.Stderr, "Usage: pipeline -url <url> or -urls <file>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if len(urls) == 0 {
		fmt.Fprintln(os.Stderr, "No URLs to process")
		os.Exit(1)
	}

	config := &pipeline.Config{
		MaxDepth:       1,
		Concurrency:    *concurrency,
		UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
		EnableCache:    !*noCache,
		EnableIndexing: !*noIndex,
		RequestTimeout: *timeout,
	}

	if apiKey != "" && apiKey != "-" {
		llmClient := semantic.NewLLMClient(apiKey)
		config.SemanticConfig = &semantic.PipelineConfig{
			LLMClient:        llmClient,
			MaxChunks:        200,
			MaxConcurrentLLM: 10,
		}
	}

	pipe, err := pipeline.NewPipeline(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating pipeline: %v\n", err)
		os.Exit(1)
	}
	defer pipe.Close()

	// Start metrics server
	metricsServer := pipeline.NewMetricsServer(pipe, *metricsAddr)
	go func() {
		if err := metricsServer.Start(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "Metrics server error: %v\n", err)
		}
	}()
	fmt.Printf("Metrics server listening on %s\n", *metricsAddr)
	fmt.Printf("Endpoints: /metrics, /health, /stats\n\n")

	// Handle shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		cancel()
		_ = metricsServer.Shutdown()
	}()

	// Process with callbacks
	var results []*pipeline.PageResult
	var totalCompressed, totalFull int64

	start := time.Now()

	pipe.OnPageProcessed(func(ctx context.Context, result *pipeline.PageResult) {
		results = append(results, result)

		if *verbose {
			status := "✓"
			if result.Error != nil {
				status = "✗"
			}
			fmt.Printf("%s %s (%.1fs) → %d tokens",
				status, result.URL, result.TotalDuration.Seconds(), result.CompressionStats.CompressedTokens)
			if result.Error != nil {
				fmt.Printf(" ERROR: %v", result.Error)
			}
			fmt.Println()
		} else {
			fmt.Print(".")
		}

		if result.CompressionStats != nil {
			totalCompressed += int64(result.CompressionStats.CompressedTokens)
			totalFull += int64(result.CompressionStats.FullTreeTokens)
		}
	})

	// Run pipeline
	fmt.Printf("Processing %d URLs...\n", len(urls))
	results = pipe.ProcessBatch(ctx, urls)
	elapsed := time.Since(start)

	if !*verbose {
		fmt.Println()
	}

	// Output results
	switch *output {
	case "json":
		outputJSON(results)
	case "text":
		outputText(results)
	default:
		outputSummary(results, elapsed, totalCompressed, totalFull, pipe)
	}
}

func outputJSON(results []*pipeline.PageResult) {
	output := make([]map[string]any, len(results))
	for i, r := range results {
		m := map[string]any{
			"url":            r.URL,
			"html_size":      r.HTMLSize,
			"total_duration": r.TotalDuration.Milliseconds(),
		}
		if r.Error != nil {
			m["error"] = r.Error.Error()
		}
		if r.CompressionStats != nil {
			m["compressed_tokens"] = r.CompressionStats.CompressedTokens
			m["full_tokens"] = r.CompressionStats.FullTreeTokens
			m["chunks_total"] = r.CompressionStats.TotalChunks
			m["chunks_llm"] = r.CompressionStats.ChunksLLMCompressed
			m["chunks_cached"] = r.CompressionStats.ChunksCached
		}
		if r.Trace != nil {
			m["trace_id"] = r.Trace.TraceID
			m["spans"] = len(r.Trace.AllSpans())
		}
		output[i] = m
	}
	json.NewEncoder(os.Stdout).Encode(output)
}

func outputText(results []*pipeline.PageResult) {
	for _, r := range results {
		fmt.Printf("\n=== %s ===\n", r.URL)
		if r.Error != nil {
			fmt.Printf("Error: %v\n", r.Error)
			continue
		}
		if r.CompressionStats != nil {
			fmt.Printf("Tokens: %d → %d (%.1f%% compression)\n",
				r.CompressionStats.FullTreeTokens,
				r.CompressionStats.CompressedTokens,
				float64(r.CompressionStats.CompressedTokens)/float64(r.CompressionStats.FullTreeTokens)*100)
			fmt.Printf("Duration: %v\n", r.TotalDuration)
			fmt.Printf("Chunks: %d total, %d LLM, %d cached\n",
				r.CompressionStats.TotalChunks,
				r.CompressionStats.ChunksLLMCompressed,
				r.CompressionStats.ChunksCached)
		}
		if r.Trace != nil {
			fmt.Printf("Trace ID: %s\n", r.Trace.TraceID)
			fmt.Printf("Spans:\n")
			for _, span := range r.Trace.AllSpans() {
				fmt.Printf("  - %s: %v (%s)\n", span.Name, span.Duration, span.Status)
			}
		}
	}
}

func outputSummary(results []*pipeline.PageResult, elapsed time.Duration, totalCompressed, totalFull int64, pipe *pipeline.Pipeline) {
	var successes, errors int
	var totalHTML, totalFetchTime, totalExtractTime int64
	llmCalls := 0
	cacheHits := 0

	for _, r := range results {
		if r.Error != nil {
			errors++
		} else {
			successes++
		}
		totalHTML += r.HTMLSize
		totalFetchTime += r.FetchDuration.Milliseconds()
		totalExtractTime += r.ExtractDuration.Milliseconds()
		if r.CompressionStats != nil {
			llmCalls += int(r.CompressionStats.ChunksLLMCompressed)
			cacheHits += int(r.CompressionStats.ChunksCached)
		}
	}

	fmt.Println("\n========================================")
	fmt.Println("Pipeline Summary")
	fmt.Println("========================================")
	fmt.Printf("URLs processed: %d (success: %d, errors: %d)\n", len(results), successes, errors)
	fmt.Printf("Total duration: %v\n", elapsed)
	fmt.Printf("Avg per URL:    %v\n", elapsed/time.Duration(len(results)))
	fmt.Printf("\nSizes:\n")
	fmt.Printf("  HTML fetched: %d bytes (%.1f MB)\n", totalHTML, float64(totalHTML)/1024/1024)
	fmt.Printf("\nTiming:\n")
	fmt.Printf("  Fetch avg:    %dms\n", totalFetchTime/int64(len(results)))
	fmt.Printf("  Extract avg:  %dms\n", totalExtractTime/int64(len(results)))
	fmt.Printf("\nCompression:\n")
	fmt.Printf("  Total tokens: %d → %d\n", totalFull, totalCompressed)
	if totalFull > 0 {
		fmt.Printf("  Ratio:        %.2f%% (%.0fx reduction)\n",
			float64(totalCompressed)/float64(totalFull)*100,
			float64(totalFull)/float64(totalCompressed))
		fmt.Printf("  Saved:        %d tokens\n", totalFull-totalCompressed)
	}
	fmt.Printf("\nLLM:\n")
	fmt.Printf("  Calls:        %d\n", llmCalls)
	fmt.Printf("  Cache hits:   %d\n", cacheHits)
	fmt.Printf("  Hit rate:     %.1f%%\n", float64(cacheHits)/float64(llmCalls+cacheHits)*100)
	fmt.Println("========================================")
}
