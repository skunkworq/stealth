package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stealth/brwslab/brws/pipeline"
	"github.com/stealth/brwslab/brws/semantic"
	"github.com/stealth/brwslab/brws/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

func main() {
	urlsFile := flag.String("urls", "", "file with URLs (one per line)")
	urlList := flag.String("url", "", "single URL or comma-separated URLs")
	output := flag.String("output", "json", "output format: json, text, summary")
	promAddr := flag.String("prom", ":9090", "Prometheus metrics endpoint")
	otelEndpoint := flag.String("otel", "", "OpenTelemetry OTLP endpoint (e.g., localhost:4317)")
	concurrency := flag.Int("concurrency", 4, "number of concurrent workers")
	timeout := flag.Duration("timeout", 5*time.Minute, "request timeout")
	noCache := flag.Bool("no-cache", false, "disable caching")
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
		fmt.Fprintln(os.Stderr, "Usage: crawl -url <url> or -urls <file>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if len(urls) == 0 {
		fmt.Fprintln(os.Stderr, "No URLs to process")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize telemetry
	tel, err := initializeTelemetry(ctx, *otelEndpoint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Telemetry init error: %v\n", err)
		os.Exit(1)
	}
	if tel != nil {
		defer tel.Shutdown(ctx)
		fmt.Println("OpenTelemetry enabled")
	}

	// Initialize Prometheus metrics
	promMetrics := pipeline.NewPrometheusMetrics("semantic_crawler")
	promMetrics.MustRegister()

	// Start Prometheus server
	if *promAddr != "" {
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())
			mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			})
			fmt.Printf("Prometheus metrics at %s/metrics\n", *promAddr)
			http.ListenAndServe(*promAddr, mux)
		}()
	}

	// Configure pipeline
	config := &pipeline.Config{
		MaxDepth:       1,
		Concurrency:    *concurrency,
		UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
		EnableCache:    !*noCache,
		EnableIndexing: true,
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

	// Setup signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		cancel()
	}()

	// Process with instrumentation
	var results []*pipeline.PageResult
	var totalCompressed, totalFull int64
	start := time.Now()

	tracer := otel.Tracer("crawler")

	pipe.OnPageProcessed(func(ctx context.Context, result *pipeline.PageResult) {
		_, span := tracer.Start(ctx, "page_processed")
		defer span.End()

		results = append(results, result)

		// Record Prometheus metrics
		if result.Error != nil {
			promMetrics.RecordURLFailed()
			span.RecordError(result.Error)
		} else {
			promMetrics.RecordURLProcessed()
		}

		promMetrics.RecordFetchDuration(result.FetchDuration)
		promMetrics.RecordExtractDuration(result.ExtractDuration)
		promMetrics.RecordEmbedDuration(result.EmbedDuration)
		promMetrics.RecordBytes(result.HTMLSize)

		if result.CompressionStats != nil {
			promMetrics.RecordTokens(
				int(result.CompressionStats.CompressedTokens),
				int(result.CompressionStats.FullTreeTokens),
			)
			promMetrics.RecordChunks(
				int(result.CompressionStats.ChunksLLMCompressed),
				int(result.CompressionStats.ChunksCached),
			)
			totalCompressed += int64(result.CompressionStats.CompressedTokens)
			totalFull += int64(result.CompressionStats.FullTreeTokens)
		}

		span.SetAttributes(
			attribute.String("url", result.URL),
			attribute.Int64("html_size", result.HTMLSize),
			attribute.Int64("duration_ms", result.TotalDuration.Milliseconds()),
		)

		if *verbose {
			status := "✓"
			if result.Error != nil {
				status = "✗"
			}
			fmt.Printf("%s %s (%.1fs) → %d tokens",
				status, result.URL, result.TotalDuration.Seconds(),
				result.CompressionStats.CompressedTokens)
			if result.Error != nil {
				fmt.Printf(" ERROR: %v", result.Error)
			}
			fmt.Println()
		} else {
			fmt.Print(".")
		}
	})

	// Run with tracing
	ctx, mainSpan := tracer.Start(ctx, "crawl_batch")
	defer mainSpan.End()

	mainSpan.SetAttributes(
		attribute.Int("url_count", len(urls)),
	)

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

func initializeTelemetry(ctx context.Context, otlpEndpoint string) (*telemetry.Telemetry, error) {
	if otlpEndpoint == "" {
		return nil, nil
	}

	cfg := &telemetry.Config{
		ServiceName:    "semantic-crawler",
		ServiceVersion: "1.0.0",
		OTLPEndpoint:   otlpEndpoint,
		SampleRate:     1.0,
	}

	return telemetry.New(ctx, cfg)
}

func outputJSON(results []*pipeline.PageResult) {
	fmt.Println("[")
	for i, r := range results {
		if i > 0 {
			fmt.Println(",")
		}
		fmt.Printf(`{"url": "%s", "html_size": %d, "duration_ms": %d, "tokens": %d, "error": "%v"}`,
			r.URL, r.HTMLSize, r.TotalDuration.Milliseconds(),
			r.CompressionStats.CompressedTokens, r.Error)
	}
	fmt.Println("]")
}

func outputText(results []*pipeline.PageResult) {
	for _, r := range results {
		fmt.Printf("\n=== %s ===\n", r.URL)
		if r.Error != nil {
			fmt.Printf("Error: %v\n", r.Error)
			continue
		}
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
}

func outputSummary(results []*pipeline.PageResult, elapsed time.Duration, totalCompressed, totalFull int64, pipe *pipeline.Pipeline) {
	var successes, errors int
	var totalHTML int64
	llmCalls := 0
	cacheHits := 0

	for _, r := range results {
		if r.Error != nil {
			errors++
		} else {
			successes++
		}
		totalHTML += r.HTMLSize
		if r.CompressionStats != nil {
			llmCalls += int(r.CompressionStats.ChunksLLMCompressed)
			cacheHits += int(r.CompressionStats.ChunksCached)
		}
	}

	fmt.Println("\n========================================")
	fmt.Println("Crawl Summary")
	fmt.Println("========================================")
	fmt.Printf("URLs processed: %d (success: %d, errors: %d)\n", len(results), successes, errors)
	fmt.Printf("Total duration: %v\n", elapsed)
	fmt.Printf("Avg per URL:    %v\n", elapsed/time.Duration(len(results)))
	fmt.Printf("\nSizes:\n")
	fmt.Printf("  HTML fetched: %d bytes (%.1f MB)\n", totalHTML, float64(totalHTML)/1024/1024)
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
	if llmCalls+cacheHits > 0 {
		fmt.Printf("  Hit rate:     %.1f%%\n", float64(cacheHits)/float64(llmCalls+cacheHits)*100)
	}
	fmt.Println("\nMetrics available at /metrics endpoint")
	fmt.Println("========================================")
}
