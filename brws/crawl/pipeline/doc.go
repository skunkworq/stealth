// Package pipeline provides an integrated crawler pipeline with tracing and metrics.
//
// The pipeline package orchestrates the complete flow from URL to semantic extraction
// to vector indexing, with built-in distributed tracing and real-time metrics.
//
// # Architecture
//
// The pipeline operates in three stages:
//
//  1. FETCH: HTTP GET with timeout, retry, and user-agent configuration
//  2. EXTRACT: Semantic tree extraction via brws/semantic package
//  3. EMBED: Vector indexing for similarity search
//
// Each stage is traced with hierarchical spans and emits metrics.
//
// # Quick Start
//
// Basic URL processing:
//
//	config := &pipeline.Config{
//	    Concurrency:    4,
//	    RequestTimeout: 2 * time.Minute,
//	    EnableCache:    true,
//	    EnableIndexing: true,
//	}
//
//	pipe, _ := pipeline.NewPipeline(config)
//	defer pipe.Close()
//
//	result := pipe.ProcessURL(ctx, "https://example.com")
//	// result.SemanticTree: Extracted semantic structure
//	// result.Trace: Complete trace with spans
//	// result.CompressionStats: Token metrics
//
// # Batch Processing
//
// Process multiple URLs concurrently:
//
//	urls := []string{"https://a.com", "https://b.com", "https://c.com"}
//	results := pipe.ProcessBatch(ctx, urls)
//
//	for _, r := range results {
//	    if r.Error != nil {
//	        log.Printf("Error: %s: %v", r.URL, r.Error)
//	    } else {
//	        log.Printf("OK: %s → %d tokens", r.URL, r.CompressionStats.CompressedTokens)
//	    }
//	}
//
// # Distributed Tracing
//
// Each PageResult includes a complete trace:
//
//	result := pipe.ProcessURL(ctx, url)
//
//	fmt.Printf("Trace ID: %s\n", result.Trace.TraceID)
//	for _, span := range result.Trace.AllSpans() {
//	    fmt.Printf("  %s: %v (%s)\n", span.Name, span.Duration, span.Status)
//	}
//	// Output:
//	// Trace ID: 1772432545788680000
//	//   fetch: 1.075s (ok)
//	//   extract: 560µs (ok)
//	//   embed: 13µs (ok)
//
// # Trace Context
//
// Spans can be accessed for detailed debugging:
//
//	for _, span := range result.Trace.AllSpans() {
//	    if span.Name == "extract" {
//	        fmt.Printf("Chunks: %v\n", span.Attributes["chunks_total"])
//	        fmt.Printf("LLM calls: %v\n", span.Attributes["chunks_llm"])
//	        fmt.Printf("Cache hits: %v\n", span.Attributes["chunks_cached"])
//	    }
//	}
//
// Export traces as JSON:
//
//	jsonTrace := result.Trace.ToJSON()
//	// Full JSON with all spans, events, and attributes
//
// # Metrics Server
//
// Start HTTP metrics endpoint:
//
//	pipe, _ := pipeline.NewPipeline(config)
//
//	metricsServer := pipeline.NewMetricsServer(pipe, ":8080")
//	go metricsServer.Start()
//	defer metricsServer.Shutdown()
//
//	// Endpoints available:
//	// GET /metrics - All counters and gauges
//	// GET /health  - Health check
//	// GET /stats   - Summary statistics
//
// Query metrics programmatically:
//
//	metrics := pipe.Metrics()
//	counters := metrics.GetAllCounters()
//	gauges := metrics.GetAllGauges()
//
//	fmt.Printf("URLs processed: %d\n", counters["pipeline_urls_processed"])
//	fmt.Printf("Errors: %d\n", counters["pipeline_fetch_errors"])
//
// # Metrics Available
//
// Counter metrics (cumulative):
//
//	pipeline_urls_queued           - URLs added to queue
//	pipeline_urls_processed        - Successfully processed URLs
//	pipeline_fetch_errors          - HTTP fetch failures
//	pipeline_extract_errors       - Semantic extraction failures
//	stage_fetch_bytes             - Bytes fetched
//	stage_fetch_bytes_total       - Total bytes fetched
//	stage_extract_tokens_compressed - Tokens after compression
//	stage_extract_tokens_full      - Tokens before compression
//	stage_extract_chunks_llm       - LLM API calls
//	stage_extract_chunks_cached    - Cache hits
//	stage_embed_vectors_added      - Vectors indexed
//	trace_spans_started           - Spans created
//	span_errors                   - Span errors
//
// Timing metrics (histograms):
//
//	stage_fetch_duration           - Fetch stage latency
//	stage_extract_duration         - Extract stage latency
//	stage_embed_duration           - Embed stage latency
//	span_duration                  - Span execution time
//
// Gauge metrics (current value):
//
//	pipeline_compression_ratio     - Current compression ratio
//
// # Callbacks and Hooks
//
// Register callbacks for monitoring:
//
//	pipe.OnPageProcessed(func(ctx context.Context, result *pipeline.PageResult) {
//	    if result.Error != nil {
//	        metrics.IncCounter("crawl_errors", map[string]string{"url": result.URL})
//	        return
//	    }
//
//	    log.Printf("[%s] %s → %d tokens (%.1f%% compression)",
//	        result.Trace.TraceID,
//	        result.URL,
//	        result.CompressionStats.CompressedTokens,
//	        float64(result.CompressionStats.CompressedTokens)/
//	            float64(result.CompressionStats.FullTreeTokens)*100)
//	})
//
// # Configuration
//
//	Config struct {
//	    SemanticConfig  *semantic.PipelineConfig // Semantic extraction config
//	    MaxDepth        int                       // Crawling depth (default: 1)
//	    Concurrency     int                       // Workers (default: 4)
//	    UserAgent       string                    // HTTP User-Agent
//	    EnableIndexing  bool                      // Vector indexing
//	    EnableCache     bool                      // SQLite cache
//	    RequestTimeout  time.Duration             // HTTP timeout
//	}
//
// SemanticConfig passes through to the semantic package:
//
//	semanticConfig := &semantic.PipelineConfig{
//	    LLMClient:        semantic.NewLLMClient(apiKey),
//	    MaxChunks:        200,
//	    MaxConcurrentLLM: 10,
//	}
//
//	config := &pipeline.Config{
//	    SemanticConfig:  semanticConfig,
//	    Concurrency:     8,
//	    EnableIndexing:  true,
//	    RequestTimeout:  2 * time.Minute,
//	}
//
// # Search and Retrieval
//
// After indexing, search across processed pages:
//
//	queryVector := generateEmbedding("login form")
//	results := pipe.Search(queryVector, 10)
//
//	for _, result := range results {
//	    fmt.Printf("URL: %s, Score: %.2f\n", result.URL, result.Score)
//	}
//
// # Data Structures
//
// PageResult contains all extraction data:
//
//	type PageResult struct {
//	    URL              string
//	    HTMLSize         int64
//	    SemanticTree     *semantic.SemanticTree
//	    CompressionStats *semantic.CompressionStats
//	    VectorAdded      bool
//	    Trace            *TraceContext
//	    FetchDuration    time.Duration
//	    ExtractDuration  time.Duration
//	    EmbedDuration    time.Duration
//	    TotalDuration    time.Duration
//	    Error            error
//	}
//
// # Tracing Details
//
// Span attributes vary by stage:
//
// FETCH stage:
//
//	span.SetAttribute("url", url)
//	span.SetAttribute("status_code", resp.StatusCode)
//	span.AddEvent("headers_received", map[string]any{
//	    "content_type": resp.Header.Get("Content-Type"),
//	})
//
// EXTRACT stage:
//
//	span.SetAttribute("html_size", len(html))
//	span.SetAttribute("compressed_tokens", stats.CompressedTokens)
//	span.SetAttribute("full_tokens", stats.FullTreeTokens)
//	span.SetAttribute("chunks_total", stats.TotalChunks)
//	span.SetAttribute("chunks_llm", stats.ChunksLLMCompressed)
//	span.SetAttribute("chunks_cached", stats.ChunksCached)
//
// EMBED stage:
//
//	span.SetAttribute("indexed", true)
//
// # Error Handling
//
// Check result.Error for failures:
//
//	result := pipe.ProcessURL(ctx, url)
//	if result.Error != nil {
//	    // Check trace for error details
//	    for _, span := range result.Trace.AllSpans() {
//	        if span.Status == "error" {
//	            fmt.Printf("Stage %s failed: %v\n", span.Name, span.Error)
//	        }
//	    }
//	}
//
// # Performance Tuning
//
// For high-throughput crawling:
//
//	config := &pipeline.Config{
//	    Concurrency:     16,              // More workers
//	    RequestTimeout:  30 * time.Second, // Shorter timeout
//	    EnableCache:     true,             // Enable caching
//	    SemanticConfig: &semantic.PipelineConfig{
//	        MaxChunks:        100,  // Limit chunks per page
//	        MaxConcurrentLLM: 20,   // More concurrent LLM calls
//	    },
//	}
//
// # Integration with Observability
//
// The pipeline uses brws/observability for metrics:
//
//	import "github.com/skunkworq/stealth/brws/core/observability"
//
//	// Global metrics collector
//	observability.IncCounter("custom_metric", map[string]string{"key": "value"})
//	observability.SetGauge("custom_gauge", 1.5, nil)
//
//	// Timer helper
//	timer := observability.StartTimer("operation_duration", nil)
//	// ... do work ...
//	duration := timer.Stop()
//
// # CLI Usage
//
// The cmd/pipeline tool provides CLI access:
//
//	# Single URL
//	go run ./cmd/pipeline -url "https://example.com"
//
//	# Batch from file
//	go run ./cmd/pipeline -urls urls.txt -concurrency 8
//
//	# With metrics server
//	go run ./cmd/pipeline -url "..." -metrics ":8080"
//	curl http://localhost:8080/stats
//
// # Example Output
//
// Summary format:
//
//	========================================
//	Pipeline Summary
//	========================================
//	URLs processed: 3 (success: 3, errors: 0)
//	Total duration: 3.2s
//	Avg per URL:    1.07s
//
//	Compression:
//	  Total tokens: 1171 → 62
//	  Ratio:        5.29% (19x reduction)
//	  Saved:        1109 tokens
//
//	LLM:
//	  Calls:        0
//	  Cache hits:   6
//	  Hit rate:     100.0%
//	========================================
package pipeline
