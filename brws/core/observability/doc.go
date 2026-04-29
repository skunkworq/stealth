// Package observability provides metrics collection and health monitoring.
//
// The observability package offers an in-memory metrics collector with counters,
// gauges, histograms, and timing support. It integrates with the pipeline package
// for real-time monitoring of crawler operations.
//
// # Quick Start
//
// Basic counter and gauge usage:
//
//	// Get the global collector
//	collector := observability.GlobalCollector()
//
//	// Increment a counter
//	collector.IncCounter("requests_total", map[string]string{"method": "GET"})
//
//	// Set a gauge
//	collector.SetGauge("queue_size", 42.0, map[string]string{"queue": "pending"})
//
//	// Record timing
//	collector.RecordTiming("request_duration", 150*time.Millisecond, nil)
//
// # Concurrent Safety
//
// All operations are safe for concurrent use:
//
//	// Multiple goroutines can safely update metrics
//	go func() {
//	    for i := 0; i < 100; i++ {
//	        observability.IncCounter("worker_requests", map[string]string{"worker": "1"})
//	    }
//	}()
//
//	go func() {
//	    for i := 0; i < 100; i++ {
//	        observability.IncCounter("worker_requests", map[string]string{"worker": "2"})
//	    }
//	}()
//
// # Counters
//
// Counters only increase (monotonic):
//
//	// Simple counter
//	collector.IncCounter("events_total", nil)
//
//	// Counter with labels
//	collector.IncCounter("http_requests", map[string]string{
//	    "method": "GET",
//	    "status": "200",
//	})
//
//	// Add to counter (for batch increments)
//	collector.AddCounter("bytes_sent", 1024, map[string]string{"endpoint": "/api"})
//
// Retrieving counter values:
//
//	value := collector.GetCounter("events_total", nil)
//	fmt.Printf("Total events: %d\n", value)
//
//	Get all counters:
//
//	all := collector.GetAllCounters()
//	for name, value := range all {
//	    fmt.Printf("%s: %d\n", name, value)
//	}
//
// # Gauges
//
// Gauges represent point-in-time values:
//
//	// Set current queue depth
//	collector.SetGauge("queue_depth", 15.0, map[string]string{"queue": "processing"})
//
//	// Set temperature
//	collector.SetGauge("temperature", 72.5, nil)
//
// Retrieving gauge values:
//
//	depth := collector.GetGauge("queue_depth", map[string]string{"queue": "processing"})
//	fmt.Printf("Queue depth: %.0f\n", depth)
//
//	Get all gauges:
//
//	all := collector.GetAllGauges()
//	for name, value := range all {
//	    fmt.Printf("%s: %.2f\n", name, value)
//	}
//
// # Histograms and Timings
//
// Record distribution of values:
//
//	// Record request size
//	collector.RecordHistogram("request_size_bytes", 1024.0, nil)
//	collector.RecordHistogram("request_size_bytes", 2048.0, nil)
//	collector.RecordHistogram("request_size_bytes", 512.0, nil)
//
//	// Record timing
//	collector.RecordTiming("request_duration", 150*time.Millisecond, nil)
//	collector.RecordTiming("request_duration", 200*time.Millisecond, nil)
//
// Get histogram statistics:
//
//	stats := collector.GetHistogram("request_duration", nil)
//	fmt.Printf("Count: %d\n", stats.Count)
//	fmt.Printf("Sum: %.2f\n", stats.Sum)
//	fmt.Printf("Min: %.2f\n", stats.Min)
//	fmt.Printf("Max: %.2f\n", stats.Max)
//
// # Timer Helper
//
// Simplify timing code blocks:
//
//	// Basic timer
//	timer := observability.StartTimer("operation_duration", nil)
//	performOperation()
//	duration := timer.Stop()
//	fmt.Printf("Operation took: %v\n", duration)
//
//	// Timer with labels
//	timer := observability.StartTimer("db_query", map[string]string{
//	    "query": "select_users",
//	    "db":    "primary",
//	})
//	rows, _ := db.Query("SELECT * FROM users")
//	timer.Stop()
//
// TimeFunc helper:
//
//	duration := observability.TimeFunc("batch_process", nil, func() {
//	    processItems(items)
//	})
//	fmt.Printf("Batch processing: %v\n", duration)
//
// TimeFuncErr for error-returning functions:
//
//	duration, err := observability.TimeFuncErr("fetch_url", map[string]string{
//	    "url": "https://example.com",
//	}, func() error {
//	    return fetchURL(url)
//	})
//	fmt.Printf("Fetch took %v, error: %v\n", duration, err)
//
// # Labels
//
// Labels provide dimensional metrics (like Prometheus):
//
//	// Counter with labels
//	collector.IncCounter("http_requests", map[string]string{
//	    "method": "POST",
//	    "status": "201",
//	})
//
//	// Query by labels
//	count := collector.GetCounter("http_requests", map[string]string{
//	    "method": "POST",
//	    "status": "201",
//	})
//
// Labels are automatically sorted and escaped for consistent keys.
//
// # Context Support
//
// Store collector in context for request-scoped metrics:
//
//	// Add collector to context
//	ctx := observability.WithCollector(context.Background(), collector)
//
//	// Retrieve from context
//	c := observability.CollectorFromContext(ctx)
//	c.IncCounter("request_started", nil)
//
// # Global Collector
//
// Use global collector for convenience:
//
//	// These all use the global collector
//	observability.IncCounter("events_total", nil)
//	observability.SetGauge("current_temp", 72.0, nil)
//	observability.RecordTiming("op_duration", 100*time.Millisecond, nil)
//
// Set a custom global collector:
//
//	customCollector := observability.NewInMemoryCollector()
//	observability.SetGlobalCollector(customCollector)
//
// # Integration with Pipeline
//
// The pipeline package automatically records metrics:
//
//	pipe, _ := pipeline.NewPipeline(config)
//
//	// Process URLs - metrics are auto-recorded:
//	// - pipeline_urls_queued
//	// - pipeline_urls_processed
//	// - stage_fetch_duration
//	// - stage_extract_duration
//	// - stage_extract_chunks_llm
//	// - stage_extract_chunks_cached
//	// - etc.
//
//	// Access metrics
//	metrics := pipe.Metrics()
//	counters := metrics.GetAllCounters()
//
// Example metrics from a crawl:
//
//	{
//	    "counters": {
//	        "pipeline_urls_queued:url=https://example.com": 1,
//	        "pipeline_urls_processed": 1,
//	        "stage_fetch_bytes:url=https://example.com": 1,
//	        "stage_fetch_bytes_total": 38344,
//	        "stage_extract_tokens_compressed": 18,
//	        "stage_extract_tokens_full": 4862,
//	        "stage_extract_chunks_llm": 6,
//	        "stage_extract_chunks_cached": 55,
//	        "stage_embed_vectors_added": 1,
//	        "trace_spans_started:span=fetch,...": 1,
//	        "trace_spans_started:span=extract,...": 1
//	    },
//	    "gauges": {
//	        "pipeline_compression_ratio:url=https://example.com": 0.0037
//	    }
//	}
//
// # Reset
//
// Clear all metrics (useful for testing):
//
//	collector.Reset()
//	// All counters, gauges, histograms are empty
//
// # Metric Naming Conventions
//
// Follow Prometheus naming conventions:
//   - Use snake_case: stage_fetch_bytes (not stageFetchBytes)
//   - Suffix units: _total for counters, _seconds for time
//   - Add units in the name: request_duration_milliseconds
//   - Use labels for dimensions: http_requests_total{method="GET"}
//
// # Performance
//
// InMemoryCollector is optimized for read-mostly workloads:
//   - Increments use atomic operations (no lock)
//   - Gauge reads use RLock (concurrent readers)
//   - Histogram writes use Lock (sequential writes)
//
// For high-throughput, consider:
//   - Batch increments with AddCounter (vs multiple IncCounter)
//   - Reuse label maps (avoid allocation)
//   - Use global collector (already initialized)
//
// # Example HTTP Endpoint
//
// Expose metrics via HTTP:
//
//	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
//	    collector := observability.GlobalCollector()
//	    counters := collector.GetAllCounters()
//	    gauges := collector.GetAllGauges()
//
//	    data := map[string]any{
//	        "counters": counters,
//	        "gauges":   gauges,
//	    }
//
//	    json.NewEncoder(w).Encode(data)
//	})
//
// # Thread Safety
//
// All operations are safe for concurrent use:
//   - IncCounter: atomic add, no lock
//   - AddCounter: atomic add, no lock
//   - SetGauge: mutex protected
//   - RecordHistogram: mutex protected
//   - RecordTiming: calls RecordHistogram
//   - Get*: read locks only
//
// # Memory Usage
//
// Metrics grow unbounded - no automatic expiration.
// For long-running processes, consider:
//   - Periodic Reset() calls
//   - External time-series DB (Prometheus, InfluxDB)
//   - Custom collector with TTL support
package observability
