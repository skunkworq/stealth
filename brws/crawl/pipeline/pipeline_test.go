package pipeline_test

import (
	"context"
	"testing"
	"time"

	"github.com/skunkworq/stealth/brws/crawl/pipeline"
)

func TestPipelineBasic(t *testing.T) {
	config := &pipeline.Config{
		MaxDepth:       1,
		Concurrency:    2,
		RequestTimeout: 30 * time.Second,
		EnableCache:    false,
		EnableIndexing: false,
	}

	pipe, err := pipeline.NewPipeline(config)
	if err != nil {
		t.Fatalf("Failed to create pipeline: %v", err)
	}
	defer pipe.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	result := pipe.ProcessURL(ctx, "https://httpbin.org/html")

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Error != nil {
		t.Fatalf("Processing failed: %v", result.Error)
	}

	if result.HTMLSize == 0 {
		t.Error("Expected non-zero HTML size")
	}

	if result.SemanticTree == nil {
		t.Error("Expected semantic tree")
	}

	t.Logf("✓ %s → %d tokens (%.1f%% compression)",
		result.URL,
		result.CompressionStats.CompressedTokens,
		float64(result.CompressionStats.CompressedTokens)/float64(result.CompressionStats.FullTreeTokens)*100)
}

func TestPipelineTracing(t *testing.T) {
	config := &pipeline.Config{
		MaxDepth:       1,
		Concurrency:    1,
		RequestTimeout: 30 * time.Second,
		EnableCache:    false,
		EnableIndexing: false,
	}

	pipe, err := pipeline.NewPipeline(config)
	if err != nil {
		t.Fatalf("Failed to create pipeline: %v", err)
	}
	defer pipe.Close()

	ctx := context.Background()
	result := pipe.ProcessURL(ctx, "https://httpbin.org/html")

	if result.Trace == nil {
		t.Fatal("Expected trace context in result")
	}

	spans := result.Trace.AllSpans()
	if len(spans) == 0 {
		t.Fatal("Expected at least one span")
	}

	t.Logf("Trace ID: %s", result.Trace.TraceID)
	for _, span := range spans {
		t.Logf("  %s: %v (%s)", span.Name, span.Duration, span.Status)
	}
}

func TestPipelineMetrics(t *testing.T) {
	config := &pipeline.Config{
		MaxDepth:       1,
		Concurrency:    1,
		RequestTimeout: 30 * time.Second,
		EnableCache:    false,
		EnableIndexing: false,
	}

	pipe, err := pipeline.NewPipeline(config)
	if err != nil {
		t.Fatalf("Failed to create pipeline: %v", err)
	}
	defer pipe.Close()

	ctx := context.Background()
	result := pipe.ProcessURL(ctx, "https://httpbin.org/html")

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	metrics := pipe.Metrics()
	counters := metrics.GetAllCounters()

	// Check that our pipeline-specific counters are set
	if result.CompressionStats == nil {
		t.Fatal("Expected compression stats")
	}

	t.Logf("URL processed: %s", result.URL)
	t.Logf("Compressed tokens: %d", result.CompressionStats.CompressedTokens)
	t.Logf("Metrics available: %d counters", len(counters))
}

func TestPipelineBatch(t *testing.T) {
	config := &pipeline.Config{
		MaxDepth:       1,
		Concurrency:    2,
		RequestTimeout: 30 * time.Second,
		EnableCache:    false,
		EnableIndexing: false,
	}

	pipe, err := pipeline.NewPipeline(config)
	if err != nil {
		t.Fatalf("Failed to create pipeline: %v", err)
	}
	defer pipe.Close()

	urls := []string{
		"https://httpbin.org/html",
		"https://httpbin.org/robots.txt",
	}

	ctx := context.Background()
	results := pipe.ProcessBatch(ctx, urls)

	if len(results) != 2 {
		t.Fatalf("Expected 2 results, got %d", len(results))
	}

	for _, r := range results {
		if r.Error != nil {
			t.Errorf("Failed to process %s: %v", r.URL, r.Error)
		}
	}

	t.Logf("✓ Processed %d URLs", len(results))
}
