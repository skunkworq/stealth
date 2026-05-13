# Semantic Extraction System - Implementation Plan

## Overview

Port of Webfurl semantic extraction system from Rust to Go. Compresses web pages into hierarchical semantic trees to minimize LLM context usage (~99% token reduction).

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            APPLICATION LAYER                                  │
│                                                                               │
│   ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐           │
│   │ cmd/pipeline    │   │ cmd/semantic-mcp│   │ cmd/test_semantic│           │
│   │ (crawler)       │   │ (MCP server)    │   │ (testing)        │           │
│   └────────┬────────┘   └────────┬────────┘   └────────┬────────┘           │
│            │                     │                     │                     │
└────────────┼─────────────────────┼─────────────────────┼─────────────────────┘
             │                     │                     │
             └─────────────────────┼─────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            PIPELINE LAYER                                     │
│                          brws/pipeline/                                       │
│                                                                               │
│   ┌────────────────────────────────────────────────────────────────────┐     │
│   │                      Pipeline Orchestrator                          │     │
│   │                                                                     │     │
│   │   ProcessURL(ctx, url) ─▶ PageResult                               │     │
│   │   ProcessBatch(ctx, urls) ─▶ []PageResult                          │     │
│   │                                                                     │     │
│   │   Hooks: OnPageProcessed, OnError                                  │     │
│   └──────────────────────────┬─────────────────────────────────────────┘     │
│                              │                                               │
│         ┌────────────────────┼────────────────────┐                         │
│         ▼                    ▼                    ▼                          │
│   ┌──────────┐         ┌──────────┐         ┌──────────┐                    │
│   │  FETCH   │         │ EXTRACT  │         │  EMBED   │                    │
│   │  Stage   │         │  Stage   │         │  Stage   │                    │
│   ├──────────┤         ├──────────┤         ├──────────┤                    │
│   │ • HTTP   │         │ • Chunk  │         │ • HNSW   │                    │
│   │ • Timeout│         │ • LLM    │         │ • Vector │                    │
│   │ • Retry  │         │ • Cache  │         │ • Index  │                    │
│   └──────────┘         └──────────┘         └──────────┘                    │
│         │                    │                    │                          │
│         └────────────────────┴────────────────────┘                         │
│                              │                                               │
│                              ▼                                               │
│   ┌──────────────────────────────────────────────────────────────────┐      │
│   │                      TRACING & METRICS                            │      │
│   ├──────────────────────────────────────────────────────────────────┤      │
│   │  tracing.go                    metrics_server.go                  │      │
│   │  • TraceID                     • GET /metrics                    │      │
│   │  • SpanID                      • GET /health                    │      │
│   │  • Hierarchical spans          • GET /stats                     │      │
│   │  • JSON export                 • Real-time monitoring            │      │
│   └──────────────────────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SEMANTIC LAYER                                      │
│                          brws/semantic/                                       │
│                                                                               │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│   │   pipeline   │  │     tree     │  │    cache     │  │     llm      │    │
│   │   .go        │  │     .go      │  │    .go       │  │     .go      │    │
│   └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘    │
│                                                                               │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│   │   forms      │  │    diff      │  │   unfold     │  │   actions    │    │
│   │   .go        │  │    .go       │  │    .go       │  │    .go       │    │
│   └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘    │
│                                                                               │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                       │
│   │   vision_    │  │   embeddings │  │    index/    │                       │
│   │   grounding  │  │    .go       │  │   hnsw.go   │                       │
│   └──────────────┘  └──────────────┘  └──────────────┘                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          OBSERVABILITY LAYER                                  │
│                        brws/observability/                                     │
│                                                                               │
│   ┌──────────────────────────────────────────────────────────────────┐      │
│   │                    metrics.go                                     │      │
│   │  • InMemoryCollector                                              │      │
│   │  • Counters, Gauges, Histograms                                   │      │
│   │  • Global collector with context support                          │      │
│   │  • Timer helpers for duration tracking                            │      │
│   └──────────────────────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Completed Components

### 1. Pipeline Package (`brws/pipeline/`)

| File | Purpose | Status |
|------|---------|--------|
| `tracing.go` | Distributed tracing with trace/span IDs | ✅ Complete |
| `pipeline.go` | 3-stage processing (fetch→extract→embed) | ✅ Complete |
| `metrics_server.go` | HTTP metrics endpoint | ✅ Complete |
| `pipeline_test.go` | Integration tests | ✅ Complete |

**Features:**
- Hierarchical spans for each stage
- Real-time metrics exported via HTTP
- Concurrent batch processing
- Hooks for callbacks
- Token and timing tracking

### 2. Core Semantic Package (`brws/semantic/`)

| File | Purpose | Status |
|------|---------|--------|
| `tree.go` | SemanticNode/SemanticTree structures | ✅ Complete |
| `pipeline.go` | DOM chunking + LLM compression | ✅ Complete |
| `cache.go` | SQLite-based content-hash cache | ✅ Complete |
| `llm.go` | OpenRouter LLM client with timeout | ✅ Complete |
| `embeddings.go` | OpenRouter embedding client | ✅ Complete |
| `forms.go` | Form schema extraction | ✅ Complete |
| `diff.go` | Incremental update diffing | ✅ Complete |
| `vision_grounding.go` | Bounding box calculation | ✅ Complete |
| `serialize.go` | `[WEBFURL]` text format | ✅ Complete |
| `unfold.go` | Budget-based unfolding | ✅ Complete |
| `actions.go` | Click, Fill, Select, Toggle | ✅ Complete |
| `index/hnsw.go` | HNSW vector index | ✅ Complete |

**Performance Optimizations:**
- HTTP client timeout (60s)
- Concurrency limiter (10 concurrent LLM calls)
- MaxChunks limit for large pages
- Cache hits reduce LLM calls

**Test Coverage:** 50+ tests passing

### 3. Observability Package (`brws/observability/`)

| File | Purpose | Status |
|------|---------|--------|
| `metrics.go` | In-memory metrics collector | ✅ Complete |
| `health.go` | Health check endpoints | ✅ Complete |

**Metrics Available:**
- Counters: URLs processed, errors, cache hits
- Gauges: Compression ratio, success rate
- Timings: Fetch, extract, embed duration
- Histograms: Token distribution

### 4. CLI Tools

| Tool | Purpose |
|------|---------|
| `cmd/pipeline/` | Integrated crawler with metrics |
| `cmd/semantic-mcp/` | MCP server for LLM integration |
| `cmd/test_semantic/` | URL testing with diagnostics |
| `cmd/vecbench/` | Vector backend benchmark |

---

## Data Flow

```
URL Input
    │
    ▼
┌─────────────┐
│  FETCH      │  ─▶ HTML (fetched with timeout/retry)
│  Stage      │     • Trace span: "fetch"
└─────────────┘     • Metrics: bytes, duration, status
    │
    ▼
┌─────────────┐
│  EXTRACT    │  ─▶ SemanticTree
│  Stage      │     • Trace span: "extract"
└─────────────┘     • Chunk DOM → LLM/Cache → Tree
    │               • Metrics: tokens, chunks, cache hits
    ▼
┌─────────────┐
│  EMBED      │  ─▶ Vector Index
│  Stage      │     • Trace span: "embed"
└─────────────┘     • Add to HNSW index
                    • Metrics: vectors added
    │
    ▼
PageResult ─▶ {URL, Tree, Stats, Trace, Error}
```

---

## Tracing Format

Each `PageResult` includes a `TraceContext`:

```json
{
  "trace_id": "1772432545788680000",
  "spans": [
    {
      "name": "fetch",
      "duration": "1.075s",
      "status": "ok",
      "attributes": {
        "url": "https://example.com",
        "status_code": 200
      }
    },
    {
      "name": "extract",
      "duration": "560µs",
      "status": "ok",
      "attributes": {
        "compressed_tokens": 55,
        "full_tokens": 953,
        "chunks_llm": 0,
        "chunks_cached": 2
      }
    },
    {
      "name": "embed",
      "duration": "13µs",
      "status": "ok",
      "attributes": {
        "indexed": true
      }
    }
  ],
  "duration": "1.076s"
}
```

---

## Metrics Endpoints

| Endpoint | Description | Example |
|----------|-------------|---------|
| `GET /metrics` | All counters and gauges | `{"counters": {...}, "gauges": {...}}` |
| `GET /health` | Health check | `{"status": "healthy"}` |
| `GET /stats` | Summary statistics | URLs processed, success rate, compression |

---

## Usage Examples

### Pipeline CLI

```bash
# Single URL with metrics server
go run ./cmd/scrape/pipeline -url "https://example.com" -metrics ":8080"

# Batch from file
go run ./cmd/scrape/pipeline -urls urls.txt -concurrency 8 -output summary

# Verbose with traces
go run ./cmd/scrape/pipeline -url "..." -v -output text
```

### Programmatic

```go
config := &pipeline.Config{
    Concurrency:     4,
    RequestTimeout:  2 * time.Minute,
    EnableCache:     true,
    EnableIndexing:  true,
}

pipe, _ := pipeline.NewPipeline(config)
defer pipe.Close()

// Single URL
result := pipe.ProcessURL(ctx, "https://example.com")
fmt.Printf("Trace: %s\n", result.Trace.ToJSON())

// Batch
results := pipe.ProcessBatch(ctx, urls)

// Get metrics
counters := pipe.Metrics().GetAllCounters()
```

### MCP Server

```bash
# Start MCP server for Claude Desktop integration
go run ./cmd/semantic/semantic-mcp

# Tools available:
# - extract_semantic_tree
# - diff_semantic_trees
# - get_form_schemas
# - serialize_tree
```

---

## Performance Characteristics

| Site | HTML Size | Tokens | Compressed | Ratio | Duration |
|------|-----------|--------|------------|-------|----------|
| httpbin.org/html | 3.8KB | 953 | 55 | 5.8% | 1.07s |
| httpbin.org/forms | 1.4KB | 218 | 7 | 3.2% | 1.08s |
| Hacker News | 34KB | 5,436 | 8 | 0.1% | 59s |
| GitHub | 561KB | 4,862 | 18 | 0.4% | 40s |
| Wikipedia | 438KB | 9,851 | 39 | 0.4% | 160s |

---

## Cost Analysis

See `docs/SEMANTIC_COSTS.md` for detailed token cost breakdown:

- LLM tokens spent: ~10,500 for GitHub (one-time)
- Compression result: 140K → 18 tokens (99.99% reduction)
- Break-even: After 0.1 queries to downstream LLM

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENROUTER_API_KEY` | LLM/Embeddings API key | Required for LLM mode |
| `SEMANTIC_CACHE_PATH` | SQLite cache location | `~/.semantic/cache.db` |

### Pipeline Config

```go
type Config struct {
    SemanticConfig   *semantic.PipelineConfig
    MaxDepth         int           // Crawling depth
    Concurrency      int           // Worker count
    UserAgent        string        // HTTP User-Agent
    EnableIndexing   bool          // Vector index
    EnableCache      bool          // SQLite cache
    RequestTimeout   time.Duration // HTTP timeout
}
```

### Semantic Config

```go
type PipelineConfig struct {
    LLMClient        *LLMClient
    EmbeddingClient  *EmbeddingClient
    Cache            *CacheStore
    MaxDepth         int
    MinContentLen    int
    MaxChunks        int           // Limit for large pages
    MaxConcurrentLLM int           // Rate limiter
}
```

---

## Future Enhancements

1. **Streaming support** - Process large pages incrementally
2. **Prometheus exporter** - Native Prometheus metrics format
3. **Distributed tracing** - OpenTelemetry integration
4. **Graph-based crawling** - Site-wide semantic maps
5. **MCP tools expansion** - Auto-unfold, semantic search

---

## Related Documentation

- `docs/SEMANTIC_COSTS.md` - Token cost analysis
- `docs/BENCHMARK.md` - Performance benchmarks
- `AGENTS.md` - Agent instructions (bd issue tracking)

---

## Production Crawler with Full Instrumentation

### Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        cmd/crawl (CLI)                                │
│                                                                       │
│  Flags: -url, -urls, -prom, -otel, -concurrency, -timeout, -v       │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│   Telemetry     │   │  Prometheus     │   │    Pipeline     │
│  (OTLP/OTel)    │   │   /metrics      │   │   Processing    │
└─────────────────┘   └─────────────────┘   └─────────────────┘
```

### OpenTelemetry Integration

The system uses OpenTelemetry for distributed tracing:

```bash
# With OTLP exporter (Jaeger, Tempo, etc.)
go run ./cmd/scrape/crawl -url "https://example.com" \
  -otel localhost:4317 \
  -prom :9090
```

Spans recorded:
- `crawl_batch` - Main batch operation
- `page_processed` - Per-page processing
- `fetch` - HTTP fetch (inherited from pipeline)
- `extract` - Semantic extraction
- `embed` - Vector indexing

### Prometheus Metrics

Available at `/metrics` endpoint:

| Metric | Type | Description |
|--------|------|-------------|
| `semantic_crawler_urls_processed_total` | Counter | Total URLs processed |
| `semantic_crawler_urls_failed_total` | Counter | Total URLs failed |
| `semantic_crawler_fetch_duration_seconds` | Histogram | Fetch latency |
| `semantic_crawler_extract_duration_seconds` | Histogram | Extract latency |
| `semantic_crawler_embed_duration_seconds` | Histogram | Embed latency |
| `semantic_crawler_tokens_compressed_total` | Counter | Compressed tokens |
| `semantic_crawler_tokens_full_total` | Counter | Original tokens |
| `semantic_crawler_chunks_llm_total` | Counter | LLM API calls |
| `semantic_crawler_chunks_cached_total` | Counter | Cache hits |
| `semantic_crawler_bytes_fetched_total` | Counter | Bytes fetched |
| `semantic_crawler_compression_ratio` | Gauge | Current ratio |

### Example Crawl Results

**Wikipedia Programming Languages (2 pages):**

```
URLs processed: 2 (success: 2, errors: 0)
HTML fetched: 1.0 MB
Compression: 115,458 → 189 tokens (611x reduction)
Cache hits: 1,289 (99.8% hit rate)
Duration: 50.7s total, 25.4s avg per URL
```

Cross-page caching benefit:
- Go article processed first → chunks cached
- Python article reuses similar chunks → 99.8% cache hit rate
- Only 3 LLM calls for both pages combined

### Grafana Dashboard Queries

```promql
# Processing rate (URLs/min)
rate(semantic_crawler_urls_processed_total[1m]) * 60

# Average compression ratio
semantic_crawler_compression_ratio

# Cache hit rate
rate(semantic_crawler_chunks_cached_total[5m]) / 
  (rate(semantic_crawler_chunks_cached_total[5m]) + rate(semantic_crawler_chunks_llm_total[5m]))

# P99 extraction latency
histogram_quantile(0.99, 
  rate(semantic_crawler_extract_duration_seconds_bucket[5m]))

# Bytes per second
rate(semantic_crawler_bytes_fetched_total[1m])
```

