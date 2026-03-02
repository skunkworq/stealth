# Semantic Extraction System - Implementation Plan

## Overview

Port of Webfurl semantic extraction system from Rust to Go. Compresses web pages into hierarchical semantic trees to minimize LLM context usage (~99% token reduction).

## Completed Components

### 1. Core Semantic Package (`brws/semantic/`)

| File | Purpose | Status |
|------|---------|--------|
| `tree.go` | SemanticNode/SemanticTree data structures | ✅ Complete |
| `pipeline.go` | DOM chunking + LLM compression (~1100 lines) | ✅ Complete |
| `cache.go` | SQLite-based content-hash cache | ✅ Complete |
| `llm.go` | OpenRouter LLM client | ✅ Complete |
| `embeddings.go` | OpenRouter embedding client | ✅ Complete |
| `vision.go` | Image description via vision models | ✅ Complete |
| `serialize.go` | `[WEBFURL]` text format for LLM context | ✅ Complete |
| `unfold.go` | Budget-based unfolding with semantic search | ✅ Complete |
| `actions.go` | Action types (Click, Fill, Select, Toggle) | ✅ Complete |
| `hasher.go` | SHA-256 structural/content hashing | ✅ Complete |
| `graph.go` | Multi-page semantic graph | ✅ Complete |
| `extractor.go` | Integration with engine package | ✅ Complete |

**Test Coverage:** 47% statements, 38 tests passing

### 2. Benchmark Suite (`brws/semantic/bench/`)

- `Result` struct: HTML size, tokens, latency, cache hits
- `Suite.RunURL()`: Benchmark single URL
- `Suite.RunBatch()`: Batch processing with summaries
- JSON report generation

### 3. Vector Index (`brws/semantic/index/`)

- In-memory cosine similarity search
- `Search()` by embedding or natural language query
- `FindSimilar()` for related content discovery

**Performance (384-dim vectors):**
- 1K vectors: 1,600 QPS
- 50K vectors: 35 QPS
- Zvec (HNSW): ~1000 QPS at 10M vectors

### 4. Page Graph (`brws/semantic/graph.go`)

- Multi-page semantic graph for navigation tracking
- `PageNode` with incoming/outgoing edges
- `FindPath()` for multi-hop navigation discovery
- Hub page detection for crawl prioritization
- `CrawlSession` for building site-wide semantic maps

### 5. Spider/Crawler Framework (`brws/spider/`)

| File | Purpose | Status |
|------|---------|--------|
| `spider.go` | Spider interface, Request/Response, CSS/XPath | ✅ Complete |
| `crawler.go` | Concurrent crawler with workers | ✅ Complete |
| `scheduler.go` | Priority queue with deduplication | ✅ Complete |
| `settings.go` | Configuration (delay, concurrency, etc.) | ✅ Complete |
| `middleware.go` | Request/response middleware | ✅ Complete |
| `pipeline.go` | Item processing pipelines | ✅ Complete |
| `semantic.go` | SemanticSpider integrating extraction | ✅ Complete |

### 6. CLI Tools

| Tool | Purpose |
|------|---------|
| `cmd/semantic/` | Semantic extraction CLI |
| `cmd/semanticcrawl/` | Semantic web crawler |
| `cmd/vecbench/` | Vector backend benchmark |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Semantic Crawler                          │
├─────────────────────────────────────────────────────────────────┤
│  SemanticSpider                                                  │
│    ↓                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │   Spider     │───▶│   Engine     │───▶│  Semantic    │       │
│  │  Framework   │    │  (fetcher)   │    │  Pipeline    │       │
│  └──────────────┘    └──────────────┘    └──────────────┘       │
│         │                  │                   │                 │
│         ▼                  ▼                   ▼                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │  Scheduler   │    │   Response   │    │ SemanticTree │       │
│  │  (priority)  │    │    Body      │    │   (nodes)    │       │
│  └──────────────┘    └──────────────┘    └──────────────┘       │
│                                                │                 │
│                    ┌───────────────────────────┤                 │
│                    ▼                           ▼                 │
│            ┌──────────────┐           ┌──────────────┐         │
│            │    Cache     │           │  PageGraph   │         │
│            │   (SQLite)   │           │  (multi-page)│         │
│            └──────────────┘           └──────────────┘         │
└─────────────────────────────────────────────────────────────────┘
```

## Next Steps

### Phase 1: Enhanced Vector Storage (WIP)

**Goal:** Add HNSW-based persistent vector index for scale

**Options:**
1. **sqlite-vec** - SQLite extension with HNSW support
2. **go-vector-index** - Pure Go HNSW implementation
3. **Zvec** - Alibaba's in-process vector DB (Python/C++, via CGO)

**Decision:** Start with sqlite-vec for simplicity, consider Zvec for >100K vectors

**Implementation:**
```
brws/semantic/index/
  sqlite_vec.go      # SQLite with vector extension
  hnsw.go            # HNSW implementation (fallback)
```

### Phase 2: Multi-hop Semantic Search

**Goal:** Find interconnected content across pages (Chunkhound-style)

**Implementation:**
- Index all semantic nodes from crawled pages
- Link nodes via URL references and semantic similarity
- Traverse graph for multi-hop queries

### Phase 3: Diff-based Updates

**Goal:** Only re-extract changed DOM portions

**Implementation:**
- Track structural hashes per chunk
- Compare hashes on re-crawl
- Incremental update of semantic tree

### Phase 4: Form Schema Extraction

**Goal:** Extract form fields, types, validation rules

**Implementation:**
- Detect form elements and their constraints
- Infer field types from names/patterns
- Generate structured schema for automation

### Phase 5: Visual Grounding

**Goal:** Map semantic nodes to bounding boxes

**Implementation:**
- Extract coordinates during DOM parsing
- Associate semantic nodes with regions
- Enable vision model integration

## Current State

**Commits:**
- `dac20e3` - feat(brws/semantic): add semantic extraction system ported from Webfurl
- `b81da92` - feat(brws/semantic): add benchmarking, vector index, and page graph
- `48786e6` - feat(brws/spider): add semantic spider with vector benchmark
- `fa6a47d` - feat(brws/spider): restore crawling solution with semantic integration

**Test Status:** All passing
**Build Status:** Clean
**Coverage:** 47% statements

## Usage Examples

### Basic Extraction
```go
config := semantic.NewConfigFromEnv()
tree, stats, err := semantic.HTMLToSemanticTree(ctx, html, url, config)
// tokens: 100K → 400 (99.6% reduction)
```

### Semantic Crawl
```go
spider := spider.NewSemanticSpider("crawler", startURLs, config,
    spider.WithSemanticMaxDepth(3),
)
crawler.Run()
trees := spider.GetAllSemanticTrees()
```

### Vector Search
```go
idx := index.NewVectorIndex(embedder)
idx.AddTree(ctx, tree)
results, _ := idx.Search(ctx, "product checkout flow", 5)
```

## Key Metrics

| Metric | Target | Current |
|--------|--------|---------|
| Token reduction | >95% | ~99% ✅ |
| Cache hit rate | >80% | Variable |
| LLM latency | <2s/chunk | ~1-2s |
| Search QPS | >100 | 35-1600 |

## Dependencies

- `github.com/mattn/go-sqlite3` - SQLite cache
- `golang.org/x/net/html` - HTML parsing
- OpenRouter API - LLM + embeddings

## Files Created

```
brws/semantic/
  actions.go         # Action types
  cache.go           # SQLite cache
  cache_test.go      # Cache tests
  embeddings.go      # OpenRouter embeddings
  error.go           # Error types
  extractor.go       # Engine integration
  graph.go           # Multi-page graph
  hasher.go          # Content hashing
  integration_test.go # E2E tests
  jsonutil.go        # JSON helpers
  llm.go             # LLM client
  pipeline.go        # Main pipeline
  pipeline_test.go   # Pipeline tests
  semantic_test.go   # Core tests
  serialize.go       # [WEBFURL] format
  tree.go            # Data structures
  unfold.go          # Budget unfolding
  vision.go          # Image description
  bench/
    benchmark.go     # Benchmark harness
    benchmark_test.go
  index/
    vector.go        # In-memory index
    vector_test.go

brws/spider/
  crawler.go         # Concurrent crawler
  middleware.go      # Middleware support
  pipeline.go        # Item pipelines
  scheduler.go       # Priority queue
  semantic.go        # SemanticSpider
  settings.go        # Configuration
  spider.go          # Core Spider interface

cmd/semantic/
  main.go            # CLI tool
  benchmark.go       # Benchmark commands
  index.go           # Index commands
cmd/semanticcrawl/
  main.go            # Semantic crawler CLI
cmd/vecbench/
  main.go            # Vector backend benchmark
```
