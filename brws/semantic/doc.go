// Package semantic provides HTML-to-semantic-tree extraction with LLM compression.
//
// The semantic package transforms web pages into compressed hierarchical trees
// suitable for LLM context windows. It achieves ~99% token reduction by:
//   - Chunking DOM into digestible fragments
//   - Compressing each chunk via LLM summarization
//   - Caching results by content hash
//   - Building hierarchical semantic structures
//
// # Architecture Overview
//
// The extraction pipeline operates in three phases:
//
//  1. DOM Chunking: Split HTML into manageable fragments based on structure
//  2. LLM Compression: Summarize each chunk's semantic meaning
//  3. Tree Building: Assemble chunks into hierarchical SemanticTree
//
// # Quick Start
//
// Basic extraction:
//
//	config, _ := semantic.NewConfigFromEnv()
//	tree, stats, err := semantic.HTMLToSemanticTree(ctx, html, url, config)
//	// tree: hierarchical semantic structure
//	// stats: compression metrics (tokens, chunks, cache hits)
//
// With caching:
//
//	cache, _ := semantic.NewCacheStore(ctx, "")
//	defer cache.Close()
//	config.Cache = cache
//
//	tree, stats, err := semantic.HTMLToSemanticTreeCached(ctx, html, url, config)
//
// # Semantic Trees
//
// A SemanticTree represents a compressed web page:
//
//	type SemanticTree struct {
//	    URL                  string         // Original URL
//	    Domain               string         // Extracted domain
//	    Title                string         // Page title
//	    RootNodes            []SemanticNode // Hierarchical nodes
//	    CompressedTokenCount uint32         // Tokens in compressed form
//	    FullTokenCount       uint32         // Tokens in original HTML
//	    StructuralHash       string         // SHA-256 hash of structure
//	}
//
// Each SemanticNode contains:
//   - Summary: Semantic description of the content
//   - Actions: Interactive elements (click, fill, select)
//   - Children: Nested semantic nodes
//   - Embedding: Vector representation for similarity search
//
// # Compression Pipeline
//
// The pipeline.go file contains the core extraction logic:
//
//	HTML → cleanAndParseHTML → chunkDOM → compressChunksParallel → SemanticTree
//
// Each chunk is processed independently:
//   - Check cache for existing content hash
//   - If miss: Send to LLM for summarization
//   - If hit: Reuse cached summary
//   - Build SemanticNode with actions and embeddings
//
// # Configuration
//
//	PipelineConfig struct {
//	    LLMClient        *LLMClient       // OpenRouter client
//	    EmbeddingClient  *EmbeddingClient // Vector embeddings
//	    VisionClient     *VisionClient   // Image description
//	    Cache            *CacheStore      // SQLite cache
//	    MaxDepth         int              // Max DOM tree depth
//	    MinContentLen    int              // Min content length
//	    MaxChunks        int              // Limit for large pages
//	    MaxConcurrentLLM int              // Rate limiter (default: 10)
//	}
//
// # LLM Integration
//
// The package uses OpenRouter for LLM and embedding services:
//
//	apiKey := os.Getenv("OPENROUTER_API_KEY")
//	llmClient := semantic.NewLLMClient(apiKey)
//	llmClient.WithCompressModel("openai/gpt-oss-120b")
//
// Without an API key, the system gracefully degrades to structural
// extraction without semantic compression (pipeline_nollm.go).
//
// # Caching
//
// SQLite-backed content-addressed cache:
//
//	cache, _ := semantic.NewCacheStore(ctx, "~/.semantic/cache.db")
//	defer cache.Close()
//
//	// Automatic on HTMLToSemanticTreeCached
//	stats.ChunksCached    // Number of cache hits
//	stats.ChunksLLMCompressed // Number of LLM calls
//
// # Form Extraction
//
// Extract structured form schemas:
//
//	forms := semantic.ExtractFormSchemas(html)
//	// []FormSchema with:
//	// - Action URL and method
//	// - Field names, types, labels
//	// - Validation constraints (required, min/max length)
//	// - CSRF token detection
//
// # Visual Grounding
//
// Map semantic nodes to page coordinates:
//
//	grounding := semantic.ExtractVisualGrounding(html, 1920, 1080)
//	for _, el := range grounding.Elements {
//	    fmt.Printf("%s: (%.0f, %.0f) %.0fx%.0f\n",
//	        el.Selector, el.BoundingBox.X, el.BoundingBox.Y,
//	        el.BoundingBox.Width, el.BoundingBox.Height)
//	}
//
// # Incremental Updates
//
// Diff two semantic trees for incremental updates:
//
//	diff := semantic.ComputeDiff(oldTree, newTree)
//	// diff.ChangedChunks  - Modified nodes
//	// diff.AddedChunks    - New nodes
//	// diff.RemovedChunks  - Deleted nodes
//	// diff.Summary()      - Human-readable report
//
// Use IncrementalUpdater for tracked crawling:
//
//	updater := semantic.NewIncrementalUpdater(cache, config)
//	tree, diff, err := updater.Update(ctx, url, html)
//
// # Vector Index
//
// The index sub-package provides similarity search:
//
//	idx := index.NewHNSWIndex(1536)  // 1536-dimensional vectors
//	idx.Add(nodeID, url, embedding, summary)
//
//	results := idx.Search(queryVector, k)
//
// # Serialization
//
// Convert trees to [WEBFURL] format for LLM context:
//
//	serialized := semantic.SerializeTree(tree, state, nil)
//	// [WEBFURL] format with hierarchical structure
//
// Budget-aware unfolding:
//
//	state := semantic.InitialPack(tree, 4000, 16000)
//	tree, _ := semantic.HTMLToSemanticTreeCached(ctx, html, url, config)
//	semantic.AutoUnfold(tree, state)
//
// # Metrics and Monitoring
//
// Use CompressionStats for monitoring:
//
//	stats := &CompressionStats{
//	    RawHTMLBytes:        int64(len(html)),
//	    CleanHTMLBytes:      int64(len(cleanHTML)),
//	    TotalChunks:         chunkCount,
//	    ChunksCached:        cacheHits,
//	    ChunksLLMCompressed: llmCalls,
//	    CompressedTokens:    compressedTokens,
//	    FullTreeTokens:      fullTokens,
//	}
//
//	stats.CompressionRatio()     // 0.004 for 99.6% reduction
//	stats.EstimatedRawTokens()   // Original token count
//	stats.TokensSaved()          // Tokens reduced
//
// # Performance
//
// Typical performance on production sites:
//
//	| Site         | HTML Size | Duration | Compression |
//	|--------------|-----------|----------|-------------|
//	| GitHub       | 561KB     | 40s      | 99.6%       |
//	| Hacker News  | 34KB      | 59s      | 99.9%       |
//	| Wikipedia    | 438KB     | 160s     | 99.6%       |
//	| httpbin.org  | 3.8KB     | 1.1s     | 94.2%       |
//
// # Cost Analysis
//
// See docs/SEMANTIC_COSTS.md for detailed analysis:
//   - LLM tokens spent: ~10,500 for GitHub (one-time)
//   - Compression: 140K → 18 tokens (99.99% reduction)
//   - Break-even: After 0.1 queries to downstream LLM
//
// # Error Handling
//
// The package defines specific error types:
//
//	var err *semantic.LLMError
//	if errors.As(err, &e) {
//	    // LLM API error
//	}
//
//	var err *semantic.CacheError
//	if errors.As(err, &e) {
//	    // SQLite cache error
//	}
//
// # Graceful Degradation
//
// Without OPENROUTER_API_KEY, the system falls back to structural extraction:
//
//	tree, stats, err := semantic.HTMLToSemanticTree(ctx, html, url, &semantic.PipelineConfig{})
//	// No LLM calls, structural nodes only, minimal token usage
package semantic
