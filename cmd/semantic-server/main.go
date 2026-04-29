package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/skunkworq/stealth/brws/crawl/pipeline"
	"github.com/skunkworq/stealth/brws/content/semantic"
	"github.com/skunkworq/stealth/brws/content/semantic/index"
)

type SemanticMCPServer struct {
	config   *semantic.PipelineConfig
	pipeline *pipeline.Pipeline
	cache    *semantic.CacheStore
	index    *index.HNSWIndex
	apiKey   string

	mu        sync.RWMutex
	crawlJobs map[string]*CrawlJob
	trees     map[string]*semantic.SemanticTree
	grounding map[string]*GroundingResult
}

type CrawlJob struct {
	ID        string
	URLs      []string
	Status    string
	Progress  int
	Total     int
	StartTime time.Time
	Results   []*pipeline.PageResult
	Error     error
}

type GroundingResult struct {
	URL      string
	Width    int
	Height   int
	Elements []GroundedElement
}

type GroundedElement struct {
	Selector string  `json:"selector"`
	XPath    string  `json:"xpath"`
	X        float64 `json:"x"`
	Y        float64 `json:"y"`
	Width    float64 `json:"width"`
	Height   float64 `json:"height"`
	Tag      string  `json:"tag"`
	Text     string  `json:"text"`
}

func main() {
	ctx := context.Background()

	apiKey := os.Getenv("OPENROUTER_API_KEY")
	if apiKey == "" || apiKey == "-" {
		log.Println("Warning: OPENROUTER_API_KEY not set, using no-LLM mode")
		apiKey = ""
	}

	// Initialize semantic config
	var semanticConfig *semantic.PipelineConfig
	if apiKey != "" {
		llmClient := semantic.NewLLMClient(apiKey)
		semanticConfig = &semantic.PipelineConfig{
			LLMClient:        llmClient,
			MaxChunks:        200,
			MaxConcurrentLLM: 10,
		}
	} else {
		semanticConfig = &semantic.PipelineConfig{}
	}

	// Initialize cache
	cache, err := semantic.NewCacheStore(ctx, "")
	if err != nil {
		log.Printf("Warning: Failed to create cache: %v", err)
		cache = nil
	}

	// Initialize pipeline
	pipeConfig := &pipeline.Config{
		SemanticConfig: semanticConfig,
		Concurrency:    4,
		RequestTimeout: 5 * time.Minute,
		EnableCache:    cache != nil,
		EnableIndexing: true,
		UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	}

	pipe, err := pipeline.NewPipeline(pipeConfig)
	if err != nil {
		log.Fatalf("Failed to create pipeline: %v", err)
	}
	defer pipe.Close()

	// Initialize MCP server
	mcpServer := &SemanticMCPServer{
		config:    semanticConfig,
		pipeline:  pipe,
		cache:     cache,
		index:     index.NewHNSWIndex(1536),
		apiKey:    apiKey,
		crawlJobs: make(map[string]*CrawlJob),
		trees:     make(map[string]*semantic.SemanticTree),
		grounding: make(map[string]*GroundingResult),
	}

	if cache != nil {
		defer cache.Close()
	}

	s := server.NewMCPServer(
		"semantic-extractor",
		"2.0.0",
		server.WithToolCapabilities(true),
	)

	// === EXTRACTION TOOLS ===
	s.AddTool(mcp.NewTool("extract_semantic_tree",
		mcp.WithDescription(`Extract a semantic tree from a URL or HTML content.
		
Returns a compressed hierarchical representation optimized for LLM context.
Achieves ~99% token reduction via LLM summarization and caching.

Use this when you need to understand a page's structure and content.`),
		mcp.WithString("url", mcp.Required(), mcp.Description("URL to extract from")),
		mcp.WithString("html", mcp.Description("Optional HTML (if provided, URL is for context only)")),
		mcp.WithBoolean("include_forms", mcp.Description("Extract form schemas")),
		mcp.WithBoolean("include_actions", mcp.Description("Extract interactive elements")),
	), mcpServer.extractSemanticTree)

	s.AddTool(mcp.NewTool("extract_forms",
		mcp.WithDescription(`Extract form schemas from HTML content.

Returns structured form information including:
- Form action URLs and methods
- Field names, types, labels
- Validation constraints (required, min/max length)
- CSRF tokens detected

Use this to understand what data a form accepts.`),
		mcp.WithString("url", mcp.Required(), mcp.Description("URL to extract forms from")),
	), mcpServer.extractForms)

	s.AddTool(mcp.NewTool("extract_actions",
		mcp.WithDescription(`Extract interactive elements (clickable, fillable) from a page.

Returns list of actions with:
- Element selectors (CSS, XPath)
- Action types (click, fill, select)
- Descriptions of what each element does

Use this to understand what interactions are possible.`),
		mcp.WithString("url", mcp.Required(), mcp.Description("URL to extract actions from")),
	), mcpServer.extractActions)

	// === CRAWLING TOOLS ===
	s.AddTool(mcp.NewTool("crawl_urls",
		mcp.WithDescription(`Crawl multiple URLs concurrently with semantic extraction.

Processes URLs in parallel, extracts semantic trees, and indexes content.
Returns a crawl job ID for status tracking.

Use this for bulk processing of multiple pages.`),
		mcp.WithString("urls", mcp.Required(), mcp.Description("Comma-separated list of URLs to crawl")),
		mcp.WithNumber("concurrency", mcp.Description("Number of concurrent workers (default: 4)")),
	), mcpServer.crawlURLs)

	s.AddTool(mcp.NewTool("get_crawl_status",
		mcp.WithDescription(`Get status of a crawl job.

Returns progress, completed URLs, errors, and partial results.
Use job_id from previous crawl_urls call.`),
		mcp.WithString("job_id", mcp.Required(), mcp.Description("Crawl job ID")),
	), mcpServer.getCrawlStatus)

	// === SEARCH TOOLS ===
	s.AddTool(mcp.NewTool("search_content",
		mcp.WithDescription(`Search crawled content by description using semantic similarity.

Finds pages that match the query description.
Requires previous crawl or extract operations to have indexed content.

Use this to find relevant pages from previously crawled content.`),
		mcp.WithString("query", mcp.Required(), mcp.Description("Description of content to find")),
		mcp.WithNumber("limit", mcp.Description("Maximum results (default: 10)")),
	), mcpServer.searchContent)

	s.AddTool(mcp.NewTool("find_similar_pages",
		mcp.WithDescription(`Find pages similar to a given URL.

Uses vector similarity to find related content from crawled pages.
Useful for discovering related content.`),
		mcp.WithString("url", mcp.Required(), mcp.Description("URL to find similar pages for")),
		mcp.WithNumber("limit", mcp.Description("Maximum results (default: 5)")),
	), mcpServer.findSimilarPages)

	// === ANALYSIS TOOLS ===
	s.AddTool(mcp.NewTool("analyze_page",
		mcp.WithDescription(`Perform comprehensive page analysis.

Returns:
- Semantic tree (compressed structure)
- Form schemas
- Interactive actions
- Navigation links
- Content statistics

Use this for complete page understanding.`),
		mcp.WithString("url", mcp.Required(), mcp.Description("URL to analyze")),
	), mcpServer.analyzePage)

	s.AddTool(mcp.NewTool("compare_pages",
		mcp.WithDescription(`Compare two pages and identify differences.

Returns:
- Added/removed/modified nodes
- Changed forms
- New interactive elements
- Structural changes

Use this to detect page changes or A/B variations.`),
		mcp.WithString("url1", mcp.Required(), mcp.Description("First URL to compare")),
		mcp.WithString("url2", mcp.Required(), mcp.Description("Second URL to compare")),
	), mcpServer.comparePages)

	// === SERIALIZATION TOOLS ===
	s.AddTool(mcp.NewTool("serialize_for_llm",
		mcp.WithDescription(`Serialize a page to [WEBFURL] format optimized for LLM context.

Compressed text format suitable for feeding to LLM.
Respects token budget to fit context windows.

Use this to prepare page content for LLM analysis.`),
		mcp.WithString("url", mcp.Required(), mcp.Description("URL to serialize")),
		mcp.WithNumber("token_budget", mcp.Description("Maximum tokens (default: 4000)")),
	), mcpServer.serializeForLLM)

	log.Println("Semantic MCP Server starting...")
	log.Println("Tools available: extract_semantic_tree, extract_forms, extract_actions, crawl_urls, get_crawl_status, search_content, find_similar_pages, analyze_page, compare_pages, serialize_for_llm")

	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

// === EXTRACTION IMPLEMENTATIONS ===

func (s *SemanticMCPServer) extractSemanticTree(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	url, err := req.RequireString("url")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	html := req.GetString("html", "")
	includeForms := req.GetBool("include_forms", false)
	includeActions := req.GetBool("include_actions", false)

	start := time.Now()
	var tree *semantic.SemanticTree
	var stats *semantic.CompressionStats

	if html != "" {
		tree, stats, err = semantic.HTMLToSemanticTreeCached(ctx, html, url, s.config)
	} else {
		html, err = s.fetchURL(ctx, url)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch: %v", err)), nil
		}
		tree, stats, err = semantic.HTMLToSemanticTreeCached(ctx, html, url, s.config)
	}

	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Extraction failed: %v", err)), nil
	}

	// Store for later use
	s.mu.Lock()
	s.trees[url] = tree
	s.mu.Unlock()

	result := map[string]interface{}{
		"url":               tree.URL,
		"title":             tree.Title,
		"domain":            tree.Domain,
		"compressed_tokens": stats.CompressedTokens,
		"original_tokens":   stats.FullTreeTokens,
		"root_nodes":        len(tree.RootNodes),
		"duration_ms":       time.Since(start).Milliseconds(),
		"chunks_processed":  stats.TotalChunks,
		"llm_calls":         stats.ChunksLLMCompressed,
		"cache_hits":        stats.ChunksCached,
	}

	if stats.FullTreeTokens > 0 {
		result["compression_ratio"] = fmt.Sprintf("%.2f%%",
			float64(stats.CompressedTokens)/float64(stats.FullTreeTokens)*100)
	}

	if includeForms {
		forms := semantic.ExtractFormSchemas(html)
		result["forms"] = forms
		result["forms_count"] = len(forms)
	}

	if includeActions {
		actions := s.extractAllActions(tree)
		result["actions"] = actions
		result["actions_count"] = len(actions)
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (s *SemanticMCPServer) extractForms(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	url, err := req.RequireString("url")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	html, err := s.fetchURL(ctx, url)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch: %v", err)), nil
	}

	forms := semantic.ExtractFormSchemas(html)

	result := map[string]interface{}{
		"url":         url,
		"forms_count": len(forms),
		"forms":       forms,
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (s *SemanticMCPServer) extractActions(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	url, err := req.RequireString("url")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Get or extract tree
	s.mu.RLock()
	tree, exists := s.trees[url]
	s.mu.RUnlock()

	if !exists {
		html, err := s.fetchURL(ctx, url)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch: %v", err)), nil
		}
		tree, _, err = semantic.HTMLToSemanticTreeCached(ctx, html, url, s.config)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Extraction failed: %v", err)), nil
		}
		s.mu.Lock()
		s.trees[url] = tree
		s.mu.Unlock()
	}

	actions := s.extractAllActions(tree)

	result := map[string]interface{}{
		"url":           url,
		"actions_count": len(actions),
		"actions":       actions,
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

// === CRAWLING IMPLEMENTATIONS ===

func (s *SemanticMCPServer) crawlURLs(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	urlsStr, err := req.RequireString("urls")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	concurrency := int(req.GetInt("concurrency", 4))

	urls := strings.Split(urlsStr, ",")
	for i := range urls {
		urls[i] = strings.TrimSpace(urls[i])
	}

	jobID := fmt.Sprintf("crawl_%d", time.Now().UnixNano())

	job := &CrawlJob{
		ID:        jobID,
		URLs:      urls,
		Status:    "running",
		Total:     len(urls),
		StartTime: time.Now(),
		Results:   make([]*pipeline.PageResult, 0),
	}

	s.mu.Lock()
	s.crawlJobs[jobID] = job
	s.mu.Unlock()

	// Run in background
	go s.runCrawlJob(jobID, urls, concurrency)

	result := map[string]interface{}{
		"job_id":     jobID,
		"status":     "started",
		"total_urls": len(urls),
		"message":    "Crawl started. Use get_crawl_status to check progress.",
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (s *SemanticMCPServer) runCrawlJob(jobID string, urls []string, concurrency int) {
	ctx := context.Background()

	s.pipeline.OnPageProcessed(func(ctx context.Context, result *pipeline.PageResult) {
		s.mu.Lock()
		if job, exists := s.crawlJobs[jobID]; exists {
			job.Results = append(job.Results, result)
			job.Progress = len(job.Results)

			// Index the result
			if result.SemanticTree != nil && result.Error == nil {
				s.trees[result.URL] = result.SemanticTree
				// Add to vector index
				if len(result.SemanticTree.RootNodes) > 0 {
					embedding := result.SemanticTree.RootNodes[0].Embedding
					if embedding == nil {
						embedding = make([]float32, 1536)
					}
					s.index.Add(
						result.SemanticTree.StructuralHash,
						result.URL,
						embedding,
						result.SemanticTree.Title,
					)
				}
			}
		}
		s.mu.Unlock()
	})

	results := s.pipeline.ProcessBatch(ctx, urls)

	s.mu.Lock()
	if job, exists := s.crawlJobs[jobID]; exists {
		job.Status = "completed"
		job.Results = results
		if len(results) > 0 && results[len(results)-1].Error != nil {
			job.Error = results[len(results)-1].Error
		}
	}
	s.mu.Unlock()
}

func (s *SemanticMCPServer) getCrawlStatus(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	jobID, err := req.RequireString("job_id")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	s.mu.RLock()
	job, exists := s.crawlJobs[jobID]
	s.mu.RUnlock()

	if !exists {
		return mcp.NewToolResultError("Job not found"), nil
	}

	result := map[string]interface{}{
		"job_id":     job.ID,
		"status":     job.Status,
		"progress":   job.Progress,
		"total":      job.Total,
		"started_at": job.StartTime.Format(time.RFC3339),
		"duration":   time.Since(job.StartTime).String(),
	}

	if job.Status == "completed" {
		var success, failed int
		var totalCompressed, totalOriginal int64

		for _, r := range job.Results {
			if r.Error != nil {
				failed++
			} else {
				success++
				if r.CompressionStats != nil {
					totalCompressed += int64(r.CompressionStats.CompressedTokens)
					totalOriginal += int64(r.CompressionStats.FullTreeTokens)
				}
			}
		}

		result["completed"] = map[string]interface{}{
			"success":           success,
			"failed":            failed,
			"total_compressed":  totalCompressed,
			"total_original":    totalOriginal,
			"compression_ratio": fmt.Sprintf("%.2f%%", float64(totalCompressed)/float64(totalOriginal)*100),
		}
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

// === SEARCH IMPLEMENTATIONS ===

func (s *SemanticMCPServer) searchContent(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query, err := req.RequireString("query")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	limit := int(req.GetInt("limit", 10))

	// For now, search by matching tree titles/summaries
	// TODO: Use embedding-based semantic search when available

	s.mu.RLock()
	results := make([]map[string]interface{}, 0)
	for url, tree := range s.trees {
		if strings.Contains(strings.ToLower(tree.Title), strings.ToLower(query)) {
			results = append(results, map[string]interface{}{
				"url":    url,
				"title":  tree.Title,
				"score":  1.0,
				"tokens": tree.CompressedTokenCount,
			})
			if len(results) >= limit {
				break
			}
		}
	}
	s.mu.RUnlock()

	result := map[string]interface{}{
		"query":         query,
		"results_count": len(results),
		"results":       results,
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (s *SemanticMCPServer) findSimilarPages(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	url, err := req.RequireString("url")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	limit := int(req.GetInt("limit", 5))

	s.mu.RLock()
	tree, exists := s.trees[url]
	s.mu.RUnlock()

	if !exists {
		return mcp.NewToolResultError("URL not in index. Extract it first."), nil
	}

	// Search using tree's embedding
	var embedding []float32
	if len(tree.RootNodes) > 0 && tree.RootNodes[0].Embedding != nil {
		embedding = tree.RootNodes[0].Embedding
	} else {
		embedding = make([]float32, 1536)
	}

	results := s.index.Search(embedding, limit+1) // +1 to exclude self

	similar := make([]map[string]interface{}, 0)
	for _, r := range results {
		if r.URL != url { // Exclude the query URL itself
			similar = append(similar, map[string]interface{}{
				"url":     r.URL,
				"score":   r.Score,
				"summary": r.Content,
			})
			if len(similar) >= limit {
				break
			}
		}
	}

	result := map[string]interface{}{
		"url":           url,
		"similar_count": len(similar),
		"similar_pages": similar,
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

// === ANALYSIS IMPLEMENTATIONS ===

func (s *SemanticMCPServer) analyzePage(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	url, err := req.RequireString("url")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	html, err := s.fetchURL(ctx, url)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch: %v", err)), nil
	}

	start := time.Now()

	// Extract tree
	tree, stats, err := semantic.HTMLToSemanticTreeCached(ctx, html, url, s.config)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Extraction failed: %v", err)), nil
	}

	// Extract forms
	forms := semantic.ExtractFormSchemas(html)

	// Extract actions
	actions := s.extractAllActions(tree)

	// Extract links
	links := s.extractLinks(html)

	// Store tree
	s.mu.Lock()
	s.trees[url] = tree
	s.mu.Unlock()

	result := map[string]interface{}{
		"url":         url,
		"title":       tree.Title,
		"domain":      tree.Domain,
		"duration_ms": time.Since(start).Milliseconds(),
		"semantic": map[string]interface{}{
			"compressed_tokens": stats.CompressedTokens,
			"original_tokens":   stats.FullTreeTokens,
			"compression_ratio": fmt.Sprintf("%.2f%%", float64(stats.CompressedTokens)/float64(stats.FullTreeTokens)*100),
			"root_nodes":        len(tree.RootNodes),
			"chunks_processed":  stats.TotalChunks,
			"llm_calls":         stats.ChunksLLMCompressed,
			"cache_hits":        stats.ChunksCached,
		},
		"forms": map[string]interface{}{
			"count": len(forms),
			"list":  forms,
		},
		"actions": map[string]interface{}{
			"count": len(actions),
			"list":  actions,
		},
		"navigation": map[string]interface{}{
			"links_count": len(links),
			"links":       links,
		},
		"html_size_bytes": len(html),
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (s *SemanticMCPServer) comparePages(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	url1, err := req.RequireString("url1")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	url2, err := req.RequireString("url2")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Get or extract tree 1
	s.mu.RLock()
	tree1, exists1 := s.trees[url1]
	tree2, exists2 := s.trees[url2]
	s.mu.RUnlock()

	if !exists1 {
		html, err := s.fetchURL(ctx, url1)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch %s: %v", url1, err)), nil
		}
		tree1, _, err = semantic.HTMLToSemanticTreeCached(ctx, html, url1, s.config)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to extract %s: %v", url1, err)), nil
		}
		s.mu.Lock()
		s.trees[url1] = tree1
		s.mu.Unlock()
	}

	if !exists2 {
		html, err := s.fetchURL(ctx, url2)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch %s: %v", url2, err)), nil
		}
		tree2, _, err = semantic.HTMLToSemanticTreeCached(ctx, html, url2, s.config)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to extract %s: %v", url2, err)), nil
		}
		s.mu.Lock()
		s.trees[url2] = tree2
		s.mu.Unlock()
	}

	diff := semantic.ComputeDiff(tree1, tree2)

	result := map[string]interface{}{
		"url1":            url1,
		"url2":            url2,
		"has_changes":     diff.HasChanges(),
		"changed_count":   len(diff.ChangedChunks),
		"added_count":     len(diff.AddedChunks),
		"removed_count":   len(diff.RemovedChunks),
		"unchanged_count": diff.UnchangedCount,
		"change_percent":  diff.ChangedPercent(),
		"summary":         diff.Summary(),
		"changed_chunks":  diff.ChangedChunks,
		"added_chunks":    diff.AddedChunks,
		"removed_chunks":  diff.RemovedChunks,
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

// === SERIALIZATION IMPLEMENTATIONS ===

func (s *SemanticMCPServer) serializeForLLM(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	url, err := req.RequireString("url")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	tokenBudget := uint32(req.GetInt("token_budget", 4000))

	// Get or extract tree
	s.mu.RLock()
	tree, exists := s.trees[url]
	s.mu.RUnlock()

	if !exists {
		html, err := s.fetchURL(ctx, url)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch: %v", err)), nil
		}
		tree, _, err = semantic.HTMLToSemanticTreeCached(ctx, html, url, s.config)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Extraction failed: %v", err)), nil
		}
		s.mu.Lock()
		s.trees[url] = tree
		s.mu.Unlock()
	}

	state := semantic.InitialPack(tree, tokenBudget, tokenBudget*4)
	serialized := semantic.SerializeTree(tree, state, nil)

	result := map[string]interface{}{
		"url":                url,
		"format":             "[WEBFURL]",
		"estimated_tokens":   semantic.EstimateTokens(serialized),
		"token_budget":       tokenBudget,
		"content_length":     len(serialized),
		"serialized_content": serialized,
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

// === HELPER FUNCTIONS ===

func (s *SemanticMCPServer) fetchURL(ctx context.Context, url string) (string, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func (s *SemanticMCPServer) extractAllActions(tree *semantic.SemanticTree) []map[string]interface{} {
	actions := make([]map[string]interface{}, 0)
	for _, root := range tree.RootNodes {
		actions = append(actions, s.extractNodeActions(&root)...)
	}
	return actions
}

func (s *SemanticMCPServer) extractNodeActions(node *semantic.SemanticNode) []map[string]interface{} {
	actions := make([]map[string]interface{}, 0)

	for _, action := range node.Actions {
		actions = append(actions, map[string]interface{}{
			"type":        string(action.Type),
			"selector":    action.Selector,
			"description": action.Description,
		})
	}

	for i := range node.Children {
		actions = append(actions, s.extractNodeActions(&node.Children[i])...)
	}

	return actions
}

func (s *SemanticMCPServer) extractLinks(html string) []string {
	links := make([]string, 0)
	// Simple regex-based extraction for now
	// Could use proper HTML parser if needed

	matches := strings.FieldsFunc(html, func(r rune) bool {
		return r == ' '
	})

	for _, match := range matches {
		if strings.HasPrefix(match, "href=\"") && strings.Contains(match, "http") {
			start := strings.Index(match, "\"") + 1
			end := strings.Index(match[start:], "\"")
			if end > 0 && start+end < len(match) {
				link := match[start : start+end]
				if strings.HasPrefix(link, "http") {
					links = append(links, link)
				}
			}
		}
	}

	// Dedupe
	seen := make(map[string]bool)
	unique := make([]string, 0)
	for _, link := range links {
		if !seen[link] {
			seen[link] = true
			unique = append(unique, link)
		}
	}

	if len(unique) > 50 {
		unique = unique[:50]
	}

	return unique
}
