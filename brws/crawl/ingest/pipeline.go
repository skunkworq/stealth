package ingest

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	httpclient "github.com/skunkworq/stealth/brws/network/client"
	"github.com/skunkworq/stealth/brws/core/observability"
	"github.com/skunkworq/stealth/brws/content/understand"
	"github.com/skunkworq/stealth/brws/content/understand/index"
)

type StageResult struct {
	Data    any
	Error   error
	Span    *Span
	Metrics map[string]any
}

type Stage func(ctx context.Context, input any) (*StageResult, error)

type Pipeline struct {
	config     *Config
	metrics    *observability.InMemoryCollector
	index      *index.HNSWIndex
	cache      *understand.CacheStore
	httpClient *http.Client

	// Hooks
	onPageProcessed func(ctx context.Context, result *PageResult)
}

type Config struct {
	SemanticConfig *understand.PipelineConfig
	MaxDepth       int
	Concurrency    int
	UserAgent      string
	EnableIndexing bool
	EnableCache    bool
	RequestTimeout time.Duration
}

type PageResult struct {
	URL              string
	HTMLSize         int64
	SemanticTree     *understand.SemanticTree
	CompressionStats *understand.CompressionStats
	VectorAdded      bool
	Trace            *TraceContext
	FetchDuration    time.Duration
	ExtractDuration  time.Duration
	EmbedDuration    time.Duration
	TotalDuration    time.Duration
	Error            error
}

func NewPipeline(config *Config) (*Pipeline, error) {
	cfg := httpclient.DefaultConfig()
	cfg.Timeout = config.RequestTimeout
	p := &Pipeline{
		config:     config,
		metrics:    observability.NewInMemoryCollector(),
		httpClient: httpclient.New(cfg),
	}

	if config.EnableCache {
		cache, err := understand.NewCacheStore(context.Background(), "")
		if err != nil {
			return nil, fmt.Errorf("failed to create cache: %w", err)
		}
		p.cache = cache
	}

	if config.EnableIndexing {
		p.index = index.NewHNSWIndex(1536)
	}

	observability.SetGlobalCollector(p.metrics)

	return p, nil
}

func (p *Pipeline) Close() error {
	if p.cache != nil {
		return p.cache.Close()
	}
	return nil
}

func (p *Pipeline) ProcessURL(ctx context.Context, url string) *PageResult {
	tc := NewTraceContext()
	ctx = ContextWithTrace(ctx, tc)

	start := time.Now()
	result := &PageResult{
		URL:   url,
		Trace: tc,
	}

	observability.IncCounter("pipeline_urls_queued", map[string]string{"url": url})

	// Stage 1: Fetch
	html, fetchErr := p.fetchStage(ctx, url)
	result.HTMLSize = int64(len(html))
	result.FetchDuration = time.Since(start)

	if fetchErr != nil {
		result.Error = fetchErr
		result.TotalDuration = time.Since(start)
		observability.IncCounter("pipeline_fetch_errors", map[string]string{"url": url})
		return result
	}

	// Stage 2: Extract
	extractStart := time.Now()
	tree, stats, extractErr := p.extractStage(ctx, url, html)
	result.ExtractDuration = time.Since(extractStart)

	if extractErr != nil {
		result.Error = extractErr
		result.TotalDuration = time.Since(start)
		observability.IncCounter("pipeline_extract_errors", map[string]string{"url": url})
		return result
	}

	result.SemanticTree = tree
	result.CompressionStats = stats

	// Stage 3: Embed & Index (if enabled)
	if p.index != nil {
		embedStart := time.Now()
		embedErr := p.embedStage(ctx, tree, url)
		result.EmbedDuration = time.Since(embedStart)
		result.VectorAdded = embedErr == nil

		if embedErr != nil {
			observability.IncCounter("pipeline_embed_errors", map[string]string{"url": url})
		}
	}

	result.TotalDuration = time.Since(start)

	observability.IncCounter("pipeline_urls_processed", map[string]string{"url": url})
	observability.SetGauge("pipeline_compression_ratio",
		float64(stats.CompressedTokens)/float64(stats.FullTreeTokens),
		map[string]string{"url": url})

	if p.onPageProcessed != nil {
		p.onPageProcessed(ctx, result)
	}

	return result
}

func (p *Pipeline) fetchStage(ctx context.Context, url string) (string, error) {
	tc := TraceFromContext(ctx)
	var span *Span
	if tc != nil {
		span = tc.StartSpan("fetch")
		defer span.End()
		span.SetAttribute("url", url)
	}

	timer := observability.StartTimer("stage_fetch_duration", map[string]string{"url": url})
	defer timer.Stop()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		if span != nil {
			span.SetError(err)
		}
		return "", fmt.Errorf("create request: %w", err)
	}

	if p.config.UserAgent != "" {
		req.Header.Set("User-Agent", p.config.UserAgent)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		if span != nil {
			span.SetError(err)
		}
		return "", fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()

	if span != nil {
		span.SetAttribute("status_code", resp.StatusCode)
		span.AddEvent("headers_received", map[string]any{
			"content_type": resp.Header.Get("Content-Type"),
		})
	}

	if resp.StatusCode >= 400 {
		err := fmt.Errorf("status %d", resp.StatusCode)
		if span != nil {
			span.SetError(err)
		}
		return "", err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if span != nil {
			span.SetError(err)
		}
		return "", fmt.Errorf("read body: %w", err)
	}

	observability.IncCounter("stage_fetch_bytes", map[string]string{"url": url})
	observability.AddCounter("stage_fetch_bytes_total", int64(len(body)), nil)

	return string(body), nil
}

func (p *Pipeline) extractStage(ctx context.Context, url, html string) (*understand.SemanticTree, *understand.CompressionStats, error) {
	tc := TraceFromContext(ctx)
	var span *Span
	if tc != nil {
		span = tc.StartSpan("extract")
		defer span.End()
		span.SetAttribute("url", url)
		span.SetAttribute("html_size", len(html))
	}

	timer := observability.StartTimer("stage_extract_duration", map[string]string{"url": url})
	defer timer.Stop()

	config := p.config.SemanticConfig
	if config == nil {
		config = &understand.PipelineConfig{}
	}
	if p.cache != nil {
		config.Cache = p.cache
	}

	tree, stats, err := understand.HTMLToSemanticTreeCached(ctx, html, url, config)
	if err != nil {
		if span != nil {
			span.SetError(err)
		}
		observability.IncCounter("stage_extract_errors", map[string]string{"url": url})
		return nil, nil, err
	}

	if span != nil {
		span.SetAttribute("compressed_tokens", stats.CompressedTokens)
		span.SetAttribute("full_tokens", stats.FullTreeTokens)
		span.SetAttribute("chunks_total", stats.TotalChunks)
		span.SetAttribute("chunks_llm", stats.ChunksLLMCompressed)
		span.SetAttribute("chunks_cached", stats.ChunksCached)
	}

	observability.AddCounter("stage_extract_tokens_compressed", int64(stats.CompressedTokens), nil)
	observability.AddCounter("stage_extract_tokens_full", int64(stats.FullTreeTokens), nil)
	observability.AddCounter("stage_extract_chunks_llm", int64(stats.ChunksLLMCompressed), nil)
	observability.AddCounter("stage_extract_chunks_cached", int64(stats.ChunksCached), nil)

	return tree, stats, nil
}

func (p *Pipeline) embedStage(ctx context.Context, tree *understand.SemanticTree, url string) error {
	tc := TraceFromContext(ctx)
	var span *Span
	if tc != nil {
		span = tc.StartSpan("embed")
		defer span.End()
		span.SetAttribute("url", url)
	}

	timer := observability.StartTimer("stage_embed_duration", map[string]string{"url": url})
	defer timer.Stop()

	summary := tree.Title
	if summary == "" {
		summary = tree.URL
	}

	var embedding []float32
	if len(tree.RootNodes) > 0 && tree.RootNodes[0].Embedding != nil {
		embedding = tree.RootNodes[0].Embedding
	} else {
		embedding = make([]float32, 1536)
	}

	if err := p.index.Add(tree.StructuralHash, url, embedding, summary); err != nil {
		if span != nil {
			span.SetError(err)
		}
		return err
	}

	if span != nil {
		span.SetAttribute("indexed", true)
	}

	observability.IncCounter("stage_embed_vectors_added", nil)

	return nil
}

func (p *Pipeline) ProcessBatch(ctx context.Context, urls []string) []*PageResult {
	results := make([]*PageResult, len(urls))

	type job struct {
		idx int
		url string
	}

	jobs := make(chan job, len(urls))
	resultsCh := make(chan struct {
		idx int
		res *PageResult
	}, len(urls))

	for i, url := range urls {
		jobs <- job{idx: i, url: url}
	}
	close(jobs)

	concurrency := p.config.Concurrency
	if concurrency < 1 {
		concurrency = 4
	}

	for i := 0; i < concurrency; i++ {
		go func() {
			for j := range jobs {
				res := p.ProcessURL(ctx, j.url)
				resultsCh <- struct {
					idx int
					res *PageResult
				}{idx: j.idx, res: res}
			}
		}()
	}

	for i := 0; i < len(urls); i++ {
		r := <-resultsCh
		results[r.idx] = r.res
	}

	return results
}

func (p *Pipeline) Metrics() *observability.InMemoryCollector {
	return p.metrics
}

func (p *Pipeline) OnPageProcessed(fn func(ctx context.Context, result *PageResult)) {
	p.onPageProcessed = fn
}

func (p *Pipeline) Index() *index.HNSWIndex {
	return p.index
}

func (p *Pipeline) Search(query []float32, limit int) []index.SearchResult {
	observability.IncCounter("pipeline_searches", nil)

	if p.index == nil {
		return nil
	}

	results := p.index.Search(query, limit)
	return results
}
