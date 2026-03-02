package bench

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/stealth/brwslab/brws/semantic"
)

type Result struct {
	URL                 string        `json:"url"`
	HTMLSize            int           `json:"html_size"`
	TokenCount          uint32        `json:"token_count"`
	CompressedTokens    uint32        `json:"compressed_tokens"`
	CompressionRatio    float64       `json:"compression_ratio"`
	LLMLatency          time.Duration `json:"llm_latency"`
	EmbeddingLatency    time.Duration `json:"embedding_latency"`
	CacheHit            bool          `json:"cache_hit"`
	ChunksExtracted     int           `json:"chunks_extracted"`
	InteractiveElements int           `json:"interactive_elements"`
	TreeDepth           int           `json:"tree_depth"`
	Error               string        `json:"error,omitempty"`
}

type Suite struct {
	config *semantic.PipelineConfig
	cache  *semantic.CacheStore
	client *http.Client
}

func NewSuite(config *semantic.PipelineConfig, cache *semantic.CacheStore) *Suite {
	return &Suite{
		config: config,
		cache:  cache,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (s *Suite) RunURL(ctx context.Context, url string) *Result {
	result := &Result{URL: url}

	html, htmlSize, err := s.fetchHTML(ctx, url)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.HTMLSize = htmlSize

	start := time.Now()
	tree, stats, err := semantic.HTMLToSemanticTreeCached(ctx, html, url, s.config)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.LLMLatency = time.Since(start)

	result.TokenCount = stats.FullTreeTokens
	result.CompressedTokens = stats.CompressedTokens
	if result.TokenCount > 0 {
		result.CompressionRatio = float64(result.CompressedTokens) / float64(result.TokenCount)
	}
	result.CacheHit = stats.PageCacheHit
	result.ChunksExtracted = stats.TotalChunks

	result.TreeDepth = 1
	interactive := 0
	for _, root := range tree.RootNodes {
		interactive += len(root.Actions)
		result.TreeDepth = max(result.TreeDepth, nodeDepth(root, 1))
	}
	result.InteractiveElements = interactive

	return result
}

func (s *Suite) RunFile(ctx context.Context, path string, baseURL string) *Result {
	result := &Result{URL: path}

	data, err := os.ReadFile(path)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	html := string(data)
	result.HTMLSize = len(html)

	start := time.Now()
	tree, stats, err := semantic.HTMLToSemanticTree(ctx, html, baseURL, s.config)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.LLMLatency = time.Since(start)

	result.TokenCount = stats.FullTreeTokens
	result.CompressedTokens = stats.CompressedTokens
	if result.TokenCount > 0 {
		result.CompressionRatio = float64(result.CompressedTokens) / float64(result.TokenCount)
	}

	treeDepth := 0
	for _, root := range tree.RootNodes {
		treeDepth = max(treeDepth, nodeDepth(root, 1))
	}
	result.TreeDepth = treeDepth

	return result
}

func (s *Suite) RunBatch(ctx context.Context, urls []string) []*Result {
	results := make([]*Result, len(urls))
	for i, url := range urls {
		results[i] = s.RunURL(ctx, url)
	}
	return results
}

func (s *Suite) fetchHTML(ctx context.Context, url string) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, err
	}

	return string(data), len(data), nil
}

type Summary struct {
	TotalPages          int           `json:"total_pages"`
	SuccessRate         float64       `json:"success_rate"`
	AvgCompressionRatio float64       `json:"avg_compression_ratio"`
	AvgHTMLSize         int           `json:"avg_html_size"`
	TotalTokens         uint32        `json:"total_tokens"`
	TokensSaved         int64         `json:"tokens_saved"`
	TotalInteractive    int           `json:"total_interactive"`
	Errors              int           `json:"errors"`
	LLMTotalLatency     time.Duration `json:"llm_total_latency"`
}

func (s *Suite) Summary(results []*Result) *Summary {
	if len(results) == 0 {
		return nil
	}

	summary := &Summary{
		TotalPages: len(results),
	}

	var totalRatio float64
	var totalHTML int
	var totalCompressed uint32
	var successes int

	for _, r := range results {
		if r.Error == "" {
			successes++
			totalRatio += r.CompressionRatio
			totalHTML += r.HTMLSize
			totalCompressed += r.CompressedTokens
			summary.TotalTokens += r.TokenCount
			summary.TotalInteractive += r.InteractiveElements
			summary.LLMTotalLatency += r.LLMLatency
		} else {
			summary.Errors++
		}
	}

	if successes > 0 {
		summary.AvgCompressionRatio = totalRatio / float64(successes)
	}
	summary.AvgHTMLSize = totalHTML / max(successes, 1)
	summary.SuccessRate = float64(successes) / float64(len(results))
	if summary.TotalTokens > totalCompressed {
		summary.TokensSaved = int64(summary.TotalTokens) - int64(totalCompressed)
	}

	return summary
}

func (s *Summary) String() string {
	savedPct := float64(0)
	if s.TotalTokens > 0 {
		savedPct = float64(s.TokensSaved) / float64(s.TotalTokens) * 100
	}
	return fmt.Sprintf(
		"Pages: %d | Success: %.1f%% | Compression: %.1f%% | HTML: %d bytes avg | Tokens: %d saved (%.1f%%) | LLM: %v",
		s.TotalPages,
		s.SuccessRate*100,
		(1-s.AvgCompressionRatio)*100,
		s.AvgHTMLSize,
		s.TokensSaved,
		savedPct,
		s.LLMTotalLatency.Round(time.Millisecond),
	)
}

func WriteReport(results []*Result, path string) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func nodeDepth(node semantic.SemanticNode, depth int) int {
	maxDepth := depth
	for i := range node.Children {
		maxDepth = max(maxDepth, nodeDepth(node.Children[i], depth+1))
	}
	return maxDepth
}

func max[T int | int64 | uint32 | float64](a, b T) T {
	if a > b {
		return a
	}
	return b
}
