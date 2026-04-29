package spider

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/skunkworq/stealth/brws/content/semantic"
)

type SemanticSpider struct {
	name           string
	startURLs      []string
	config         *semantic.PipelineConfig
	maxDepth       int
	allowedDomains []string
	denyPatterns   []string

	mu           sync.Mutex
	visited      map[string]bool
	semanticTree map[string]*semantic.SemanticTree
	pageGraph    *semantic.PageGraph

	stats      *SemanticStats
	onPage     func(url string, tree *semantic.SemanticTree)
	onComplete func(stats *SemanticStats)
}

type SemanticStats struct {
	PagesVisited     int64
	TotalTokens      int64
	CompressedTokens int64
	InteractiveFound int64
	LLMCalls         int64
	CacheHits        int64
	Errors           int64
	Duration         time.Duration
}

func (s *SemanticStats) CompressionRatio() float64 {
	if s.TotalTokens == 0 {
		return 0
	}
	return float64(s.CompressedTokens) / float64(s.TotalTokens)
}

func (s *SemanticStats) TokensSaved() int64 {
	return s.TotalTokens - s.CompressedTokens
}

type SemanticSpiderOption func(*SemanticSpider)

func WithSemanticMaxDepth(depth int) SemanticSpiderOption {
	return func(s *SemanticSpider) {
		s.maxDepth = depth
	}
}

func WithAllowedDomains(domains []string) SemanticSpiderOption {
	return func(s *SemanticSpider) {
		s.allowedDomains = domains
	}
}

func WithOnPage(fn func(url string, tree *semantic.SemanticTree)) SemanticSpiderOption {
	return func(s *SemanticSpider) {
		s.onPage = fn
	}
}

func WithOnComplete(fn func(stats *SemanticStats)) SemanticSpiderOption {
	return func(s *SemanticSpider) {
		s.onComplete = fn
	}
}

func NewSemanticSpider(name string, startURLs []string, config *semantic.PipelineConfig, opts ...SemanticSpiderOption) *SemanticSpider {
	s := &SemanticSpider{
		name:         name,
		startURLs:    startURLs,
		config:       config,
		maxDepth:     3,
		visited:      make(map[string]bool),
		semanticTree: make(map[string]*semantic.SemanticTree),
		pageGraph:    semantic.NewPageGraph(),
		stats:        &SemanticStats{},
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

func (s *SemanticSpider) Name() string {
	return s.name
}

func (s *SemanticSpider) Start() []*Request {
	requests := make([]*Request, len(s.startURLs))
	for i, url := range s.startURLs {
		requests[i] = NewRequest(url, s.parsePage).SetDepth(1).SetMeta("semantic", true)
	}
	return requests
}

func (s *SemanticSpider) Parse(resp Response) []*Request {
	return s.parsePage(resp)
}

func (s *SemanticSpider) parsePage(resp Response) []*Request {
	ctx := context.Background()
	url := resp.URL

	s.mu.Lock()
	if s.visited[url] {
		s.mu.Unlock()
		return nil
	}
	s.visited[url] = true
	s.mu.Unlock()

	atomic.AddInt64(&s.stats.PagesVisited, 1)

	tree, stats, err := semantic.HTMLToSemanticTreeCached(ctx, resp.Text, url, s.config)
	if err != nil {
		atomic.AddInt64(&s.stats.Errors, 1)
		return nil
	}

	atomic.AddInt64(&s.stats.TotalTokens, int64(stats.FullTreeTokens))
	atomic.AddInt64(&s.stats.CompressedTokens, int64(stats.CompressedTokens))
	atomic.AddInt64(&s.stats.LLMCalls, int64(stats.ChunksLLMCompressed))
	atomic.AddInt64(&s.stats.CacheHits, int64(stats.ChunksCached))

	s.mu.Lock()
	s.semanticTree[url] = tree
	s.pageGraph.AddPage(tree)
	s.mu.Unlock()

	interactive := 0
	for _, root := range tree.RootNodes {
		interactive += countActions(&root)
	}
	atomic.AddInt64(&s.stats.InteractiveFound, int64(interactive))

	if s.onPage != nil {
		s.onPage(url, tree)
	}

	var followRequests []*Request
	links := resp.GetLinks()

	for _, link := range links {
		absoluteURL := resolveURL(url, link)
		if absoluteURL == "" {
			continue
		}

		if !s.isAllowed(absoluteURL) {
			continue
		}

		s.mu.Lock()
		visited := s.visited[absoluteURL]
		s.mu.Unlock()

		if !visited && (s.maxDepth == 0 || resp.Request.Depth < s.maxDepth) {
			followRequests = append(followRequests, NewRequest(absoluteURL, s.parsePage).
				SetDepth(resp.Request.Depth+1).
				SetMeta("semantic", true).
				SetMeta("from_url", url))
		}
	}

	return followRequests
}

func (s *SemanticSpider) isAllowed(urlStr string) bool {
	if len(s.allowedDomains) == 0 {
		return true
	}

	domain := extractDomain(urlStr)
	for _, allowed := range s.allowedDomains {
		if domain == allowed || len(domain) > len(allowed) && domain[len(domain)-len(allowed)-1:] == "."+allowed {
			return true
		}
	}
	return false
}

func (s *SemanticSpider) GetSemanticTree(url string) *semantic.SemanticTree {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.semanticTree[url]
}

func (s *SemanticSpider) GetAllSemanticTrees() map[string]*semantic.SemanticTree {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make(map[string]*semantic.SemanticTree)
	for k, v := range s.semanticTree {
		result[k] = v
	}
	return result
}

func (s *SemanticSpider) GetPageGraph() *semantic.PageGraph {
	return s.pageGraph
}

func (s *SemanticSpider) GetStats() *SemanticStats {
	return s.stats
}

func countActions(node *semantic.SemanticNode) int {
	count := len(node.Actions)
	for i := range node.Children {
		count += countActions(&node.Children[i])
	}
	return count
}

func extractDomain(urlStr string) string {
	if len(urlStr) < 8 {
		return ""
	}
	if urlStr[:8] == "https://" {
		urlStr = urlStr[8:]
	} else if urlStr[:7] == "http://" {
		urlStr = urlStr[7:]
	}
	for i, c := range urlStr {
		if c == '/' || c == ':' || c == '?' {
			return urlStr[:i]
		}
	}
	return urlStr
}

func resolveURL(base, href string) string {
	if len(href) < 2 {
		return ""
	}
	if href[:2] == "//" {
		return "https:" + href
	}
	if len(href) > 4 && (href[:4] == "http" || href[:4] == "HTTP") {
		return href
	}
	if href[0] == '/' {
		domain := extractDomain(base)
		if domain == "" {
			return ""
		}
		proto := "https"
		if len(base) > 7 && base[:7] == "http://" {
			proto = "http"
		}
		return proto + "://" + domain + href
	}
	return ""
}
