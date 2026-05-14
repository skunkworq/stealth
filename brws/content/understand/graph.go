package understand

import (
	"context"
	"fmt"
	"sync"
)

type PageGraph struct {
	mu    sync.RWMutex
	pages map[string]*PageNode
	edges []*PageEdge
	index *PageIndex
}

type PageNode struct {
	URL         string
	Title       string
	Tree        *SemanticTree
	Incoming    int
	Outgoing    int
	Interactive int
	Tokens      uint32
	Compressed  uint32
}

type PageEdge struct {
	From     string
	To       string
	Action   *Action
	Selector string
	Count    int
}

type PageIndex struct {
	urlToNode map[string]*PageNode
	byDomain  map[string][]*PageNode
}

func NewPageGraph() *PageGraph {
	return &PageGraph{
		pages: make(map[string]*PageNode),
		edges: make([]*PageEdge, 0),
		index: &PageIndex{
			urlToNode: make(map[string]*PageNode),
			byDomain:  make(map[string][]*PageNode),
		},
	}
}

func (g *PageGraph) AddPage(tree *SemanticTree) *PageNode {
	g.mu.Lock()
	defer g.mu.Unlock()

	page := &PageNode{
		URL:         tree.URL,
		Title:       tree.Title,
		Tree:        tree,
		Tokens:      tree.FullTokenCount,
		Compressed:  tree.CompressedTokenCount,
		Interactive: countInteractive(tree),
	}

	g.pages[tree.URL] = page
	g.index.urlToNode[tree.URL] = page
	domain := tree.Domain
	g.index.byDomain[domain] = append(g.index.byDomain[domain], page)

	return page
}

func (g *PageGraph) AddNavigation(from, to string, action *Action, selector string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	existingIdx := -1
	for i, e := range g.edges {
		if e.From == from && e.To == to && e.Selector == selector {
			existingIdx = i
			break
		}
	}

	if existingIdx >= 0 {
		g.edges[existingIdx].Count++
	} else {
		g.edges = append(g.edges, &PageEdge{
			From:     from,
			To:       to,
			Action:   action,
			Selector: selector,
			Count:    1,
		})

		if fromPage, ok := g.pages[from]; ok {
			fromPage.Outgoing++
		}
		if toPage, ok := g.pages[to]; ok {
			toPage.Incoming++
		}
	}
}

func (g *PageGraph) GetPage(url string) *PageNode {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.pages[url]
}

func (g *PageGraph) GetOutgoing(url string) []*PageEdge {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var edges []*PageEdge
	for _, e := range g.edges {
		if e.From == url {
			edges = append(edges, e)
		}
	}
	return edges
}

func (g *PageGraph) GetIncoming(url string) []*PageEdge {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var edges []*PageEdge
	for _, e := range g.edges {
		if e.To == url {
			edges = append(edges, e)
		}
	}
	return edges
}

func (g *PageGraph) FindPath(from, to string, maxDepth int) [][]string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if maxDepth <= 0 {
		maxDepth = 5
	}

	paths := make([][]string, 0)
	visited := make(map[string]bool)
	queue := [][]string{{from}}

	for len(queue) > 0 && len(paths) < 10 {
		path := queue[0]
		queue = queue[1:]

		current := path[len(path)-1]
		if current == to {
			paths = append(paths, path)
			continue
		}

		if len(path) >= maxDepth {
			continue
		}

		visited[current] = true
		for _, e := range g.edges {
			if e.From == current && !visited[e.To] {
				newPath := make([]string, len(path)+1)
				copy(newPath, path)
				newPath[len(path)] = e.To
				queue = append(queue, newPath)
			}
		}
	}

	return paths
}

func (g *PageGraph) GetHubPages(limit int) []*PageNode {
	g.mu.RLock()
	defer g.mu.RUnlock()

	pages := make([]*PageNode, 0, len(g.pages))
	for _, p := range g.pages {
		pages = append(pages, p)
	}

	quickSort(pages, func(i, j int) bool {
		return pages[i].Outgoing+pages[i].Incoming > pages[j].Outgoing+pages[j].Incoming
	})

	if limit > 0 && limit < len(pages) {
		return pages[:limit]
	}
	return pages
}

func (g *PageGraph) GetOrphanPages() []*PageNode {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var orphans []*PageNode
	for _, p := range g.pages {
		if p.Incoming == 0 {
			orphans = append(orphans, p)
		}
	}
	return orphans
}

func (g *PageGraph) Stats() GraphStats {
	g.mu.RLock()
	defer g.mu.RUnlock()

	stats := GraphStats{
		TotalPages: len(g.pages),
		TotalEdges: len(g.edges),
	}

	var totalTokens, totalCompressed uint32
	for _, p := range g.pages {
		totalTokens += p.Tokens
		totalCompressed += p.Compressed
		stats.TotalInteractive += p.Interactive
	}

	stats.TotalTokens = totalTokens
	stats.CompressedTokens = totalCompressed
	if totalTokens > 0 {
		stats.CompressionRatio = float64(totalCompressed) / float64(totalTokens)
	}

	return stats
}

type GraphStats struct {
	TotalPages       int     `json:"total_pages"`
	TotalEdges       int     `json:"total_edges"`
	TotalTokens      uint32  `json:"total_tokens"`
	CompressedTokens uint32  `json:"compressed_tokens"`
	CompressionRatio float64 `json:"compression_ratio"`
	TotalInteractive int     `json:"total_interactive"`
}

func (s GraphStats) String() string {
	saved := int(s.TotalTokens) - int(s.CompressedTokens)
	savedPct := float64(0)
	if s.TotalTokens > 0 {
		savedPct = float64(saved) / float64(s.TotalTokens) * 100
	}
	return fmt.Sprintf(
		"Pages: %d | Edges: %d | Tokens: %d → %d (%.1f%% saved) | Interactive: %d",
		s.TotalPages, s.TotalEdges, s.TotalTokens, s.CompressedTokens, savedPct, s.TotalInteractive,
	)
}

func countInteractive(tree *SemanticTree) int {
	count := 0
	for _, root := range tree.RootNodes {
		count += len(root.Actions)
		for i := range root.Children {
			count += len(root.Children[i].Actions)
		}
	}
	return count
}

func quickSort[T any](s []T, less func(i, j int) bool) {
	if len(s) < 2 {
		return
	}
	quickSortRec(s, 0, len(s)-1, less)
}

func quickSortRec[T any](s []T, lo, hi int, less func(i, j int) bool) {
	if lo < hi {
		p := partition(s, lo, hi, less)
		quickSortRec(s, lo, p-1, less)
		quickSortRec(s, p+1, hi, less)
	}
}

func partition[T any](s []T, lo, hi int, less func(i, j int) bool) int {
	pivot := hi
	i := lo
	for j := lo; j < hi; j++ {
		if less(j, pivot) {
			s[i], s[j] = s[j], s[i]
			i++
		}
	}
	s[i], s[hi] = s[hi], s[i]
	return i
}

type CrawlSession struct {
	graph   *PageGraph
	cache   *CacheStore
	config  *PipelineConfig
	visited map[string]bool
}

func NewCrawlSession(cache *CacheStore, config *PipelineConfig) *CrawlSession {
	return &CrawlSession{
		graph:   NewPageGraph(),
		cache:   cache,
		config:  config,
		visited: make(map[string]bool),
	}
}

func (s *CrawlSession) Visit(ctx context.Context, url string) error {
	if s.visited[url] {
		return nil
	}
	s.visited[url] = true

	tree, _, err := HTMLToSemanticTreeCached(ctx, "", url, s.config)
	if err != nil {
		return err
	}

	s.graph.AddPage(tree)
	return nil
}

func (s *CrawlSession) Graph() *PageGraph {
	return s.graph
}
