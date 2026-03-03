package index

import (
	"context"
	"sort"
	"sync"

	"github.com/skunkworq/stealth/brws/semantic"
)

type VectorIndex struct {
	mu       sync.RWMutex
	nodes    []*indexedNode
	embedder *semantic.EmbeddingClient
}

type indexedNode struct {
	node      *semantic.SemanticNode
	url       string
	embedding []float32
}

type SearchResult struct {
	NodeID    string `json:"node_id"`
	Node      *semantic.SemanticNode
	URL       string    `json:"url"`
	Score     float32   `json:"score"`
	Content   string    `json:"content"`
	Embedding []float32 `json:"embedding,omitempty"`
}

func NewVectorIndex(embedder *semantic.EmbeddingClient) *VectorIndex {
	return &VectorIndex{
		nodes:    make([]*indexedNode, 0),
		embedder: embedder,
	}
}

func (idx *VectorIndex) Add(node *semantic.SemanticNode, url string, embedding []float32) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	idx.nodes = append(idx.nodes, &indexedNode{
		node:      node,
		url:       url,
		embedding: embedding,
	})
}

func (idx *VectorIndex) AddTree(ctx context.Context, tree *semantic.SemanticTree) error {
	for i := range tree.RootNodes {
		if err := idx.addNodeRecursive(ctx, &tree.RootNodes[i], tree.URL); err != nil {
			return err
		}
	}
	return nil
}

func (idx *VectorIndex) addNodeRecursive(ctx context.Context, node *semantic.SemanticNode, url string) error {
	if len(node.Embedding) == 0 && node.Summary != "" {
		embedding, err := idx.embedder.Embed(ctx, node.Summary)
		if err != nil {
			return err
		}
		node.Embedding = embedding
	}

	if len(node.Embedding) > 0 {
		idx.Add(node, url, node.Embedding)
	}

	for i := range node.Children {
		if err := idx.addNodeRecursive(ctx, &node.Children[i], url); err != nil {
			return err
		}
	}
	return nil
}

func (idx *VectorIndex) Search(ctx context.Context, query string, k int) ([]SearchResult, error) {
	queryEmbedding, err := idx.embedder.Embed(ctx, query)
	if err != nil {
		return nil, err
	}

	return idx.SearchEmbedding(queryEmbedding, k), nil
}

func (idx *VectorIndex) SearchEmbedding(queryEmbedding []float32, k int) []SearchResult {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	if len(idx.nodes) == 0 {
		return nil
	}

	scores := make([]SearchResult, 0, len(idx.nodes))
	for _, indexed := range idx.nodes {
		score := cosineSimilarity(queryEmbedding, indexed.embedding)
		scores = append(scores, SearchResult{
			Node:    indexed.node,
			URL:     indexed.url,
			Score:   score,
			Content: indexed.node.Summary,
		})
	}

	sort.Slice(scores, func(i, j int) bool {
		return scores[i].Score > scores[j].Score
	})

	if k > 0 && k < len(scores) {
		scores = scores[:k]
	}

	return scores
}

func (idx *VectorIndex) FindSimilar(node *semantic.SemanticNode, k int) []SearchResult {
	if len(node.Embedding) == 0 {
		return nil
	}
	return idx.SearchEmbedding(node.Embedding, k+1)[1:]
}

func (idx *VectorIndex) Stats() IndexStats {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	stats := IndexStats{
		TotalNodes: len(idx.nodes),
	}

	urls := make(map[string]int)
	for _, n := range idx.nodes {
		urls[n.url]++
	}
	stats.UniqueURLs = len(urls)

	return stats
}

type IndexStats struct {
	TotalNodes int `json:"total_nodes"`
	UniqueURLs int `json:"unique_urls"`
}

func (s IndexStats) String() string {
	return "Indexed: " + intToString(s.TotalNodes) + " nodes across " + intToString(s.UniqueURLs) + " pages"
}

func intToString(n int) string {
	if n == 0 {
		return "0"
	}
	var negative bool
	if n < 0 {
		negative = true
		n = -n
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if negative {
		return "-" + string(digits)
	}
	return string(digits)
}

func cosineSimilarity(a, b []float32) float32 {
	if len(a) != len(b) {
		return 0
	}

	var dot, normA, normB float32
	for i := range a {
		dot += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}

	if normA == 0 || normB == 0 {
		return 0
	}

	return dot / (sqrt32(normA) * sqrt32(normB))
}

func sqrt32(x float32) float32 {
	return float32(sqrt(float64(x)))
}

func sqrt(x float64) float64 {
	if x <= 0 {
		return 0
	}
	z := x
	for i := 0; i < 10; i++ {
		z = (z + x/z) / 2
	}
	return z
}
