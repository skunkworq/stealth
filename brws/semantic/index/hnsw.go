package index

import (
	"math"
	"math/rand"
	"sort"
	"sync"
)

type HNSWIndex struct {
	mu             sync.RWMutex
	nodes          []*hnswNode
	entryPoint     *hnswNode
	maxLayer       int
	efConstruction int
	efSearch       int
	dim            int
	maxM           int
	maxM0          int
	rng            *rand.Rand
}

type hnswNode struct {
	id      string
	url     string
	vector  []float32
	summary string
	links   [][]*hnswNode
	layer   int
}

func NewHNSWIndex(dim int) *HNSWIndex {
	return &HNSWIndex{
		nodes:          make([]*hnswNode, 0),
		maxLayer:       16,
		efConstruction: 200,
		efSearch:       50,
		dim:            dim,
		maxM:           16,
		maxM0:          32,
		rng:            rand.New(rand.NewSource(42)),
	}
}

func (h *HNSWIndex) Add(nodeID, url string, vector []float32, summary string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	layer := h.randomLayer()
	node := &hnswNode{
		id:      nodeID,
		url:     url,
		vector:  vector,
		summary: summary,
		links:   make([][]*hnswNode, layer+1),
		layer:   layer,
	}

	for i := range node.links {
		node.links[i] = make([]*hnswNode, 0, h.maxM)
	}

	if h.entryPoint == nil {
		h.entryPoint = node
		h.nodes = append(h.nodes, node)
		return nil
	}

	eps := []*hnswNode{h.entryPoint}

	for lc := h.maxLayer - 1; lc > layer; lc-- {
		if len(eps) > 0 && len(eps[0].links) > lc {
			eps = h.searchLayer(vector, eps, 1, lc)
		}
	}

	for lc := layer; lc >= 0; lc-- {
		candidates := h.searchLayer(vector, eps, h.efConstruction, lc)

		maxMlc := h.maxM
		if lc == 0 {
			maxMlc = h.maxM0
		}

		for _, cand := range candidates {
			if len(cand.links) > lc && len(cand.links[lc]) < maxMlc && len(node.links[lc]) < maxMlc {
				cand.links[lc] = append(cand.links[lc], node)
				node.links[lc] = append(node.links[lc], cand)
			}
		}
	}

	if layer > h.entryPoint.layer {
		h.entryPoint = node
	}

	h.nodes = append(h.nodes, node)
	return nil
}

func (h *HNSWIndex) Search(query []float32, k int) []SearchResult {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.entryPoint == nil {
		return nil
	}

	eps := []*hnswNode{h.entryPoint}

	for lc := h.maxLayer - 1; lc >= 1; lc-- {
		eps = h.searchLayer(query, eps, 1, lc)
	}

	candidates := h.searchLayer(query, eps, h.efSearch, 0)

	if k > len(candidates) {
		k = len(candidates)
	}

	results := make([]SearchResult, k)
	for i := 0; i < k; i++ {
		results[i] = SearchResult{
			NodeID:    candidates[i].id,
			URL:       candidates[i].url,
			Content:   candidates[i].summary,
			Score:     cosineSimilarity(query, candidates[i].vector),
			Embedding: candidates[i].vector,
		}
	}

	return results
}

func (h *HNSWIndex) searchLayer(query []float32, eps []*hnswNode, ef int, layer int) []*hnswNode {
	visited := make(map[string]bool)
	for _, ep := range eps {
		visited[ep.id] = true
	}

	type scoredNode struct {
		node  *hnswNode
		score float32
	}

	candidates := make([]scoredNode, 0, ef)
	for _, ep := range eps {
		candidates = append(candidates, scoredNode{
			node:  ep,
			score: cosineSimilarity(query, ep.vector),
		})
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].score > candidates[j].score
	})

	result := make([]scoredNode, 0, ef)
	result = append(result, candidates...)

	for len(candidates) > 0 {
		furthest := candidates[0]
		candidates = candidates[1:]

		if len(furthest.node.links) <= layer {
			continue
		}

		for _, neighbor := range furthest.node.links[layer] {
			if visited[neighbor.id] {
				continue
			}
			visited[neighbor.id] = true

			score := cosineSimilarity(query, neighbor.vector)

			if len(result) < ef || score > result[len(result)-1].score {
				candidates = append(candidates, scoredNode{node: neighbor, score: score})
				result = append(result, scoredNode{node: neighbor, score: score})

				sort.Slice(candidates, func(i, j int) bool {
					return candidates[i].score > candidates[j].score
				})
				sort.Slice(result, func(i, j int) bool {
					return result[i].score > result[j].score
				})

				if len(candidates) > ef {
					candidates = candidates[:ef]
				}
				if len(result) > ef {
					result = result[:ef]
				}
			}
		}
	}

	sorted := make([]*hnswNode, len(result))
	for i, r := range result {
		sorted[i] = r.node
	}
	return sorted
}

func (h *HNSWIndex) randomLayer() int {
	f := 1.0 / float64(h.maxM)
	r := h.rng.Float64()
	layer := int(-math.Log(r) * f)
	if layer >= h.maxLayer {
		layer = h.maxLayer - 1
	}
	return layer
}

func (h *HNSWIndex) Stats() IndexStats {
	h.mu.RLock()
	defer h.mu.RUnlock()

	urls := make(map[string]int)
	for _, n := range h.nodes {
		urls[n.url]++
	}

	return IndexStats{
		TotalNodes: len(h.nodes),
		UniqueURLs: len(urls),
	}
}

func (h *HNSWIndex) MultiHopSearch(query []float32, maxHops, k int) []MultiHopResult {
	visited := make(map[string]bool)
	results := make([]MultiHopResult, 0, maxHops*k)

	current := query

	for hop := 0; hop < maxHops; hop++ {
		candidates := h.Search(current, k)
		if len(candidates) == 0 {
			break
		}

		for _, c := range candidates {
			if visited[c.NodeID] {
				continue
			}
			visited[c.NodeID] = true

			results = append(results, MultiHopResult{
				Hop:    hop,
				Result: c,
			})
		}

		if len(candidates) > 0 && len(candidates[0].Embedding) > 0 {
			current = candidates[0].Embedding
		}
	}

	return results
}
