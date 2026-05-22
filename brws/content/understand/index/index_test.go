package index

import (
	"math/rand"
	"testing"
	"time"

	"github.com/skunkworq/stealth/brws/content/understand"
)

func TestHNSWIndex(t *testing.T) {
	hnsw := NewHNSWIndex(128)

	rand.Seed(time.Now().UnixNano()) //nolint:staticcheck

	for i := 0; i < 100; i++ {
		vector := randVector(128)
		nodeID := string(rune('a' + i%26))
		if i >= 26 {
			nodeID = nodeID + string(rune('0'+i/26))
		}
		_ = hnsw.Add(nodeID, "https://example.com/page"+string(rune('0'+i%10)), vector, "Node summary")
	}

	stats := hnsw.Stats()
	if stats.TotalNodes != 100 {
		t.Errorf("expected 100 nodes, got %d", stats.TotalNodes)
	}

	query := randVector(128)
	results := hnsw.Search(query, 10)

	if len(results) != 10 {
		t.Errorf("expected 10 results, got %d", len(results))
	}

	for i, r := range results {
		if r.NodeID == "" {
			t.Errorf("result %d has empty NodeID", i)
		}
		if r.Score == 0 {
			t.Logf("result %d has zero score", i)
		}
	}

	t.Logf("HNSW Stats: %d nodes, %d unique URLs", stats.TotalNodes, stats.UniqueURLs)
}

func TestHNSWIndexMultiHop(t *testing.T) {
	hnsw := NewHNSWIndex(64)

	for i := 0; i < 50; i++ {
		vector := randVector(64)
		url := "https://example.com/page" + string(rune('0'+i%5))
		hnsw.Add(string(rune('a'+i%26)), url, vector, "Page content")
	}

	query := randVector(64)
	results := hnsw.MultiHopSearch(query, 3, 5)

	t.Logf("Multi-hop search returned %d results across %d hops",
		len(results), countHops(results))

	for _, r := range results {
		t.Logf("  Hop %d: %s (%.3f)", r.Hop, r.Result.NodeID, r.Result.Score)
	}
}

func countHops(results []MultiHopResult) int {
	maxHop := 0
	for _, r := range results {
		if r.Hop > maxHop {
			maxHop = r.Hop
		}
	}
	return maxHop + 1
}

func TestInMemoryVectorIndex(t *testing.T) {
	idx := NewVectorIndex(nil)

	for i := 0; i < 20; i++ {
		node := &understand.SemanticNode{
			ID:      "node_" + string(rune('a'+i%26)),
			Summary: "Summary content",
		}
		vector := randVector(128)
		idx.Add(node, "https://example.com/page"+string(rune('0'+i%3)), vector)
	}

	stats := idx.Stats()
	if stats.TotalNodes != 20 {
		t.Errorf("expected 20 nodes, got %d", stats.TotalNodes)
	}

	query := randVector(128)
	results := idx.SearchEmbedding(query, 10)

	if len(results) != 10 {
		t.Errorf("expected 10 results, got %d", len(results))
	}

	t.Logf("InMemory Stats: %d nodes, %d unique URLs", stats.TotalNodes, stats.UniqueURLs)
}

func BenchmarkHNSWSearch(b *testing.B) {
	hnsw := NewHNSWIndex(128)

	for i := 0; i < 1000; i++ {
		vector := randVector(128)
		hnsw.Add(string(rune('a'+i%26)), "https://example.com", vector, "content")
	}

	query := randVector(128)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hnsw.Search(query, 10)
	}
}

func randVector(dim int) []float32 {
	v := make([]float32, dim)
	for i := range v {
		v[i] = rand.Float32()*2 - 1
	}
	return v
}
