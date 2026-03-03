package index

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/skunkworq/stealth/brws/semantic"
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

func TestSQLiteVecIndex(t *testing.T) {
	tmpFile := fmt.Sprintf("/tmp/test_sqlite_vec_%d.db", rand.Intn(100000))
	defer os.Remove(tmpFile)

	idx, err := NewSQLiteVecIndex(tmpFile, 128)
	if err != nil {
		t.Fatalf("failed to create index: %v", err)
	}
	defer idx.Close()

	for i := 0; i < 50; i++ {
		vector := randVector(128)
		nodeID := fmt.Sprintf("node_%c%d", 'a'+rune(i%26), i/26)
		url := fmt.Sprintf("https://example.com/page%d", i%5)
		if err := idx.Add(nodeID, url, vector, "Summary "+nodeID); err != nil {
			t.Fatalf("failed to add: %v", err)
		}
	}

	ctx := context.Background()
	query := randVector(128)
	results, err := idx.Search(ctx, query, 10)
	if err != nil {
		t.Fatalf("search failed: %v", err)
	}

	if len(results) != 10 {
		t.Errorf("expected 10 results, got %d", len(results))
	}

	stats := idx.Stats()
	if stats.TotalNodes != 50 {
		t.Errorf("expected 50 nodes, got %d", stats.TotalNodes)
	}
	if stats.UniqueURLs != 5 {
		t.Errorf("expected 5 unique URLs, got %d", stats.UniqueURLs)
	}

	t.Logf("SQLite Stats: %d nodes, %d unique URLs", stats.TotalNodes, stats.UniqueURLs)
}

func TestSQLiteVecMultiHop(t *testing.T) {
	tmpFile := "/tmp/test_sqlite_multihop.db"
	defer os.Remove(tmpFile)

	idx, err := NewSQLiteVecIndex(tmpFile, 64)
	if err != nil {
		t.Fatalf("failed to create index: %v", err)
	}
	defer idx.Close()

	for i := 0; i < 30; i++ {
		vector := randVector(64)
		url := "https://example.com/page" + string(rune('0'+i%5))
		idx.Add("node"+string(rune('a'+i%26)), url, vector, "Content")
	}

	ctx := context.Background()
	query := randVector(64)
	results, err := idx.MultiHopSearch(ctx, query, 3, 5)
	if err != nil {
		t.Fatalf("multi-hop search failed: %v", err)
	}

	t.Logf("SQLite multi-hop: %d results", len(results))
	for _, r := range results {
		t.Logf("  Hop %d: %s (%.3f)", r.Hop, r.Result.NodeID, r.Result.Score)
	}
}

func TestInMemoryVectorIndex(t *testing.T) {
	idx := NewVectorIndex(nil)

	for i := 0; i < 20; i++ {
		node := &semantic.SemanticNode{
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

func BenchmarkSQLiteVecSearch(b *testing.B) {
	tmpFile := "/tmp/ bench_sqlite_vec.db"
	defer os.Remove(tmpFile)

	idx, _ := NewSQLiteVecIndex(tmpFile, 128)
	defer idx.Close()

	for i := 0; i < 1000; i++ {
		vector := randVector(128)
		idx.Add(string(rune('a'+i%26)), "https://example.com", vector, "content")
	}

	query := randVector(128)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx.Search(ctx, query, 10)
	}
}

func randVector(dim int) []float32 {
	v := make([]float32, dim)
	for i := range v {
		v[i] = rand.Float32()*2 - 1
	}
	return v
}
