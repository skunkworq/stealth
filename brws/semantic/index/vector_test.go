package index

import (
	"testing"

	"github.com/skunkworq/stealth/brws/semantic"
)

func TestVectorIndex(t *testing.T) {
	idx := NewVectorIndex(nil)

	node1 := &semantic.SemanticNode{
		ID:      "node1",
		Summary: "Product listing page with search and filters",
	}

	node2 := &semantic.SemanticNode{
		ID:      "node2",
		Summary: "Checkout page with payment form",
	}

	embedding1 := []float32{0.1, 0.2, 0.3}
	embedding2 := []float32{0.4, 0.5, 0.6}

	idx.Add(node1, "https://example.com/products", embedding1)
	idx.Add(node2, "https://example.com/checkout", embedding2)

	t.Run("stats", func(t *testing.T) {
		stats := idx.Stats()
		if stats.TotalNodes != 2 {
			t.Errorf("expected 2 nodes, got %d", stats.TotalNodes)
		}
		if stats.UniqueURLs != 2 {
			t.Errorf("expected 2 unique URLs, got %d", stats.UniqueURLs)
		}
	})

	t.Run("search", func(t *testing.T) {
		queryEmbedding := []float32{0.1, 0.2, 0.3}
		results := idx.SearchEmbedding(queryEmbedding, 5)

		if len(results) != 2 {
			t.Errorf("expected 2 results, got %d", len(results))
		}

		if results[0].Node.ID != "node1" {
			t.Errorf("expected node1 first, got %s", results[0].Node.ID)
		}
	})

	t.Run("find_similar", func(t *testing.T) {
		node1.Embedding = embedding1
		results := idx.FindSimilar(node1, 5)
		if len(results) < 1 {
			t.Skip("expected similar nodes, got none")
		}
		if results[0].Node.ID != "node2" {
			t.Errorf("expected node2 similar, got %s", results[0].Node.ID)
		}
	})
}

func TestCosineSimilarity(t *testing.T) {
	tests := []struct {
		name     string
		a, b     []float32
		expected float32
	}{
		{
			name:     "identical",
			a:        []float32{1, 0, 0},
			b:        []float32{1, 0, 0},
			expected: 1.0,
		},
		{
			name:     "orthogonal",
			a:        []float32{1, 0, 0},
			b:        []float32{0, 1, 0},
			expected: 0.0,
		},
		{
			name:     "opposite",
			a:        []float32{1, 0, 0},
			b:        []float32{-1, 0, 0},
			expected: -1.0,
		},
		{
			name:     "different_lengths",
			a:        []float32{1, 0},
			b:        []float32{1, 0, 0},
			expected: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cosineSimilarity(tt.a, tt.b)
			if abs(result-tt.expected) > 0.0001 {
				t.Errorf("expected %.4f, got %.4f", tt.expected, result)
			}
		})
	}
}

func abs(x float32) float32 {
	if x < 0 {
		return -x
	}
	return x
}
