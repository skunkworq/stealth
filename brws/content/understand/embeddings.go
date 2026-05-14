package understand

import (
	"math"

	"github.com/skunkworq/stealth/brws/llm/embed"
)

// EmbeddingClient is a type alias of brws/llm/embed.EmbeddingClient.
// Use embed.NewEmbeddingClient or embed.NewEmbeddingClientWithBase directly.
type EmbeddingClient = embed.EmbeddingClient

// NewEmbeddingClient returns an OpenRouter-backed embedding client.
// Kept for backward compatibility — prefer embed.NewEmbeddingClient.
func NewEmbeddingClient(apiKey string) *EmbeddingClient {
	return embed.NewEmbeddingClient(apiKey)
}

// CosineSimilarity returns the cosine similarity between two embedding vectors.
func CosineSimilarity(a, b []float32) float32 {
	if len(a) == 0 || len(b) == 0 || len(a) != len(b) {
		return 0
	}
	var dot, magA, magB float32
	for i := range a {
		dot += a[i] * b[i]
		magA += a[i] * a[i]
		magB += b[i] * b[i]
	}
	if magA == 0 || magB == 0 {
		return 0
	}
	return dot / (float32(math.Sqrt(float64(magA))) * float32(math.Sqrt(float64(magB))))
}
