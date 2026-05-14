// Package embed provides the Embedder interface and provider implementations
// for text embedding models.
package embed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strings"
)

const DefaultEmbeddingModel = "qwen/qwen3-embedding-8b"

// Embedder is the shared interface for all embedding providers.
type Embedder interface {
	Embed(ctx context.Context, text string) ([]float32, error)
	EmbedBatch(ctx context.Context, texts []string) ([][]float32, error)
}

// EmbeddingClient calls an OpenAI-compatible embeddings endpoint.
// Default provider: OpenRouter. Override with NewEmbeddingClientWithBase
// or the EMBEDDING_BASE_URL environment variable.
type EmbeddingClient struct {
	baseURL string
	apiKey  string
	model   string
}

type embeddingRequest struct {
	Model          string   `json:"model"`
	Input          []string `json:"input"`
	EncodingFormat string   `json:"encoding_format"`
}

type embeddingResponse struct {
	Data []embeddingData `json:"data"`
}

type embeddingData struct {
	Embedding []float32 `json:"embedding"`
	Index     int       `json:"index"`
}

// NewEmbeddingClient returns an OpenRouter-backed embedding client.
// Override base URL via EMBEDDING_BASE_URL env var.
func NewEmbeddingClient(apiKey string) *EmbeddingClient {
	base := os.Getenv("EMBEDDING_BASE_URL")
	if base == "" {
		base = "https://openrouter.ai/api/v1"
	}
	return &EmbeddingClient{
		baseURL: strings.TrimRight(base, "/"),
		apiKey:  apiKey,
		model:   DefaultEmbeddingModel,
	}
}

// NewEmbeddingClientWithBase returns an embedding client pointing at a custom
// base URL (e.g. a local text-embeddings-inference server).
func NewEmbeddingClientWithBase(apiKey, baseURL, model string) *EmbeddingClient {
	if model == "" {
		model = DefaultEmbeddingModel
	}
	return &EmbeddingClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		model:   model,
	}
}

// WithModel returns the client configured to use a different model.
func (c *EmbeddingClient) WithModel(model string) *EmbeddingClient {
	c.model = model
	return c
}

// EmbedBatch returns one embedding vector per input text, preserving order.
func (c *EmbeddingClient) EmbedBatch(ctx context.Context, texts []string) ([][]float32, error) {
	if len(texts) == 0 {
		return nil, nil
	}
	body, err := json.Marshal(embeddingRequest{
		Model:          c.model,
		Input:          texts,
		EncodingFormat: "float",
	})
	if err != nil {
		return nil, fmt.Errorf("embedding marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/embeddings", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("embedding request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("embedding request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("embedding: status %d: %s", resp.StatusCode, b)
	}
	var result embeddingResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("embedding decode: %w", err)
	}
	embeddings := make([][]float32, len(texts))
	for _, d := range result.Data {
		if d.Index < len(embeddings) {
			embeddings[d.Index] = d.Embedding
		}
	}
	return embeddings, nil
}

// Embed returns the embedding vector for a single text.
func (c *EmbeddingClient) Embed(ctx context.Context, text string) ([]float32, error) {
	results, err := c.EmbedBatch(ctx, []string{text})
	if err != nil {
		return nil, err
	}
	if len(results) == 0 || results[0] == nil {
		return nil, fmt.Errorf("embedding: empty response")
	}
	return results[0], nil
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
