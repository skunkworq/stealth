package semantic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
)

const (
	OpenRouterEmbeddingsURL = "https://openrouter.ai/api/v1/embeddings"
	DefaultEmbeddingModel   = "qwen/qwen3-embedding-8b"
)

type EmbeddingClient struct {
	client *http.Client
	apiKey string
	model  string
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

func NewEmbeddingClient(apiKey string) *EmbeddingClient {
	return &EmbeddingClient{
		client: &http.Client{},
		apiKey: apiKey,
		model:  DefaultEmbeddingModel,
	}
}

func (c *EmbeddingClient) WithModel(model string) *EmbeddingClient {
	c.model = model
	return c
}

func (c *EmbeddingClient) EmbedBatch(ctx context.Context, texts []string) ([][]float32, error) {
	if len(texts) == 0 {
		return nil, nil
	}

	req := embeddingRequest{
		Model:          c.model,
		Input:          texts,
		EncodingFormat: "float",
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", OpenRouterEmbeddingsURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, NewEmbeddingError(fmt.Sprintf("OpenRouter returned %d: %s", resp.StatusCode, string(bodyBytes)))
	}

	var result embeddingResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	embeddings := make([][]float32, len(texts))
	for _, data := range result.Data {
		if data.Index < len(embeddings) {
			embeddings[data.Index] = data.Embedding
		}
	}

	return embeddings, nil
}

func (c *EmbeddingClient) Embed(ctx context.Context, text string) ([]float32, error) {
	results, err := c.EmbedBatch(ctx, []string{text})
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, NewEmbeddingError("empty response")
	}
	return results[0], nil
}

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

	return dot / (sqrt32(magA) * sqrt32(magB))
}

func sqrt32(x float32) float32 {
	return float32(math.Sqrt(float64(x)))
}
