package semantic

import (
	"context"
	"fmt"

	"github.com/stealth/brwslab/brws/engine"
)

type SemanticExtractor struct {
	config    *PipelineConfig
	eng       engine.Engine
	useEngine bool
}

func NewSemanticExtractor(config *PipelineConfig) *SemanticExtractor {
	return &SemanticExtractor{
		config:    config,
		useEngine: false,
	}
}

func NewSemanticExtractorWithEngine(config *PipelineConfig, eng engine.Engine) *SemanticExtractor {
	return &SemanticExtractor{
		config:    config,
		eng:       eng,
		useEngine: true,
	}
}

func (e *SemanticExtractor) Extract(ctx context.Context, url string) (*SemanticTree, *CompressionStats, error) {
	html, err := e.fetchHTML(ctx, url)
	if err != nil {
		return nil, nil, err
	}

	return HTMLToSemanticTree(ctx, html, url, e.config)
}

func (e *SemanticExtractor) ExtractWithBudget(ctx context.Context, url string, initialBudget, maxBudget uint32) (*SemanticTree, *UnfoldState, *CompressionStats, error) {
	tree, stats, err := e.Extract(ctx, url)
	if err != nil {
		return nil, nil, nil, err
	}

	state := InitialPack(tree, initialBudget, maxBudget)
	AutoUnfold(tree, state)

	return tree, state, stats, nil
}

func (e *SemanticExtractor) fetchHTML(ctx context.Context, url string) (string, error) {
	if e.useEngine && e.eng != nil {
		resp, err := e.eng.Do(ctx, &engine.Request{
			Method:  "GET",
			URL:     url,
			Timeout: 30000000000,
		})
		if err != nil {
			return "", fmt.Errorf("engine request failed: %w", err)
		}
		return string(resp.Body), nil
	}

	return "", fmt.Errorf("no engine configured for fetching HTML")
}

func (e *SemanticExtractor) Close() error {
	if e.eng != nil {
		return e.eng.Close()
	}
	return nil
}

func FromHTMLResponse(resp *engine.Response, config *PipelineConfig) (*SemanticTree, *CompressionStats, error) {
	ctx := context.Background()
	url := resp.FinalURL
	if url == "" {
		url = "https://unknown.com"
	}
	return HTMLToSemanticTree(ctx, string(resp.Body), url, config)
}

func NewConfigFromEnv() (*PipelineConfig, error) {
	apiKey := ""
	if apiKey == "" {
		return nil, fmt.Errorf("OPENROUTER_API_KEY not set")
	}

	llmClient := NewLLMClient(apiKey)
	embedClient := NewEmbeddingClient(apiKey)

	return &PipelineConfig{
		LLMClient:       llmClient,
		EmbeddingClient: embedClient,
		VisionClient:    NewVisionClient(llmClient),
		Cache:           nil,
		MaxDepth:        8,
		MinContentLen:   100,
	}, nil
}
