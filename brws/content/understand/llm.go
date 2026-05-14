package understand

import (
	"context"

	"github.com/skunkworq/stealth/brws/llm/completions"
)

const (
	DefaultLLMModel    = "openai/gpt-oss-120b"
	DefaultVisionModel = "google/gemini-2.5-flash"
)

// LLMClient is an OpenRouter-backed client with separate models for text
// compression and vision. It satisfies completions.LLM and can be passed
// anywhere that accepts completions.LLM.
//
// Use NewLLMClient for the default OpenRouter setup, or assign any
// completions.LLM provider directly to PipelineConfig.LLMClient.
type LLMClient struct {
	apiKey    string
	textLLM   completions.LLM
	visionLLM completions.LLM
}

func NewLLMClient(apiKey string) *LLMClient {
	return &LLMClient{
		apiKey:    apiKey,
		textLLM:   completions.NewOpenRouter(apiKey, DefaultLLMModel),
		visionLLM: completions.NewOpenRouter(apiKey, DefaultVisionModel),
	}
}

// WithCompressModel returns the client with a different text completion model.
func (c *LLMClient) WithCompressModel(model string) *LLMClient {
	c.textLLM = completions.NewOpenRouter(c.apiKey, model)
	return c
}

// WithVisionModel returns the client with a different vision model.
func (c *LLMClient) WithVisionModel(model string) *LLMClient {
	c.visionLLM = completions.NewOpenRouter(c.apiKey, model)
	return c
}

func (c *LLMClient) Complete(ctx context.Context, system, user string) (string, error) {
	return c.textLLM.Complete(ctx, system, user)
}

func (c *LLMClient) CompleteJSON(ctx context.Context, system, user string, v any) error {
	return c.textLLM.CompleteJSON(ctx, system, user, v)
}

func (c *LLMClient) DescribeImage(ctx context.Context, imageURL string) (string, error) {
	return c.visionLLM.DescribeImage(ctx, imageURL)
}

func (c *LLMClient) AskAboutImage(ctx context.Context, imageURL, question string) (string, error) {
	return c.visionLLM.AskAboutImage(ctx, imageURL, question)
}

func (c *LLMClient) AskAboutImageData(ctx context.Context, imageData []byte, mimeType, question string) (string, error) {
	return c.visionLLM.AskAboutImageData(ctx, imageData, mimeType, question)
}
