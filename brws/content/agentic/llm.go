package agentic

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/skunkworq/stealth/brws/content/semantic"
)

// LLM is the abstraction for any language model provider.
type LLM interface {
	Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error)
	CompleteJSON(ctx context.Context, systemPrompt, userPrompt string, v interface{}) error
}

// SemanticLLM wraps the existing semantic.LLMClient (OpenRouter-based).
type SemanticLLM struct {
	client *semantic.LLMClient
}

// NewSemanticLLM creates an LLM wrapper from an existing semantic client.
func NewSemanticLLM(client *semantic.LLMClient) *SemanticLLM {
	return &SemanticLLM{client: client}
}

// NewLLMFromEnv builds an LLM using the OPENROUTER_API_KEY environment variable.
func NewLLMFromEnv() (LLM, error) {
	key := os.Getenv("OPENROUTER_API_KEY")
	if key == "" {
		return nil, fmt.Errorf("OPENROUTER_API_KEY not set")
	}
	return NewSemanticLLM(semantic.NewLLMClient(key)), nil
}

func (s *SemanticLLM) Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	return s.client.Complete(ctx, systemPrompt, userPrompt)
}

func (s *SemanticLLM) CompleteJSON(ctx context.Context, systemPrompt, userPrompt string, v interface{}) error {
	return s.client.CompleteJSON(ctx, systemPrompt, userPrompt, v)
}

// TokenRegistry maps provider/model names to approximate context-window sizes.
// This is the Go equivalent of ScrapeGraphAI's models_tokens.py.
var TokenRegistry = map[string]map[string]int{
	"openai": {
		"gpt-4o":        128000,
		"gpt-4o-mini":   128000,
		"gpt-4.1":       1048576,
		"o1":            200000,
		"o3":            200000,
	},
	"anthropic": {
		"claude-3-opus-20240229":      200000,
		"claude-3-5-sonnet-20240620":  200000,
		"claude-opus-4-20250514":      200000,
	},
	"google": {
		"gemini-2.5-flash": 1000000,
		"gemini-2.5-pro":   1000000,
	},
	"ollama": {
		"llama3.1": 128000,
		"mistral":  128000,
	},
}

// LookupTokenLimit attempts to find the token limit for a model string in
// "provider/model" format. Falls back to 128000.
func LookupTokenLimit(model string) int {
	parts := strings.SplitN(model, "/", 2)
	if len(parts) != 2 {
		return 128000
	}
	provider, name := parts[0], parts[1]
	if m, ok := TokenRegistry[provider]; ok {
		if limit, ok2 := m[name]; ok2 {
			return limit
		}
	}
	return 128000
}
