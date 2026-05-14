package scrapegraph

import (
	"strings"

	"github.com/skunkworq/stealth/brws/llm/completions"
)

// LLM is a type alias of brws/llm/completions.LLM so any provider value (OpenAI,
// Anthropic, Mistral, Ollama, OpenRouter) passes directly without conversion.
type LLM = completions.LLM

// NewLLMFromEnv builds an LLM from environment variables.
// Reads OPENROUTER_API_KEY for backward compatibility.
// For other providers use completions.FromEnv directly.
func NewLLMFromEnv() (LLM, error) {
	return completions.FromEnv("openrouter", "")
}

// TokenRegistry maps provider/model names to approximate context-window sizes.
var TokenRegistry = map[string]map[string]int{
	"openai": {
		"gpt-4o":      128000,
		"gpt-4o-mini": 128000,
		"gpt-4.1":     1048576,
		"o1":          200000,
		"o3":          200000,
	},
	"anthropic": {
		"claude-3-opus-20240229":     200000,
		"claude-3-5-sonnet-20240620": 200000,
		"claude-opus-4-20250514":     200000,
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

// LookupTokenLimit returns the token limit for a "provider/model" string.
// Falls back to 128000 if unknown.
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
