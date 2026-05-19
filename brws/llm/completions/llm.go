// Package completions provides the LLM interface and provider implementations
// for chat-completion style language models (text generation, vision).
//
// Supported providers: openai, anthropic, mistral, ollama, openrouter,
// llamacpp, vllm, gemini.
package completions

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/skunkworq/stealth/brws/core/constants"
)

// llmHTTPClient is the shared HTTP client for all LLM API calls.
// Timeout drawn from constants.LLMTimeout — completions can be slow on large
// prompts, and http.DefaultClient has no timeout at all.
var llmHTTPClient = &http.Client{Timeout: constants.LLMTimeout}

// LLM is the shared interface for all chat-completion providers.
// All providers implement the full interface; vision methods return an error
// on models that do not support multimodal input.
type LLM interface {
	Complete(ctx context.Context, system, user string) (string, error)
	CompleteJSON(ctx context.Context, system, user string, v any) error
	DescribeImage(ctx context.Context, imageURL string) (string, error)
	AskAboutImage(ctx context.Context, imageURL, question string) (string, error)
	// AskAboutImageData is like AskAboutImage but accepts raw image bytes
	// instead of a URL — suitable for in-memory screenshots.
	AskAboutImageData(ctx context.Context, imageData []byte, mimeType, question string) (string, error)
}

// New creates an LLM from a provider name, model, and API key.
// For local providers (ollama, llamacpp, vllm) the key is ignored;
// the host is read from the corresponding *_HOST environment variable.
func New(provider, model, apiKey string) (LLM, error) {
	switch provider {
	case "openai":
		return NewOpenAI(apiKey, model), nil
	case "anthropic":
		return NewAnthropic(apiKey, model), nil
	case "mistral":
		return NewMistral(apiKey, model), nil
	case "ollama":
		return NewOllama(model), nil
	case "openrouter":
		return NewOpenRouter(apiKey, model), nil
	case "llamacpp":
		return NewLlamaCpp(model), nil
	case "vllm":
		return NewVLLM(model), nil
	case "gemini":
		return NewGemini(apiKey, model), nil
	default:
		return nil, fmt.Errorf("unknown provider %q; choose: openai, anthropic, mistral, ollama, openrouter, llamacpp, vllm, gemini", provider)
	}
}

// FromEnv creates an LLM by reading the standard environment variable for the
// given provider. Local providers need no key; their host is overridden via
// the corresponding *_HOST variable.
//
//	openai      → OPENAI_API_KEY
//	anthropic   → ANTHROPIC_API_KEY
//	mistral     → MISTRAL_API_KEY
//	openrouter  → OPENROUTER_API_KEY
//	gemini      → GEMINI_API_KEY
//	ollama      → (no key; OLLAMA_HOST overrides base URL)
//	llamacpp    → (no key; LLAMACPP_HOST overrides base URL)
//	vllm        → (no key; VLLM_HOST overrides base URL)
func FromEnv(provider, model string) (LLM, error) {
	switch provider {
	case "ollama":
		return NewOllama(model), nil
	case "llamacpp":
		return NewLlamaCpp(model), nil
	case "vllm":
		return NewVLLM(model), nil
	}
	vars := map[string]string{
		"openai":     "OPENAI_API_KEY",
		"anthropic":  "ANTHROPIC_API_KEY",
		"mistral":    "MISTRAL_API_KEY",
		"openrouter": "OPENROUTER_API_KEY",
		"gemini":     "GEMINI_API_KEY",
	}
	envVar, ok := vars[provider]
	if !ok {
		return nil, fmt.Errorf("unknown provider %q; choose: openai, anthropic, mistral, ollama, openrouter, llamacpp, vllm, gemini", provider)
	}
	key := os.Getenv(envVar)
	if key == "" {
		return nil, fmt.Errorf("%s not set", envVar)
	}
	return New(provider, model, key)
}

func completeJSON(ctx context.Context, l LLM, system, user string, v any) error {
	resp, err := l.Complete(ctx, system, user)
	if err != nil {
		return err
	}
	resp = stripFences(resp)
	if err := json.Unmarshal([]byte(resp), v); err != nil {
		return fmt.Errorf("unmarshal LLM response: %w (raw: %.200s)", err, resp)
	}
	return nil
}

func stripFences(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "```") {
		return s
	}
	if idx := strings.Index(s, "\n"); idx >= 0 {
		s = s[idx+1:]
	}
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, "```")
	return strings.TrimSpace(s)
}
