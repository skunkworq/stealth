package understand

import (
	"github.com/skunkworq/stealth/brws/llm/completions"
)

// PipelineConfig configures the semantic processing pipeline.
// LLMClient accepts any brws/llm.LLM provider (OpenAI, Anthropic, Mistral,
// Ollama, llama.cpp, vLLM, OpenRouter, or understand.LLMClient).
type PipelineConfig struct {
	LLMClient        completions.LLM
	EmbeddingClient  *EmbeddingClient
	Cache            *CacheStore
	MaxDepth         int
	MinContentLen    int
	MaxChunks        int
	MaxConcurrentLLM int
}

// DomChunk represents a chunk of the DOM for processing.
type DomChunk struct {
	Selector            string
	Tag                 string
	HTML                string
	StructuralHash      string
	Children            []DomChunk
	Images              []ImageRef
	Depth               int
	InteractiveElements []InteractiveElement
}
