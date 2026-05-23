package extract

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/skunkworq/stealth/brws/llm/completions"
)

type providerEntry struct {
	name     string
	patterns []*regexp.Regexp
	priority int
	factory  ProviderFactory
}

var providerRegistry = struct {
	mu      sync.RWMutex
	entries []providerEntry
	byName  map[string]ProviderFactory
}{
	byName: map[string]ProviderFactory{},
}

// init registers the built-in providers (Gemini, OpenAI, Ollama) into the
// global registry. Global registration is used here for the same reason Go's
// database/sql uses it: callers import the package for a side-effect, and
// the registry selects the correct provider automatically based on model ID
// patterns. Callers can add custom providers via RegisterProvider.
func init() {
	registerBuiltins()
}

func registerBuiltins() {
	_ = registerProviderWithPatterns("gemini", Gemini, 10, []string{
		`^gemini`,
	})
	_ = registerProviderWithPatterns("openai", OpenAI, 10, []string{
		`^gpt-4`,
		`^gpt4\.`,
		`^gpt-5`,
		`^gpt5\.`,
	})
	_ = registerProviderWithPatterns("ollama", Ollama, 10, []string{
		`^gemma`,
		`^llama`,
		`^mistral`,
		`^mixtral`,
		`^phi`,
		`^qwen`,
		`^deepseek`,
		`^command-r`,
		`^starcoder`,
		`^codellama`,
		`^codegemma`,
		`^tinyllama`,
		`^wizardcoder`,
		`^gpt-oss`,
		`^meta-llama/[Ll]lama`,
		`^google/gemma`,
		`^mistralai/[Mm]istral`,
		`^mistralai/[Mm]ixtral`,
		`^microsoft/phi`,
		`^Qwen/`,
		`^deepseek-ai/`,
		`^bigcode/starcoder`,
		`^codellama/`,
		`^TinyLlama/`,
		`^WizardLM/`,
	})
}

// RegisterProvider registers a custom provider factory by explicit name.
//
// Registered providers can be selected with ModelConfig.Provider or
// WithProvider/WithProviderHint.
func RegisterProvider(name string, factory ProviderFactory) error {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return fmt.Errorf("provider name is required")
	}
	if factory == nil {
		return fmt.Errorf("provider factory is required")
	}

	providerRegistry.mu.Lock()
	defer providerRegistry.mu.Unlock()
	if _, exists := providerRegistry.byName[name]; exists {
		return fmt.Errorf("provider %q already registered", name)
	}
	providerRegistry.byName[name] = factory
	return nil
}

func registerProviderWithPatterns(name string, factory ProviderFactory, priority int, patterns []string) error {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return fmt.Errorf("provider name is required")
	}
	if factory == nil {
		return fmt.Errorf("provider factory is required")
	}

	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid provider pattern %q: %w", pattern, err)
		}
		compiled = append(compiled, re)
	}

	providerRegistry.mu.Lock()
	defer providerRegistry.mu.Unlock()

	if _, exists := providerRegistry.byName[name]; !exists {
		providerRegistry.byName[name] = factory
	}

	providerRegistry.entries = append(providerRegistry.entries, providerEntry{
		name:     name,
		patterns: compiled,
		priority: priority,
		factory:  factory,
	})
	return nil
}

func resolveProviderFactory(modelID, providerHint string) (ProviderFactory, string, error) {
	hint := strings.ToLower(strings.TrimSpace(providerHint))

	providerRegistry.mu.RLock()
	defer providerRegistry.mu.RUnlock()

	if hint != "" {
		if factory, ok := providerRegistry.byName[hint]; ok {
			return factory, hint, nil
		}
		return nil, "", fmt.Errorf("no provider found matching %q", providerHint)
	}

	sortedEntries := append([]providerEntry(nil), providerRegistry.entries...)
	sort.SliceStable(sortedEntries, func(i, j int) bool {
		return sortedEntries[i].priority > sortedEntries[j].priority
	})

	for _, entry := range sortedEntries {
		for _, pattern := range entry.patterns {
			if pattern.MatchString(modelID) {
				return entry.factory, entry.name, nil
			}
		}
	}

	return nil, "", fmt.Errorf("no provider registered for model_id=%q", modelID)
}

func clearProviderRegistryForTests() {
	providerRegistry.mu.Lock()
	defer providerRegistry.mu.Unlock()
	providerRegistry.byName = map[string]ProviderFactory{}
	providerRegistry.entries = nil
}

// ListProviders returns all explicitly registered provider names.
//
// The result includes built-ins and custom providers registered via
// RegisterProvider.
func ListProviders() []string {
	providerRegistry.mu.RLock()
	defer providerRegistry.mu.RUnlock()

	names := make([]string, 0, len(providerRegistry.byName))
	for name := range providerRegistry.byName {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

type baseExtractor struct {
	formatType   FormatType
	fenceOutput  bool
	schema       any
	defaultModel string
}

func (b *baseExtractor) RequiresFenceOutput() bool { return b.fenceOutput }
func (b *baseExtractor) SetFenceOutput(enabled bool) {
	b.fenceOutput = enabled
}
func (b *baseExtractor) FormatType() FormatType { return b.formatType }
func (b *baseExtractor) SetFormatType(ft FormatType) {
	b.formatType = ft
}
func (b *baseExtractor) SetSchema(schema any) {
	b.schema = schema
}

// llmExtractor wraps any brws/llm.LLM provider and satisfies the Extractor
// interface. It calls Complete once per prompt and treats the response as a
// single scored output at confidence 1.0.
type llmExtractor struct {
	baseExtractor
	l      completions.LLM
	system string // system prompt injected before each user prompt
}

func (e *llmExtractor) Infer(ctx context.Context, prompts []string, _ map[string]any) ([][]ScoredOutput, error) {
	out := make([][]ScoredOutput, 0, len(prompts))
	for _, prompt := range prompts {
		text, err := e.l.Complete(ctx, e.system, prompt)
		if err != nil {
			return nil, &InferenceError{newErr("llm_infer", err.Error())}
		}
		if strings.TrimSpace(text) == "" {
			return nil, &InferenceOutputError{newErr("llm_infer", "empty response from model")}
		}
		out = append(out, []ScoredOutput{{Score: 1.0, Output: text}})
	}
	return out, nil
}

// OpenAI creates an OpenAI-backed extractor.
//
// Required kwargs:
//   - api_key
//
// Common optional kwargs:
//   - base_url   (overrides https://api.openai.com/v1)
//   - format_type / format
func OpenAI(_ context.Context, cfg ModelConfig) (Extractor, error) {
	apiKey := cfg.apiKey()
	if apiKey == "" {
		return nil, &InferenceConfigError{newErr("openai", "api_key is required")}
	}
	model := cfg.modelOrDefault("gpt-4o-mini")
	baseURL := stringOr(cfg.ProviderKwargs["base_url"], "")
	format := formatFromKwargs(cfg.ProviderKwargs, FormatTypeJSON)
	var l completions.LLM
	if baseURL != "" {
		l = completions.NewOpenAIWithBase(apiKey, model, baseURL)
	} else {
		l = completions.NewOpenAI(apiKey, model)
	}
	return &llmExtractor{
		baseExtractor: baseExtractor{
			formatType:   format,
			fenceOutput:  format != FormatTypeJSON,
			defaultModel: "gpt-4o-mini",
		},
		l:      l,
		system: formatSystemPrompt(format),
	}, nil
}

// Gemini creates a Gemini-backed extractor using Google's OpenAI-compatible
// endpoint.
//
// Required kwargs:
//   - api_key
//
// Common optional kwargs:
//   - base_url   (overrides default Gemini endpoint)
//   - format_type / format
func Gemini(_ context.Context, cfg ModelConfig) (Extractor, error) {
	apiKey := cfg.apiKey()
	if apiKey == "" {
		return nil, &InferenceConfigError{newErr("gemini", "api_key is required")}
	}
	model := cfg.modelOrDefault("gemini-2.5-flash")
	baseURL := stringOr(cfg.ProviderKwargs["base_url"], "")
	format := formatFromKwargs(cfg.ProviderKwargs, FormatTypeJSON)
	var l completions.LLM
	if baseURL != "" {
		l = completions.NewOpenAIWithBase(apiKey, model, baseURL)
	} else {
		l = completions.NewGemini(apiKey, model)
	}
	return &llmExtractor{
		baseExtractor: baseExtractor{
			formatType:   format,
			fenceOutput:  false,
			defaultModel: "gemini-2.5-flash",
		},
		l:      l,
		system: formatSystemPrompt(format),
	}, nil
}

// Ollama creates an Ollama-backed extractor (OpenAI-compatible endpoint).
//
// Common optional kwargs:
//   - base_url   (overrides OLLAMA_HOST / http://localhost:11434)
//   - format_type / format
func Ollama(_ context.Context, cfg ModelConfig) (Extractor, error) {
	model := cfg.modelOrDefault("llama3.2")
	format := formatFromKwargs(cfg.ProviderKwargs, FormatTypeJSON)
	// Allow per-config base_url override; fall back to NewOllama which reads OLLAMA_HOST.
	baseURL := stringOr(cfg.ProviderKwargs["base_url"], "")
	var l completions.LLM
	if baseURL != "" {
		l = completions.NewOllamaWithBase(model, baseURL)
	} else {
		l = completions.NewOllama(model)
	}
	return &llmExtractor{
		baseExtractor: baseExtractor{
			formatType:   format,
			fenceOutput:  false,
			defaultModel: "llama3.2",
		},
		l:      l,
		system: formatSystemPrompt(format),
	}, nil
}

func formatSystemPrompt(ft FormatType) string {
	switch ft {
	case FormatTypeYAML:
		return "You are a helpful assistant that responds in YAML format."
	default:
		return "You are a helpful assistant that responds in JSON format."
	}
}

func stringOr(v any, defaultValue string) string {
	if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
		return s
	}
	return defaultValue
}

func floatFrom(v any, defaultValue float64) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case float32:
		return float64(t)
	case int:
		return float64(t)
	default:
		return defaultValue
	}
}

func formatFromKwargs(kwargs map[string]any, defaultFormat FormatType) FormatType {
	if kwargs == nil {
		return defaultFormat
	}
	if value, ok := kwargs["format_type"]; ok {
		if ft, err := parseFormatType(value); err == nil {
			return ft
		}
	}
	if value, ok := kwargs["format"]; ok {
		if ft, err := parseFormatType(value); err == nil {
			return ft
		}
	}
	return defaultFormat
}

func truncateString(value string, max int) string {
	if len(value) <= max {
		return value
	}
	if max <= 3 {
		return value[:max]
	}
	return value[:max-3] + "..."
}


func (cfg ModelConfig) apiKey() string {
	if cfg.ProviderKwargs == nil {
		return ""
	}
	key := stringOr(cfg.ProviderKwargs["api_key"], "")
	if key != "" {
		return key
	}
	// Support common aliases.
	if key = stringOr(cfg.ProviderKwargs["key"], ""); key != "" {
		return key
	}
	return ""
}

func (cfg ModelConfig) modelOrDefault(defaultModel string) string {
	if strings.TrimSpace(cfg.ModelID) != "" {
		return cfg.ModelID
	}
	return defaultModel
}
