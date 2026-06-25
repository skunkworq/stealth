package langextract

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
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

func init() {
	registerBuiltins()
}

func registerBuiltins() {
	providerRegistry.mu.Lock()
	defer providerRegistry.mu.Unlock()
	providerRegistry.byName = map[string]ProviderFactory{}
	providerRegistry.entries = nil
	registerBuiltinsLocked()
}

// registerBuiltinsLocked registers the built-in providers while assuming the
// caller already holds providerRegistry.mu. This keeps the registry in a valid
// state at all times, avoiding the empty-registry window that previously raced
// with parallel tests.
func registerBuiltinsLocked() {
	addBuiltin := func(name string, factory ProviderFactory, priority int, patterns []string) {
		name = strings.ToLower(strings.TrimSpace(name))
		compiled := make([]*regexp.Regexp, 0, len(patterns))
		for _, pattern := range patterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			compiled = append(compiled, re)
		}
		if _, exists := providerRegistry.byName[name]; !exists {
			providerRegistry.byName[name] = factory
		}
		providerRegistry.entries = append(providerRegistry.entries, providerEntry{
			name:     name,
			patterns: compiled,
			priority: priority,
			factory:  factory,
		})
	}

	addBuiltin("gemini", Gemini, 10, []string{
		`^gemini`,
	})
	addBuiltin("openai", OpenAI, 10, []string{
		`^gpt-4`,
		`^gpt4\.`,
		`^gpt-5`,
		`^gpt5\.`,
	})
	// Hosted DeepSeek API (OpenAI-compatible). Priority 20 outranks the
	// Ollama "^deepseek" / "^deepseek-ai/" patterns below so plain
	// "deepseek-chat" / "deepseek-reasoner" route to api.deepseek.com.
	// To run a DeepSeek model LOCALLY via Ollama, use a name Ollama
	// recognizes (e.g. "deepseek-r1:7b") which won't match these patterns.
	addBuiltin("deepseek", DeepSeek, 20, []string{
		`^deepseek-chat$`,
		`^deepseek-reasoner$`,
		`^deepseek-coder$`,
	})
	addBuiltin("ollama", Ollama, 10, []string{
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

// resetProviderRegistryForTests clears the registry and re-registers built-in
// providers atomically while holding the registry lock. This prevents parallel
// tests from observing an empty registry during clear+register sequences.
func resetProviderRegistryForTests() {
	providerRegistry.mu.Lock()
	defer providerRegistry.mu.Unlock()
	providerRegistry.byName = map[string]ProviderFactory{}
	providerRegistry.entries = nil
	registerBuiltinsLocked()
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

type openAIExtractor struct {
	baseExtractor
	modelID      string
	apiKey       string
	baseURL      string
	organization string
	client       *http.Client
	// providerName labels the underlying provider for usage telemetry.
	// Defaults to "openai" but factories that share this implementation
	// (DeepSeek today; potential others later) override it so per-provider
	// pricing tables and cost dashboards aren't fooled by a shared codepath.
	providerName string
}

// OpenAI creates an OpenAI-backed extractor.
//
// Required kwargs:
//   - api_key
//
// Common optional kwargs:
//   - base_url
//   - organization
//   - timeout_seconds
//   - format_type / format
func OpenAI(_ context.Context, cfg ModelConfig) (Extractor, error) {
	apiKey := cfg.apiKey()
	if apiKey == "" {
		return nil, &InferenceConfigError{newErr("openai", "api_key is required")}
	}

	baseURL := stringOr(cfg.ProviderKwargs["base_url"], "https://api.openai.com")
	format := formatFromKwargs(cfg.ProviderKwargs, FormatTypeJSON)
	temperature := floatFrom(cfg.ProviderKwargs["timeout_seconds"], 30)
	client := &http.Client{Timeout: time.Duration(temperature) * time.Second}

	providerName := strings.ToLower(strings.TrimSpace(cfg.Provider))
	if providerName == "" {
		providerName = strings.ToLower(strings.TrimSpace(cfg.ProviderClass))
	}
	if providerName == "" {
		providerName = "openai"
	}
	return &openAIExtractor{
		baseExtractor: baseExtractor{
			formatType:   format,
			fenceOutput:  format != FormatTypeJSON,
			defaultModel: "gpt-4o-mini",
		},
		modelID:      cfg.modelOrDefault("gpt-4o-mini"),
		apiKey:       apiKey,
		baseURL:      strings.TrimRight(baseURL, "/"),
		organization: stringOr(cfg.ProviderKwargs["organization"], ""),
		client:       client,
		providerName: providerName,
	}, nil
}

func (o *openAIExtractor) Infer(ctx context.Context, prompts []string, options map[string]any) ([][]ScoredOutput, error) {
	if len(prompts) == 0 {
		return nil, nil
	}

	out := make([][]ScoredOutput, 0, len(prompts))
	for _, prompt := range prompts {
		callStart := time.Now()
		payload := map[string]any{
			"model": o.modelID,
			"messages": []map[string]string{
				{
					"role":    "system",
					"content": o.systemMessage(),
				},
				{
					"role":    "user",
					"content": prompt,
				},
			},
			"n": 1,
		}
		if o.formatType == FormatTypeJSON {
			payload["response_format"] = map[string]string{"type": "json_object"}
		}
		applyOpenAIOptions(payload, options)

		body, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+"/v1/chat/completions", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+o.apiKey)
		req.Header.Set("Content-Type", "application/json")
		if o.organization != "" {
			req.Header.Set("OpenAI-Organization", o.organization)
		}

		resp, err := o.client.Do(req)
		if err != nil {
			return nil, &InferenceError{newErr("openai_infer", err.Error())}
		}

		data, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, &InferenceError{newErr("openai_infer", fmt.Sprintf("status %d: %s", resp.StatusCode, truncateString(string(data), 300)))}
		}

		var parsed struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
			Model string `json:"model"`
			Usage struct {
				PromptTokens        int64 `json:"prompt_tokens"`
				CompletionTokens    int64 `json:"completion_tokens"`
				TotalTokens         int64 `json:"total_tokens"`
				PromptTokensDetails struct {
					CachedTokens int64 `json:"cached_tokens"`
				} `json:"prompt_tokens_details"`
				CompletionTokensDetails struct {
					ReasoningTokens int64 `json:"reasoning_tokens"`
				} `json:"completion_tokens_details"`
				// DeepSeek-specific fields (not in vanilla OpenAI but the
				// JSON decoder ignores unknown fields safely):
				PromptCacheHitTokens int64 `json:"prompt_cache_hit_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(data, &parsed); err != nil {
			return nil, err
		}
		if len(parsed.Choices) == 0 {
			return nil, &InferenceOutputError{newErr("openai_infer", "no choices in response")}
		}
		providerName := o.providerName
		if providerName == "" {
			providerName = "openai"
		}
		cached := parsed.Usage.PromptTokensDetails.CachedTokens
		if cached == 0 {
			cached = parsed.Usage.PromptCacheHitTokens // DeepSeek
		}
		modelID := parsed.Model
		if modelID == "" {
			modelID = o.modelID
		}
		usage := &InferenceUsage{
			Provider:          providerName,
			Model:             modelID,
			InputTokens:       parsed.Usage.PromptTokens,
			OutputTokens:      parsed.Usage.CompletionTokens,
			TotalTokens:       parsed.Usage.TotalTokens,
			CachedInputTokens: cached,
			ReasoningTokens:   parsed.Usage.CompletionTokensDetails.ReasoningTokens,
			LatencyMs:         time.Since(callStart).Milliseconds(),
		}
		out = append(out, []ScoredOutput{{Score: 1.0, Output: parsed.Choices[0].Message.Content, Usage: usage}})
	}

	return out, nil
}

func (o *openAIExtractor) systemMessage() string {
	switch o.formatType {
	case FormatTypeYAML:
		return "You are a helpful assistant that responds in YAML format."
	default:
		return "You are a helpful assistant that responds in JSON format."
	}
}

type geminiExtractor struct {
	baseExtractor
	modelID string
	apiKey  string
	baseURL string
	client  *http.Client
}

// Gemini creates a Gemini-backed extractor.
//
// Required kwargs:
//   - api_key
//
// Common optional kwargs:
//   - base_url
//   - timeout_seconds
//   - format_type / format
func Gemini(_ context.Context, cfg ModelConfig) (Extractor, error) {
	apiKey := cfg.apiKey()
	if apiKey == "" {
		return nil, &InferenceConfigError{newErr("gemini", "api_key is required")}
	}
	baseURL := stringOr(cfg.ProviderKwargs["base_url"], "https://generativelanguage.googleapis.com")
	format := formatFromKwargs(cfg.ProviderKwargs, FormatTypeJSON)

	timeout := floatFrom(cfg.ProviderKwargs["timeout_seconds"], 30)
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}

	return &geminiExtractor{
		baseExtractor: baseExtractor{
			formatType:   format,
			fenceOutput:  false,
			defaultModel: "gemini-2.5-flash",
		},
		modelID: cfg.modelOrDefault("gemini-2.5-flash"),
		apiKey:  apiKey,
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  client,
	}, nil
}

func (g *geminiExtractor) Infer(ctx context.Context, prompts []string, options map[string]any) ([][]ScoredOutput, error) {
	if len(prompts) == 0 {
		return nil, nil
	}
	out := make([][]ScoredOutput, 0, len(prompts))

	for _, prompt := range prompts {
		callStart := time.Now()
		generationConfig := map[string]any{}
		applyGeminiOptions(generationConfig, options)
		if g.formatType == FormatTypeJSON {
			generationConfig["responseMimeType"] = "application/json"
		}

		payload := map[string]any{
			"contents": []map[string]any{
				{
					"parts": []map[string]string{
						{"text": prompt},
					},
				},
			},
			"generationConfig": generationConfig,
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}

		url := fmt.Sprintf("%s/v1beta/models/%s:generateContent?key=%s", g.baseURL, g.modelID, g.apiKey)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := g.client.Do(req)
		if err != nil {
			return nil, &InferenceError{newErr("gemini_infer", err.Error())}
		}
		data, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, &InferenceError{newErr("gemini_infer", fmt.Sprintf("status %d: %s", resp.StatusCode, truncateString(string(data), 300)))}
		}

		var parsed struct {
			Candidates []struct {
				Content struct {
					Parts []struct {
						Text string `json:"text"`
					} `json:"parts"`
				} `json:"content"`
			} `json:"candidates"`
			UsageMetadata struct {
				PromptTokenCount        int64 `json:"promptTokenCount"`
				CandidatesTokenCount    int64 `json:"candidatesTokenCount"`
				TotalTokenCount         int64 `json:"totalTokenCount"`
				CachedContentTokenCount int64 `json:"cachedContentTokenCount"`
				ThoughtsTokenCount      int64 `json:"thoughtsTokenCount"`
			} `json:"usageMetadata"`
		}
		if err := json.Unmarshal(data, &parsed); err != nil {
			return nil, err
		}
		if len(parsed.Candidates) == 0 || len(parsed.Candidates[0].Content.Parts) == 0 {
			return nil, &InferenceOutputError{newErr("gemini_infer", "no candidate content in response")}
		}
		usage := &InferenceUsage{
			Provider:          "gemini",
			Model:             g.modelID,
			InputTokens:       parsed.UsageMetadata.PromptTokenCount,
			OutputTokens:      parsed.UsageMetadata.CandidatesTokenCount,
			TotalTokens:       parsed.UsageMetadata.TotalTokenCount,
			CachedInputTokens: parsed.UsageMetadata.CachedContentTokenCount,
			ReasoningTokens:   parsed.UsageMetadata.ThoughtsTokenCount,
			LatencyMs:         time.Since(callStart).Milliseconds(),
		}
		out = append(out, []ScoredOutput{{Score: 1.0, Output: parsed.Candidates[0].Content.Parts[0].Text, Usage: usage}})
	}

	return out, nil
}

type ollamaExtractor struct {
	baseExtractor
	modelID string
	baseURL string
	client  *http.Client
}

// Ollama creates an Ollama-backed extractor.
//
// Common optional kwargs:
//   - base_url
//   - timeout_seconds
//   - format_type / format
func Ollama(_ context.Context, cfg ModelConfig) (Extractor, error) {
	baseURL := stringOr(cfg.ProviderKwargs["base_url"], "http://localhost:11434")
	format := formatFromKwargs(cfg.ProviderKwargs, FormatTypeJSON)
	timeout := floatFrom(cfg.ProviderKwargs["timeout_seconds"], 120)
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}

	return &ollamaExtractor{
		baseExtractor: baseExtractor{
			formatType:   format,
			fenceOutput:  false,
			defaultModel: "llama3.2",
		},
		modelID: cfg.modelOrDefault("llama3.2"),
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  client,
	}, nil
}

func (o *ollamaExtractor) Infer(ctx context.Context, prompts []string, options map[string]any) ([][]ScoredOutput, error) {
	if len(prompts) == 0 {
		return nil, nil
	}
	out := make([][]ScoredOutput, 0, len(prompts))

	for _, prompt := range prompts {
		payload := map[string]any{
			"model":  o.modelID,
			"prompt": prompt,
			"stream": false,
		}
		if o.formatType == FormatTypeJSON {
			payload["format"] = "json"
		} else if o.formatType == FormatTypeYAML {
			payload["format"] = "yaml"
		}

		optionsBlock := map[string]any{}
		applyOllamaOptions(optionsBlock, options)
		if len(optionsBlock) > 0 {
			payload["options"] = optionsBlock
		}

		body, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+"/api/generate", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := o.client.Do(req)
		if err != nil {
			return nil, &InferenceError{newErr("ollama_infer", err.Error())}
		}
		data, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, &InferenceError{newErr("ollama_infer", fmt.Sprintf("status %d: %s", resp.StatusCode, truncateString(string(data), 300)))}
		}

		var parsed struct {
			Response string `json:"response"`
		}
		if err := json.Unmarshal(data, &parsed); err != nil {
			return nil, err
		}
		if strings.TrimSpace(parsed.Response) == "" {
			return nil, &InferenceOutputError{newErr("ollama_infer", "empty response from ollama")}
		}
		out = append(out, []ScoredOutput{{Score: 1.0, Output: parsed.Response}})
	}
	return out, nil
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

func applyOpenAIOptions(payload, options map[string]any) {
	if len(options) == 0 {
		return
	}
	var (
		reasoningValue any
		hasReasoning   bool
		effortValue    any
		hasEffort      bool
	)
	for k, v := range options {
		if v == nil {
			continue
		}
		switch k {
		case "max_output_tokens":
			payload["max_tokens"] = v
		case "reasoning":
			reasoningValue = v
			hasReasoning = true
		case "reasoning_effort":
			effortValue = v
			hasEffort = true
		case "max_workers",
			"api_key",
			"key",
			"base_url",
			"model_url",
			"timeout_seconds",
			"format_type",
			"format",
			"organization":
			// Client-side only. Do not forward to provider payload.
		default:
			payload[k] = v
		}
	}
	if hasReasoning {
		payload["reasoning"] = reasoningValue
	}
	if hasEffort {
		mergeOpenAIReasoning(payload, effortValue)
	}
}

func mergeOpenAIReasoning(payload map[string]any, effort any) {
	reasoning := map[string]any{}
	if raw, ok := payload["reasoning"]; ok {
		switch existing := raw.(type) {
		case map[string]any:
			for k, v := range existing {
				reasoning[k] = v
			}
		case map[string]string:
			for k, v := range existing {
				reasoning[k] = v
			}
		}
	}
	reasoning["effort"] = effort
	payload["reasoning"] = reasoning
}

func applyGeminiOptions(generationConfig, options map[string]any) {
	if len(options) == 0 {
		return
	}
	for k, v := range options {
		if v == nil {
			continue
		}
		switch k {
		case "max_workers",
			"api_key",
			"key",
			"base_url",
			"model_url",
			"timeout_seconds",
			"format_type",
			"format":
			// Client-side only.
		case "max_output_tokens":
			generationConfig["maxOutputTokens"] = v
		case "top_p":
			generationConfig["topP"] = v
		case "top_k":
			generationConfig["topK"] = v
		case "candidate_count":
			generationConfig["candidateCount"] = v
		case "stop_sequences":
			generationConfig["stopSequences"] = v
		default:
			generationConfig[k] = v
		}
	}
}

func applyOllamaOptions(optionsBlock, options map[string]any) {
	if len(options) == 0 {
		return
	}
	for k, v := range options {
		if v == nil {
			continue
		}
		switch k {
		case "max_workers",
			"api_key",
			"key",
			"base_url",
			"model_url",
			"timeout_seconds",
			"format_type",
			"format":
			// Client-side only.
		case "max_output_tokens":
			optionsBlock["num_predict"] = v
		default:
			optionsBlock[k] = v
		}
	}
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

// DeepSeek is a thin wrapper that returns an OpenAI-compatible extractor
// pointed at api.deepseek.com. DeepSeek's hosted API mirrors the OpenAI
// chat-completions surface so we reuse OpenAI's request/response code
// rather than duplicating it. The factory injects the right base_url
// before delegating, and reads DEEPSEEK_API_KEY from ProviderKwargs as
// a convenience alias for `api_key`.
//
// Local Ollama-hosted DeepSeek models (e.g. `deepseek-r1:7b`) still
// route through the Ollama provider — they don't match this provider's
// patterns (`^deepseek-(chat|reasoner|coder)$`).
func DeepSeek(ctx context.Context, cfg ModelConfig) (Extractor, error) {
	if cfg.ProviderKwargs == nil {
		cfg.ProviderKwargs = map[string]any{}
	}
	if _, set := cfg.ProviderKwargs["base_url"]; !set {
		cfg.ProviderKwargs["base_url"] = "https://api.deepseek.com"
	}
	// Allow callers to set DEEPSEEK_API_KEY env var via ProviderKwargs alias.
	if cfg.apiKey() == "" {
		if alt := stringOr(cfg.ProviderKwargs["deepseek_api_key"], ""); alt != "" {
			cfg.ProviderKwargs["api_key"] = alt
		}
	}
	return OpenAI(ctx, cfg)
}
