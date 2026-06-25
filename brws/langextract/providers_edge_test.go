package langextract

import (
	"context"
	"sort"
	"strings"
	"testing"
)

func TestListProvidersContainsBuiltinsAndSorted(t *testing.T) {
	resetProviderRegistryForTests()
	t.Cleanup(func() {
		resetProviderRegistryForTests()
	})

	got := ListProviders()
	if len(got) == 0 {
		t.Fatalf("expected non-empty provider list")
	}

	want := append([]string(nil), got...)
	sort.Strings(want)
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("expected sorted providers, got=%v", got)
		}
	}

	for _, required := range []string{"gemini", "openai", "ollama"} {
		found := false
		for _, name := range got {
			if name == required {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected built-in provider %q in list %v", required, got)
		}
	}
}

func TestResolveProviderFactoryErrors(t *testing.T) {
	resetProviderRegistryForTests()
	t.Cleanup(func() {
		resetProviderRegistryForTests()
	})

	if _, _, err := resolveProviderFactory("unknown-model", ""); err == nil {
		t.Fatalf("expected no provider registered error")
	}
	if _, _, err := resolveProviderFactory("any", "missing-provider"); err == nil {
		t.Fatalf("expected missing provider hint error")
	}
}

func TestModelConfigHelpers(t *testing.T) {
	t.Parallel()

	cfg := ModelConfig{
		ProviderKwargs: map[string]any{"key": "alias-key"},
	}
	if got := cfg.apiKey(); got != "alias-key" {
		t.Fatalf("expected key alias to resolve api key, got %q", got)
	}
	if got := cfg.modelOrDefault("fallback-model"); got != "fallback-model" {
		t.Fatalf("expected fallback model, got %q", got)
	}

	cfg.ModelID = "explicit-model"
	if got := cfg.modelOrDefault("fallback-model"); got != "explicit-model" {
		t.Fatalf("expected explicit model, got %q", got)
	}
}

func TestExtractorMutatorMethods(t *testing.T) {
	t.Parallel()

	extractor, err := OpenAI(context.Background(), ModelConfig{
		ModelID: "gpt-4o-mini",
		ProviderKwargs: map[string]any{
			"api_key": "test-key",
		},
	})
	if err != nil {
		t.Fatalf("failed to create extractor: %v", err)
	}

	extractor.SetFenceOutput(true)
	if !extractor.RequiresFenceOutput() {
		t.Fatalf("expected fence output to be enabled")
	}
	extractor.SetFormatType(FormatTypeYAML)
	if extractor.FormatType() != FormatTypeYAML {
		t.Fatalf("expected format type yaml, got %q", extractor.FormatType())
	}
}

func TestTruncateString(t *testing.T) {
	t.Parallel()

	if got := truncateString("hello", 10); got != "hello" {
		t.Fatalf("expected unchanged string, got %q", got)
	}
	if got := truncateString("abcdefghij", 5); got != "ab..." {
		t.Fatalf("unexpected truncated string: %q", got)
	}
	if got := truncateString("abcdef", 2); got != "ab" {
		t.Fatalf("unexpected short truncation: %q", got)
	}
	if got := truncateString("abcdef", 4); !strings.HasSuffix(got, "...") {
		t.Fatalf("expected ellipsis suffix, got %q", got)
	}
}

func TestProviderHelperParsers(t *testing.T) {
	t.Parallel()

	if got := floatFrom(float64(3.25), 1.5); got != 3.25 {
		t.Fatalf("expected float64 passthrough, got %v", got)
	}
	if got := floatFrom(float32(2.5), 1.5); got != 2.5 {
		t.Fatalf("expected float32 conversion, got %v", got)
	}
	if got := floatFrom(3, 1.5); got != 3 {
		t.Fatalf("expected int conversion to float64, got %v", got)
	}
	if got := floatFrom("bad", 1.5); got != 1.5 {
		t.Fatalf("expected default for unsupported type, got %v", got)
	}

	if got := formatFromKwargs(map[string]any{"format_type": "yaml"}, FormatTypeJSON); got != FormatTypeYAML {
		t.Fatalf("expected format_type yaml mapping, got %q", got)
	}
	if got := formatFromKwargs(map[string]any{"format": "json"}, FormatTypeYAML); got != FormatTypeJSON {
		t.Fatalf("expected format json mapping, got %q", got)
	}
	if got := formatFromKwargs(map[string]any{"format_type": "xml"}, FormatTypeYAML); got != FormatTypeYAML {
		t.Fatalf("expected fallback format for unsupported value, got %q", got)
	}
	if got := formatFromKwargs(nil, FormatTypeJSON); got != FormatTypeJSON {
		t.Fatalf("expected default when kwargs nil, got %q", got)
	}
}

func TestOpenAISystemMessageFormats(t *testing.T) {
	t.Parallel()

	ext := &openAIExtractor{}
	ext.SetFormatType(FormatTypeYAML)
	if got := ext.systemMessage(); !strings.Contains(got, "YAML") {
		t.Fatalf("expected yaml system message, got %q", got)
	}
	ext.SetFormatType(FormatTypeJSON)
	if got := ext.systemMessage(); !strings.Contains(got, "JSON") {
		t.Fatalf("expected json system message, got %q", got)
	}
}

func TestMergeOpenAIReasoningMapVariants(t *testing.T) {
	t.Parallel()

	payload := map[string]any{
		"reasoning": map[string]string{"existing": "yes"},
	}
	mergeOpenAIReasoning(payload, "minimal")
	reasoning, ok := payload["reasoning"].(map[string]any)
	if !ok {
		t.Fatalf("expected merged reasoning map, got %T", payload["reasoning"])
	}
	if reasoning["existing"] != "yes" || reasoning["effort"] != "minimal" {
		t.Fatalf("unexpected merged reasoning map: %v", reasoning)
	}

	payload = map[string]any{"reasoning": "not-a-map"}
	mergeOpenAIReasoning(payload, "low")
	reasoning, ok = payload["reasoning"].(map[string]any)
	if !ok || reasoning["effort"] != "low" {
		t.Fatalf("expected effort-only reasoning map after unsupported existing type, got %v", payload["reasoning"])
	}
}
