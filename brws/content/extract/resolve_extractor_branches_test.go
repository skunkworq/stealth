package extract

import (
	"context"
	"testing"
)

func TestResolveExtractorModelBranchWithConfigModelID(t *testing.T) {
	t.Parallel()

	model := newFakeExtractor()
	cfg := &ModelConfig{ModelID: "cfg-model"}
	gotModel, provider, modelID, err := resolveExtractor(context.Background(), extractOptions{
		ModelID: "fallback-model",
		Model:   model,
		Config:  cfg,
	})
	if err != nil {
		t.Fatalf("resolveExtractor failed: %v", err)
	}
	if gotModel != model || provider != "custom" || modelID != "cfg-model" {
		t.Fatalf("unexpected model branch result: provider=%q modelID=%q", provider, modelID)
	}
}

func TestResolveExtractorConfigAndTemperatureOverride(t *testing.T) {
	clearProviderRegistryForTests()
	t.Cleanup(func() {
		clearProviderRegistryForTests()
		registerBuiltins()
	})

	var capturedCfg ModelConfig
	if err := RegisterProvider("capture", func(_ context.Context, cfg ModelConfig) (Extractor, error) {
		capturedCfg = cfg
		return newFakeExtractor(), nil
	}); err != nil {
		t.Fatalf("register provider failed: %v", err)
	}

	temp := 0.3
	_, provider, modelID, err := resolveExtractor(context.Background(), extractOptions{
		Config: &ModelConfig{
			ModelID:       "config-model",
			ProviderClass: "capture",
			ProviderKwargs: map[string]any{
				"temperature": 0.9,
				"top_p":       0.8,
			},
		},
		ModelParams: map[string]any{
			"top_p": 0.5,
		},
		Temperature: &temp,
	})
	if err != nil {
		t.Fatalf("resolveExtractor failed: %v", err)
	}
	if provider != "capture" || modelID != "config-model" {
		t.Fatalf("unexpected resolve result: provider=%q modelID=%q", provider, modelID)
	}
	if capturedCfg.ProviderKwargs["top_p"] != 0.5 {
		t.Fatalf("expected runtime model params override, got top_p=%v", capturedCfg.ProviderKwargs["top_p"])
	}
	if capturedCfg.ProviderKwargs["temperature"] != temp {
		t.Fatalf("expected explicit temperature override, got %v", capturedCfg.ProviderKwargs["temperature"])
	}
}

func TestResolveExtractorDefaultModelIDAndHintPrecedence(t *testing.T) {
	clearProviderRegistryForTests()
	t.Cleanup(func() {
		clearProviderRegistryForTests()
		registerBuiltins()
	})

	if err := RegisterProvider("hinted", func(_ context.Context, _ ModelConfig) (Extractor, error) {
		return newFakeExtractor(), nil
	}); err != nil {
		t.Fatalf("register provider failed: %v", err)
	}

	_, provider, modelID, err := resolveExtractor(context.Background(), extractOptions{
		ModelID:      "",
		ProviderHint: "hinted",
	})
	if err != nil {
		t.Fatalf("resolveExtractor failed: %v", err)
	}
	if provider != "hinted" {
		t.Fatalf("expected hinted provider, got %q", provider)
	}
	if modelID != defaultModelID {
		t.Fatalf("expected default model id %q, got %q", defaultModelID, modelID)
	}
}
