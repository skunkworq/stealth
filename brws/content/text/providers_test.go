package langextract

import (
	"context"
	"testing"
)

func TestProviderRegistryPriorityAndHint(t *testing.T) {
	clearProviderRegistryForTests()
	t.Cleanup(func() {
		clearProviderRegistryForTests()
		registerBuiltins()
	})

	factoryLow := func(_ context.Context, _ ModelConfig) (Extractor, error) {
		return newFakeExtractor(), nil
	}
	factoryHigh := func(_ context.Context, _ ModelConfig) (Extractor, error) {
		return newFakeExtractor(), nil
	}

	if err := registerProviderWithPatterns("low", factoryLow, 1, []string{`^model`}); err != nil {
		t.Fatalf("register low failed: %v", err)
	}
	if err := registerProviderWithPatterns("high", factoryHigh, 10, []string{`^model`}); err != nil {
		t.Fatalf("register high failed: %v", err)
	}

	factory, name, err := resolveProviderFactory("model-v1", "")
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if name != "high" {
		t.Fatalf("expected high-priority provider, got %q", name)
	}
	if _, err := factory(context.Background(), ModelConfig{ModelID: "model-v1"}); err != nil {
		t.Fatalf("factory call failed: %v", err)
	}

	_, name, err = resolveProviderFactory("model-v1", "low")
	if err != nil {
		t.Fatalf("resolve by hint failed: %v", err)
	}
	if name != "low" {
		t.Fatalf("expected hinted provider low, got %q", name)
	}
}

func TestRegisterProviderDuplicate(t *testing.T) {
	clearProviderRegistryForTests()
	t.Cleanup(func() {
		clearProviderRegistryForTests()
		registerBuiltins()
	})

	factory := func(_ context.Context, _ ModelConfig) (Extractor, error) {
		return newFakeExtractor(), nil
	}
	if err := RegisterProvider("custom", factory); err != nil {
		t.Fatalf("initial register failed: %v", err)
	}
	if err := RegisterProvider("custom", factory); err == nil {
		t.Fatalf("expected duplicate registration error")
	}
}
