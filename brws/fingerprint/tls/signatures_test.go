package tlsfprint

import (
	"encoding/json"
	"testing"
)

func TestGetAllSignatures(t *testing.T) {
	sigs := GetAllSignatures()

	if len(sigs) == 0 {
		t.Error("GetAllSignatures returned empty")
	}

	if len(sigs) < 5 {
		t.Errorf("Expected at least 5 signatures, got %d", len(sigs))
	}
}

func TestGetSignatureByName(t *testing.T) {
	tests := []struct {
		name        string
		expectFound bool
	}{
		{"chrome-133-windows", true},
		{"chrome-120-android", true},
		{"firefox-120-windows", true},
		{"safari-16-macos", true},
		{"nonexistent", false},
	}

	for _, tt := range tests {
		sig := GetSignatureByName(tt.name)
		if tt.expectFound && sig == nil {
			t.Errorf("Expected to find %s, got nil", tt.name)
		}
		if !tt.expectFound && sig != nil {
			t.Errorf("Expected not to find %s, got %v", tt.name, sig)
		}
	}
}

func TestGetSignaturesByLabel(t *testing.T) {
	sigs := GetSignaturesByLabel("chrome")
	if len(sigs) == 0 {
		t.Error("GetSignaturesByLabel returned empty for 'chrome'")
	}

	for _, sig := range sigs {
		found := false
		for _, l := range sig.Labels {
			if l == "chrome" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Signature %s doesn't have label 'chrome'", sig.Name)
		}
	}
}

func TestGetSignaturesByPlatform(t *testing.T) {
	sigs := GetSignaturesByPlatform(PlatformWindows)
	if len(sigs) == 0 {
		t.Error("GetSignaturesByPlatform returned empty for 'windows'")
	}

	for _, sig := range sigs {
		if sig.BrowserProps.Platform != PlatformWindows {
			t.Errorf("Signature %s has platform %s, expected windows", sig.Name, sig.BrowserProps.Platform)
		}
	}
}

func TestGetSignaturesByLibrary(t *testing.T) {
	sigs := GetSignaturesByLibrary(LibraryBoringSSL)
	if len(sigs) == 0 {
		t.Error("GetSignaturesByLibrary returned empty for 'boringssl'")
	}
}

func TestSignatureConfigMatches(t *testing.T) {
	config := SignatureConfig{
		PreferredBrowser: FamilyChrome,
		RequireHTTP3:     true,
		MinConfidence:    0.8,
	}

	sigs := GetAllSignatures()
	for _, sig := range sigs {
		result := config.Matches(&sig)
		if result && sig.BrowserProps.BrowserFamily != FamilyChrome {
			t.Errorf("Config matched %s which is not Chrome", sig.Name)
		}
		if result && !sig.BrowserProps.SupportsHTTP3 {
			t.Errorf("Config matched %s which doesn't support HTTP3", sig.Name)
		}
		if result && sig.Confidence < 0.8 {
			t.Errorf("Config matched %s which has low confidence", sig.Name)
		}
	}
}

func TestFilterSignatures(t *testing.T) {
	config := SignatureConfig{
		PreferredBrowser: FamilyFirefox,
	}
	sigs := FilterSignatures(config)

	for _, sig := range sigs {
		if sig.BrowserProps.BrowserFamily != FamilyFirefox {
			t.Errorf("Filtered signature %s is not Firefox", sig.Name)
		}
	}
}

func TestAdaptiveSpoofer(t *testing.T) {
	spoof := NewAdaptiveSpoofer()

	config := SignatureConfig{
		PreferredBrowser: FamilyChrome,
	}
	spoof.WithConfig(config)

	sig := spoof.GetBestSignature()
	if sig.Name == "" {
		t.Error("GetBestSignature returned empty")
	}
}

func TestAdaptiveSpooferWithMLPrediction(t *testing.T) {
	spoof := NewAdaptiveSpoofer()

	prediction := &MLPrediction{
		SignatureName: "chrome-133-windows",
		Confidence:    0.95,
	}
	spoof.SetMLPrediction(prediction)

	sig := spoof.GetBestSignature()
	if sig.Name != "chrome-133-windows" {
		t.Errorf("Expected chrome-133-windows, got %s", sig.Name)
	}
}

func TestAdaptiveSpooferHistory(t *testing.T) {
	spoof := NewAdaptiveSpoofer()

	spoof.RecordSelection(SignatureSelection{
		Signature: "chrome-133-windows",
		Success:   true,
		Latency:   100,
		Score:     0.9,
	})

	history := spoof.GetHistory()
	if len(history) != 1 {
		t.Errorf("Expected 1 history entry, got %d", len(history))
	}
}

func TestFeatureExtractor(t *testing.T) {
	extractor := FeatureExtractor{}

	sig := Chrome133Windows
	features := extractor.ExtractFromSignature(&sig)

	if len(features) == 0 {
		t.Error("ExtractFromSignature returned empty")
	}
}

func TestFeatureExtractorFromJA4(t *testing.T) {
	extractor := FeatureExtractor{}

	features := extractor.ExtractFromJA4("t13h2_1301")

	if len(features) == 0 {
		t.Error("ExtractFromJA4 returned empty")
	}
}

func TestCalculateSimilarity(t *testing.T) {
	sim := CalculateSimilarity(&Chrome133Windows, &Chrome133MacOS)

	if sim < 0 || sim > 1 {
		t.Errorf("Similarity should be between 0 and 1, got %f", sim)
	}

	selfSim := CalculateSimilarity(&Chrome133Windows, &Chrome133Windows)
	if selfSim != 1.0 {
		t.Errorf("Self-similarity should be 1.0, got %f", selfSim)
	}
}

func TestFindMostSimilar(t *testing.T) {
	candidates := []FingerprintSignature{
		Chrome133MacOS,
		Firefox120Windows,
		Safari16MacOS,
	}

	match := FindMostSimilar(&Chrome133Windows, candidates)
	if match == nil {
		t.Error("FindMostSimilar returned nil")
	}
}

func TestSignatureRegistry(t *testing.T) {
	registry := NewSignatureRegistry()

	registry.Register(Chrome133Windows)

	sig := registry.Get("chrome-133-windows")
	if sig == nil {
		t.Error("Registry.Get returned nil")
	}

	sigs := registry.List()
	if len(sigs) == 0 {
		t.Error("Registry.List returned empty")
	}
}

func TestSignatureRegistryJSON(t *testing.T) {
	registry := NewSignatureRegistry()
	registry.Register(Chrome133Windows)

	jsonStr, err := registry.ToJSON()
	if err != nil {
		t.Errorf("ToJSON error: %v", err)
	}

	if jsonStr == "" {
		t.Error("ToJSON returned empty string")
	}

	registry2 := NewSignatureRegistry()
	err = registry2.FromJSON(jsonStr)
	if err != nil {
		t.Errorf("FromJSON error: %v", err)
	}

	sig := registry2.Get("chrome-133-windows")
	if sig == nil {
		t.Error("Registry from JSON Get returned nil")
	}
}

func TestSignatureRegistryMerge(t *testing.T) {
	registry1 := NewSignatureRegistry()
	registry1.Register(Chrome133Windows)

	registry2 := NewSignatureRegistry()
	registry2.Register(Firefox120Windows)

	registry1.Merge(registry2)

	if len(registry1.List()) != 2 {
		t.Error("Merge didn't combine signatures")
	}
}

func TestSignatureGenerator(t *testing.T) {
	gen := NewSignatureGenerator()

	sig := gen.GenerateRandom()
	if sig == nil {
		t.Error("GenerateRandom returned nil")
	}

	sig = gen.GenerateFromBase("chrome-133-windows")
	if sig == nil {
		t.Error("GenerateFromBase returned nil")
	}
}

func TestSignatureGeneratorWithSeed(t *testing.T) {
	gen := NewSignatureGenerator()
	gen.WithSeed(12345)

	sig1 := gen.GenerateRandom()
	if sig1 == nil {
		t.Error("GenerateRandom returned nil")
	}

	gen2 := NewSignatureGenerator()
	gen2.WithSeed(12345)

	sig2 := gen2.GenerateRandom()
	if sig2 == nil {
		t.Error("GenerateRandom returned nil")
	}
}

func TestSignatureGeneratorWithModifier(t *testing.T) {
	gen := NewSignatureGenerator()
	gen.AddModifier(func(props *BrowserProperties) {
		props.IsMobile = true
	})

	sig := gen.GenerateFromBase("chrome-133-windows")
	if sig == nil {
		t.Error("GenerateFromBase returned nil")
	}
}

func TestDefaultRegistry(t *testing.T) {
	if DefaultRegistry == nil {
		t.Error("DefaultRegistry is nil")
	}

	sigs := DefaultRegistry.List()
	if len(sigs) == 0 {
		t.Error("DefaultRegistry has no signatures")
	}
}

func TestBrowserPropertiesSerialization(t *testing.T) {
	props := Chrome133Windows.BrowserProps

	data, err := json.Marshal(props)
	if err != nil {
		t.Errorf("Marshal error: %v", err)
	}

	var props2 BrowserProperties
	err = json.Unmarshal(data, &props2)
	if err != nil {
		t.Errorf("Unmarshal error: %v", err)
	}

	if props2.Name != props.Name {
		t.Errorf("Name mismatch: %s vs %s", props2.Name, props.Name)
	}
}

func TestSignatureSerialization(t *testing.T) {
	sig := Chrome133Windows

	data, err := json.Marshal(sig)
	if err != nil {
		t.Errorf("Marshal error: %v", err)
	}

	var sig2 FingerprintSignature
	err = json.Unmarshal(data, &sig2)
	if err != nil {
		t.Errorf("Unmarshal error: %v", err)
	}

	if sig2.Name != sig.Name {
		t.Errorf("Name mismatch: %s vs %s", sig2.Name, sig.Name)
	}
}
