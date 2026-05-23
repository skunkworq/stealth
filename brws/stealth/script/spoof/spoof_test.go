package spoof

import (
	"context"
	"testing"
)

// TestNewChromeSpoof verifies the Chrome 116 constructor returns a valid, non-nil engine.
func TestNewChromeSpoof(t *testing.T) {
	engine, err := NewChromeSpoof()
	if err != nil {
		t.Fatalf("NewChromeSpoof() returned error: %v", err)
	}
	if engine == nil {
		t.Fatal("NewChromeSpoof() returned nil engine")
	}
}

// TestNewFirefoxSpoof verifies the Firefox 109 constructor returns a valid, non-nil engine.
func TestNewFirefoxSpoof(t *testing.T) {
	engine, err := NewFirefoxSpoof()
	if err != nil {
		t.Fatalf("NewFirefoxSpoof() returned error: %v", err)
	}
	if engine == nil {
		t.Fatal("NewFirefoxSpoof() returned nil engine")
	}
}

// TestNewSpoofEngine_ValidKeys checks all built-in signature keys load without error.
func TestNewSpoofEngine_ValidKeys(t *testing.T) {
	keys := []string{
		"chrome-116",
		"chrome-146",
		"firefox-109",
		"firefox-128",
		"edge-122",
		"safari-17",
	}
	for _, key := range keys {
		key := key
		t.Run(key, func(t *testing.T) {
			engine, err := NewSpoofEngine(key)
			if err != nil {
				t.Fatalf("NewSpoofEngine(%q) returned error: %v", key, err)
			}
			if engine == nil {
				t.Fatalf("NewSpoofEngine(%q) returned nil engine", key)
			}
		})
	}
}

// TestNewSpoofEngine_InvalidKey verifies an unknown key produces an error.
func TestNewSpoofEngine_InvalidKey(t *testing.T) {
	_, err := NewSpoofEngine("invalid-key")
	if err == nil {
		t.Fatal("expected error for invalid signature key, got nil")
	}
}

// TestNewSpoofEngine_EmptyKey verifies an empty string key produces an error.
func TestNewSpoofEngine_EmptyKey(t *testing.T) {
	_, err := NewSpoofEngine("")
	if err == nil {
		t.Fatal("expected error for empty signature key, got nil")
	}
}

// TestNewSpoofEngineFromSignature_NilSig verifies nil signature returns an error.
func TestNewSpoofEngineFromSignature_NilSig(t *testing.T) {
	_, err := NewSpoofEngineFromSignature("test", nil)
	if err == nil {
		t.Fatal("expected error for nil signature, got nil")
	}
}

// TestNewSpoofEngineFromSignature_Valid verifies a complete signature loads correctly.
func TestNewSpoofEngineFromSignature_Valid(t *testing.T) {
	sig := GetChrome116()
	engine, err := NewSpoofEngineFromSignature("chrome-custom", sig)
	if err != nil {
		t.Fatalf("NewSpoofEngineFromSignature() returned error: %v", err)
	}
	if engine == nil {
		t.Fatal("NewSpoofEngineFromSignature() returned nil engine")
	}
}

// TestSpoofEngine_Name verifies the Name() method returns the construction key.
func TestSpoofEngine_Name(t *testing.T) {
	engine, err := NewSpoofEngine("chrome-116")
	if err != nil {
		t.Fatalf("NewSpoofEngine failed: %v", err)
	}
	if engine.Name() != "chrome-116" {
		t.Errorf("Name() = %q, want %q", engine.Name(), "chrome-116")
	}
}

// TestSpoofEngine_Name_FromSignature verifies Name() returns the name given to NewSpoofEngineFromSignature.
func TestSpoofEngine_Name_FromSignature(t *testing.T) {
	sig := GetFirefox109()
	engine, err := NewSpoofEngineFromSignature("my-firefox", sig)
	if err != nil {
		t.Fatalf("NewSpoofEngineFromSignature failed: %v", err)
	}
	if engine.Name() != "my-firefox" {
		t.Errorf("Name() = %q, want %q", engine.Name(), "my-firefox")
	}
}

// TestSpoofEngine_Stats verifies Stats() returns a map with expected keys and no panic.
func TestSpoofEngine_Stats(t *testing.T) {
	engine, err := NewChromeSpoof()
	if err != nil {
		t.Fatalf("NewChromeSpoof() failed: %v", err)
	}
	stats := engine.Stats()
	if stats == nil {
		t.Fatal("Stats() returned nil map")
	}
	if _, ok := stats["requests_made"]; !ok {
		t.Error("Stats() missing key 'requests_made'")
	}
	if _, ok := stats["signature"]; !ok {
		t.Error("Stats() missing key 'signature'")
	}
}

// TestSpoofEngine_ImplementsEngineInterface checks that *SpoofEngine satisfies Engine.
func TestSpoofEngine_ImplementsEngineInterface(t *testing.T) {
	engine, err := NewChromeSpoof()
	if err != nil {
		t.Fatalf("NewChromeSpoof() failed: %v", err)
	}
	var _ Engine = engine
}

// TestSpoofEngine_Fetch_SkipsNetwork exercises Fetch() path only with a skip for actual network.
func TestSpoofEngine_Fetch_SkipsNetwork(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	t.Skip("skipping: live network not available in unit test environment")
	engine, err := NewChromeSpoof()
	if err != nil {
		t.Fatalf("NewChromeSpoof() failed: %v", err)
	}
	_, _ = engine.Fetch(context.Background(), "https://example.com")
}

// TestIsGREASEValue verifies helper correctly identifies GREASE values.
func TestIsGREASEValue(t *testing.T) {
	grease := []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xfafa}
	for _, g := range grease {
		if !isGREASEValue(g) {
			t.Errorf("isGREASEValue(%04x) = false, want true", g)
		}
	}
	notGREASE := []uint16{0x0000, 0x0001, 0x1301, 0xc02b, 0x002b}
	for _, v := range notGREASE {
		if isGREASEValue(v) {
			t.Errorf("isGREASEValue(%04x) = true, want false", v)
		}
	}
}

// TestGetGREASEValue verifies getGREASEValue returns a valid GREASE value for non-GREASE input.
func TestGetGREASEValue(t *testing.T) {
	// For a non-GREASE seed, should return default GREASE (0x5a5a)
	result := getGREASEValue(0x0001)
	if !isGREASEValue(result) {
		t.Errorf("getGREASEValue(0x0001) = %04x, which is not a GREASE value", result)
	}
	// For a GREASE seed, should return it unchanged
	result2 := getGREASEValue(0x0a0a)
	if result2 != 0x0a0a {
		t.Errorf("getGREASEValue(0x0a0a) = %04x, want 0x0a0a", result2)
	}
}

// TestLoadDefaultSignatures verifies all expected keys are present.
func TestLoadDefaultSignatures(t *testing.T) {
	sigs := LoadDefaultSignatures()
	if sigs == nil {
		t.Fatal("LoadDefaultSignatures() returned nil")
	}
	expected := []string{"chrome-116", "chrome-146", "firefox-109", "firefox-128", "edge-122", "safari-17"}
	for _, key := range expected {
		if _, ok := sigs[key]; !ok {
			t.Errorf("LoadDefaultSignatures() missing key %q", key)
		}
	}
}
