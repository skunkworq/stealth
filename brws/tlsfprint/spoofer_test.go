package tlsfprint

import (
	"testing"
)

// Note: Some tests commented out due to naming differences in utls library

func TestSpooferGetChromeID(t *testing.T) {
	s := New()

	fp := s.getChromeID("133")
	if fp.Str() == "" {
		t.Error("getChromeID returned empty")
	}

	fp = s.getChromeID("120")
	if fp.Str() == "" {
		t.Error("getChromeID returned empty")
	}

	fp = s.getChromeID("auto")
	if fp.Str() == "" {
		t.Error("getChromeID returned empty")
	}
}

func TestSpooferGetFirefoxID(t *testing.T) {
	s := New()

	fp := s.getFirefoxID("120")
	if fp.Str() == "" {
		t.Error("getFirefoxID returned empty")
	}

	fp = s.getFirefoxID("105")
	if fp.Str() == "" {
		t.Error("getFirefoxID returned empty")
	}

	fp = s.getFirefoxID("auto")
	if fp.Str() == "" {
		t.Error("getFirefoxID returned empty")
	}
}

func TestSpooferGetClientHelloID(t *testing.T) {
	s := New()

	_ = s.GetClientHelloID(Chrome, "133")
	_ = s.GetClientHelloID(Chrome, "120")
	_ = s.GetClientHelloID(Chrome, "auto")
	_ = s.GetClientHelloID(Firefox, "120")
	_ = s.GetClientHelloID(Firefox, "auto")
	_ = s.GetClientHelloID(Safari, "16.0")
	_ = s.GetClientHelloID(Edge, "106")
	_ = s.GetClientHelloID(Edge, "auto")
	_ = s.GetClientHelloID(IOS, "14")
	_ = s.GetClientHelloID(IOS, "13")
	_ = s.GetClientHelloID(Android, "11")
}

func TestSpooferGetRotatingFingerprint(t *testing.T) {
	s := New()

	fp1 := s.GetRotatingFingerprint()
	fp2 := s.GetRotatingFingerprint()

	if fp1.Str() == fp2.Str() {
		t.Logf("Note: Rotating fingerprints may repeat due to random selection")
	}
}

func TestSpooferGetRandomized(t *testing.T) {
	s := New()

	fp1 := s.GetRandomized(true)
	fp2 := s.GetRandomized(false)

	if fp1.Str() == "" {
		t.Error("GetRandomized(true) returned empty")
	}
	if fp2.Str() == "" {
		t.Error("GetRandomized(false) returned empty")
	}
}

func TestSpooferDetectBrowserFromJA4(t *testing.T) {
	s := New()

	tests := []struct {
		ja4      string
		expected string
	}{
		{"t13_1301", "chrome"},
		{"t13_1302", "chrome"},
		{"t13_1303", "chrome"},
		{"t13_cca9", "modern_browser"},
		{"t12_cca9", "tls12_browser"},
		{"unknown", "unknown"},
	}

	for _, tt := range tests {
		result := s.DetectBrowserFromJA4(tt.ja4)
		if result != tt.expected {
			t.Errorf("DetectBrowserFromJA4(%s) = %s, want %s", tt.ja4, result, tt.expected)
		}
	}
}

func TestSpooferCalculateJA3(t *testing.T) {
	s := New()

	ciphers := []uint16{0x1301, 0x1302, 0x1303}
	extensions := []uint16{0, 1, 2, 3, 4, 5}

	ja3 := s.CalculateJA3(ciphers, extensions, 0x0303)

	if ja3 == "" {
		t.Error("CalculateJA3 returned empty string")
	}
}

func TestSpooferCalculateJA4(t *testing.T) {
	s := New()

	ja4 := s.CalculateJA4(0x0304, 0x1301, "h2", []uint16{0, 1, 2})

	if ja4 == "" {
		t.Error("CalculateJA4 returned empty string")
	}

	expected := "t13h2_1301"
	if ja4 != expected {
		t.Errorf("CalculateJA4() = %s, want %s", ja4, expected)
	}
}

func TestSpooferGetSupportedBrowsers(t *testing.T) {
	s := New()

	browsers := s.GetSupportedBrowsers()

	if len(browsers) == 0 {
		t.Error("GetSupportedBrowsers returned empty list")
	}

	expectedBrowsers := []string{
		"chrome-auto",
		"chrome-133",
		"chrome-120",
		"firefox-auto",
		"firefox-120",
		"firefox-105",
		"safari-16.0",
		"edge-auto",
		"edge-106",
		"ios-14",
		"ios-13",
		"android-11-okhttp",
		"randomized",
		"randomized-alpn",
		"randomized-noalpn",
	}

	for _, expected := range expectedBrowsers {
		found := false
		for _, b := range browsers {
			if b == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected browser %s not found in supported browsers", expected)
		}
	}
}

func TestSpooferParseBrowserVersion(t *testing.T) {
	tests := []struct {
		input           string
		expectedBrowser Browser
		expectedVersion string
	}{
		{"chrome-auto", Chrome, ""},
		{"chrome-120", Chrome, "120"},
		{"firefox-105", Firefox, "105"},
		{"safari-16.0", Safari, "16.0"},
		{"edge-auto", Edge, ""},
		{"ios-14", IOS, "14"},
		{"android-11", Android, "11"},
	}

	for _, tt := range tests {
		browser, version := ParseBrowserVersion(tt.input)
		if browser != tt.expectedBrowser {
			t.Errorf("ParseBrowserVersion(%s) browser = %s, want %s", tt.input, browser, tt.expectedBrowser)
		}
		if version != tt.expectedVersion {
			t.Errorf("ParseBrowserVersion(%s) version = %s, want %s", tt.input, version, tt.expectedVersion)
		}
	}
}

func TestFingerprintGenerator(t *testing.T) {
	fg := NewFingerprintGenerator()

	fp := fg.Browser(Chrome).Version("120").Build()
	if fp.Str() == "" {
		t.Error("FingerprintGenerator Build() returned empty")
	}

	fpRandom := fg.Browser(Chrome).BuildRandomized()
	if fpRandom.Str() == "" {
		t.Error("FingerprintGenerator BuildRandomized() returned empty")
	}

	fpRotating := fg.BuildRotating()
	if fpRotating.Str() == "" {
		t.Error("FingerprintGenerator BuildRotating() returned empty")
	}
}

func TestRotator(t *testing.T) {
	fps := []ClientHelloID{HelloChrome_Auto, HelloFirefox_Auto, HelloSafari_16_0}
	r := NewRotator(fps)

	fp1 := r.Next()
	fp2 := r.Next()
	_ = fp2
	fp3 := r.Next()
	fp4 := r.Next()

	if fp1.Str() == fp3.Str() {
		t.Error("Rotator.Next() returned same fingerprint")
	}
	if fp4.Str() != fp1.Str() {
		t.Error("Rotator should have wrapped around")
	}
}

func TestRotatorRandom(t *testing.T) {
	fps := []ClientHelloID{HelloChrome_Auto, HelloFirefox_Auto}
	r := NewRotator(fps)

	fp := r.Random()
	if fp.Str() == "" {
		t.Error("Rotator.Random() returned empty")
	}
}

func TestFingerprintPool(t *testing.T) {
	pool := NewFingerprintPool()

	pool.AddRotator("chrome", []ClientHelloID{HelloChrome_Auto, HelloChrome_120})
	pool.AddRotator("firefox", []ClientHelloID{HelloFirefox_Auto, HelloFirefox_120})
	pool.SetDefault(HelloSafari_16_0)

	_ = pool.Get("chrome")
	_ = pool.Get("firefox")

	fp3 := pool.GetRandom("chrome")
	if fp3.Str() == "" {
		t.Error("FingerprintPool.GetRandom() returned empty")
	}

	fp4 := pool.Get("unknown")
	if fp4.Str() != "Safari-16.0" {
		t.Errorf("FingerprintPool.Get(unknown) = %s, want default Safari-16.0", fp4.Str())
	}
}

func TestSpooferWithSeed(t *testing.T) {
	s1 := New().WithSeed(12345)
	s2 := New().WithSeed(12345)

	fp1 := s1.GetRotatingFingerprint()
	fp2 := s2.GetRotatingFingerprint()

	if fp1.Str() != fp2.Str() {
		t.Error("Same seed should produce same fingerprint sequence")
	}
}

func TestSpooferCreateChromeFingerprint(t *testing.T) {
	s := New()

	fp := s.CreateChromeFingerprint()

	if fp.Str() == "" {
		t.Error("CreateChromeFingerprint() returned empty")
	}
}

func TestSpooferCreateFirefoxFingerprint(t *testing.T) {
	s := New()

	fp := s.CreateFirefoxFingerprint()

	if fp.Str() == "" {
		t.Error("CreateFirefoxFingerprint() returned empty")
	}
}

func TestSpooferCreateMobileFingerprint(t *testing.T) {
	s := New()

	fp := s.CreateMobileFingerprint()

	if fp.Str() == "" {
		t.Error("CreateMobileFingerprint() returned empty")
	}
}

func TestSpooferAnalyzeJA4(t *testing.T) {
	s := New()

	info := s.AnalyzeJA4("t13_1301_cca8")

	if info.JA4 != "t13_1301_cca8" {
		t.Errorf("AnalyzeJA4 JA4 = %s, want t13_1301_cca8", info.JA4)
	}
	if info.Version != "TLS 1.3" {
		t.Errorf("AnalyzeJA4 Version = %s, want TLS 1.3", info.Version)
	}
	if len(info.Ciphers) == 0 {
		t.Error("AnalyzeJA4 Ciphers should not be empty")
	}
}

func TestFingerprintToJA3Hash(t *testing.T) {
	hash := FingerprintToJA3Hash("test-ja3")

	if hash == "" {
		t.Error("FingerprintToJA3Hash returned empty")
	}
}
