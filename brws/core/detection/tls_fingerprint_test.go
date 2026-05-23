package detection

import (
	"strings"
	"testing"
)

func TestTLSFingerprinter_AnalyzeConnection(t *testing.T) {
	fp := NewTLSFingerprinter()

	result, err := fp.AnalyzeConnection("google.com:443")
	if err != nil {
		t.Skipf("Skipping TLS test: %v", err)
	}

	t.Logf("TLS Analysis Results:")
	t.Logf("  JA4: %s", result.JA4)
	t.Logf("  JA3: %s", result.JA3)
	t.Logf("  JA3Hash: %s", result.JA3Hash)
	t.Logf("  Browser: %s", result.Browser)
	t.Logf("  IsChrome: %v", result.IsChrome)
	t.Logf("  Version: %s", result.Version)
	t.Logf("  ALPN: %s", result.ALPN)
	t.Logf("  SNI: %s", result.SNI)
	t.Logf("  Anomalies: %v", result.Anomalies)
}

func TestTLSFingerprinter_DetectBrowser(t *testing.T) {
	fp := NewTLSFingerprinter()

	tests := []struct {
		ja4      string
		expected string
	}{
		{"t12d1516h2_3fcf15715704", "chrome"},
		{"t13d1516h2_4a0256025210", "chrome"},
		{"t13__1301", "chrome"},
		{"t13__1302", "chrome"},
		{"t13__1303", "chrome"},
	}

	for _, tt := range tests {
		result := fp.DetectBrowserFromJA4(tt.ja4)
		if result != tt.expected {
			t.Errorf("DetectBrowserFromJA4(%s) = %s; want %s", tt.ja4, result, tt.expected)
		}
	}
}

func TestTLSFingerprinter_ChromeFingerprint(t *testing.T) {
	fp := NewTLSFingerprinter()

	fingerprint, err := fp.CaptureFingerprint("google.com:443", "chrome")
	if err != nil {
		t.Skipf("Skipping TLS test: %v", err)
	}

	t.Logf("Chrome Fingerprint:")
	t.Logf("  JA4: %s", fingerprint.JA4)
	t.Logf("  Version: %s", fingerprint.Version)
	t.Logf("  SNI: %s", fingerprint.SNI)
}

func TestNewTLSFingerprinter_notNil(t *testing.T) {
	fp := NewTLSFingerprinter()
	if fp == nil {
		t.Fatal("NewTLSFingerprinter returned nil")
	}
}

func TestTLSFingerprinter_DetectBrowser_unknown(t *testing.T) {
	fp := NewTLSFingerprinter()
	got := fp.DetectBrowserFromJA4("s12d0000h0_unknown_format")
	if got != "unknown" {
		t.Errorf("DetectBrowserFromJA4(unknown) = %q, want %q", got, "unknown")
	}
}

func TestTLSFingerprinter_DetectBrowser_empty(t *testing.T) {
	fp := NewTLSFingerprinter()
	got := fp.DetectBrowserFromJA4("")
	if got != "unknown" {
		t.Errorf("DetectBrowserFromJA4('') = %q, want %q", got, "unknown")
	}
}

func TestTLSFingerprinter_ValidateFingerprint_match(t *testing.T) {
	fp := NewTLSFingerprinter()
	// Chrome JA4 should validate as chrome
	if !fp.ValidateFingerprint("t13d1516h2_3fcf15715704", "chrome") {
		t.Error("ValidateFingerprint should return true for chrome JA4 and chrome browser")
	}
}

func TestTLSFingerprinter_ValidateFingerprint_mismatch(t *testing.T) {
	fp := NewTLSFingerprinter()
	if fp.ValidateFingerprint("t13d1516h2_3fcf15715704", "firefox") {
		t.Error("ValidateFingerprint should return false for chrome JA4 and firefox browser")
	}
}

func TestTLSFingerprinter_GetBrowserFingerprint_chrome(t *testing.T) {
	fp := NewTLSFingerprinter()
	id, err := fp.GetBrowserFingerprint("chrome")
	if err != nil {
		t.Fatalf("GetBrowserFingerprint(chrome) error: %v", err)
	}
	if id == nil {
		t.Fatal("GetBrowserFingerprint(chrome) returned nil")
	}
}

func TestTLSFingerprinter_GetBrowserFingerprint_firefox(t *testing.T) {
	fp := NewTLSFingerprinter()
	id, err := fp.GetBrowserFingerprint("firefox")
	if err != nil {
		t.Fatalf("GetBrowserFingerprint(firefox) error: %v", err)
	}
	if id == nil {
		t.Fatal("GetBrowserFingerprint(firefox) returned nil")
	}
}

func TestTLSFingerprinter_GetBrowserFingerprint_unknown(t *testing.T) {
	fp := NewTLSFingerprinter()
	id, err := fp.GetBrowserFingerprint("badbrowser")
	if err != nil {
		t.Fatalf("GetBrowserFingerprint(unknown) unexpected error: %v", err)
	}
	if id == nil {
		t.Error("GetBrowserFingerprint(unknown) returned nil (expected Chrome fallback)")
	}
}

func TestCapturedTLSFingerprint_struct(t *testing.T) {
	fp := &CapturedTLSFingerprint{
		JA3:     "md5hash",
		JA3Hash: "hexhash",
		JA4:     "t13d1516h2_abc",
		Version: "TLS 1.3",
		ALPN:    "h2",
		SNI:     "example.com",
		GREASE:  true,
	}
	if fp.Version != "TLS 1.3" {
		t.Errorf("Version = %q", fp.Version)
	}
	if !fp.GREASE {
		t.Error("GREASE should be true")
	}
	if !strings.Contains(fp.JA4, "t13") {
		t.Errorf("JA4 = %q, should start with t13", fp.JA4)
	}
}

func TestTLSAnalysisResult_struct(t *testing.T) {
	result := &TLSAnalysisResult{
		JA4:      "t13d1516h2_abc",
		JA3:      "jastring",
		JA3Hash:  "hashval",
		Browser:  "chrome",
		IsChrome: true,
		Version:  "TLS 1.3",
		ALPN:     "h2",
		SNI:      "example.com",
	}
	if result.Browser != "chrome" {
		t.Errorf("Browser = %q", result.Browser)
	}
	if !result.IsChrome {
		t.Error("IsChrome should be true")
	}
}
