package adversarial

import (
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
