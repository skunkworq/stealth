package tlsfprint

import (
	"testing"
)

func TestRustFingerprint(t *testing.T) {
	fp, err := ConnectAndFingerprint("google.com", 443)
	if err != nil {
		t.Fatalf("ConnectAndFingerprint failed: %v", err)
	}

	t.Logf("TLS Fingerprint (via Rust):")
	t.Logf("  JA4: %s", fp.JA4)
	t.Logf("  TLSVersion: %s", fp.TLSVersion)
	t.Logf("  CipherCount: %d", fp.CipherCount)
	t.Logf("  ExtensionCount: %d", fp.ExtensionCount)
	t.Logf("  HasGREASE: %v", fp.HasGREASE)
	t.Logf("  HasHTTP2: %v", fp.HasHTTP2)
	t.Logf("  ALPN: %s", fp.ALPN)
	t.Logf("  SNI: %s", fp.SNI)
	t.Logf("  JA3Hash: %s", fp.JA3Hash)
	t.Logf("  DetectedBrowser: %s", fp.DetectedBrowser)
	t.Logf("  TraceID: %s", fp.TraceID)
	t.Logf("  Browser (via JA4): %s", DetectBrowserFromJA4(fp.JA4))
}
