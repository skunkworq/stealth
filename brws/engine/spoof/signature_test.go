package spoof

import (
	"testing"
)

func TestSignature_Firefox128_NoClientHints(t *testing.T) {
	sig := GetFirefox128()

	if sig.HTTP.ClientHints != nil {
		t.Fatal("Firefox 128 should not have client hints")
	}

	// Also verify no sec-ch-ua headers in the header list
	for _, h := range sig.HTTP.Headers {
		if h.Name == "sec-ch-ua" || h.Name == "sec-ch-ua-mobile" || h.Name == "sec-ch-ua-platform" {
			t.Fatalf("Firefox 128 should not have client hint header %q", h.Name)
		}
	}
}

func TestSignature_Firefox128_PseudoHeaderOrder(t *testing.T) {
	sig := GetFirefox128()

	expected := []string{":method", ":path", ":authority", ":scheme"}

	if len(sig.HTTP2.PseudoHeaders) != len(expected) {
		t.Fatalf("expected %d pseudo-headers, got %d", len(expected), len(sig.HTTP2.PseudoHeaders))
	}

	for i, h := range expected {
		if sig.HTTP2.PseudoHeaders[i] != h {
			t.Errorf("pseudo-header[%d]: expected %q, got %q", i, h, sig.HTTP2.PseudoHeaders[i])
		}
	}
}

func TestSignature_Edge122_ChromiumBased(t *testing.T) {
	edge := GetEdge122()
	chrome := GetChrome116()

	// TLS cipher suites should match Chrome (Chromium-based)
	if len(edge.TLS.CipherSuites) != len(chrome.TLS.CipherSuites) {
		t.Fatalf("Edge TLS cipher suite count (%d) should match Chrome (%d)",
			len(edge.TLS.CipherSuites), len(chrome.TLS.CipherSuites))
	}

	for i, cs := range edge.TLS.CipherSuites {
		if cs.Value != chrome.TLS.CipherSuites[i].Value {
			t.Errorf("cipher suite[%d]: Edge 0x%04x != Chrome 0x%04x", i, cs.Value, chrome.TLS.CipherSuites[i].Value)
		}
	}

	// HTTP/2 settings should match Chrome
	if edge.HTTP2.InitialWindowSize != chrome.HTTP2.InitialWindowSize {
		t.Errorf("Edge HTTP2 window size (%d) should match Chrome (%d)",
			edge.HTTP2.InitialWindowSize, chrome.HTTP2.InitialWindowSize)
	}

	// But user-agent should differ
	if edge.HTTP.UserAgent == chrome.HTTP.UserAgent {
		t.Error("Edge user-agent should differ from Chrome")
	}

	// Edge should have Edg/ in user-agent
	found := false
	for _, h := range edge.HTTP.Headers {
		if h.Name == "user-agent" {
			if h.Value != edge.HTTP.UserAgent {
				t.Errorf("user-agent header mismatch")
			}
			found = true
		}
	}
	if !found {
		t.Error("Edge should have user-agent header")
	}

	// Edge client hints should mention "Microsoft Edge"
	if edge.HTTP.ClientHints == nil {
		t.Fatal("Edge should have client hints")
	}
	if edge.HTTP.ClientHints.SecCHUA != `"Chromium";v="122", "Microsoft Edge";v="122", "Not(A:Brand";v="24"` {
		t.Errorf("Edge sec-ch-ua mismatch: %s", edge.HTTP.ClientHints.SecCHUA)
	}
}

func TestSignature_Safari17_UniqueHTTP2(t *testing.T) {
	safari := GetSafari17()

	// Safari uses 2MB initial window size (vs Chrome's 6MB)
	if safari.HTTP2.InitialWindowSize != 2097152 {
		t.Errorf("Safari initial window size: expected 2097152 (2MB), got %d", safari.HTTP2.InitialWindowSize)
	}

	// Verify SETTINGS entries contain correct values
	foundWindowSize := false
	for _, s := range safari.HTTP2.Settings {
		if s.ID == 4 { // INITIAL_WINDOW_SIZE
			if s.Value != 2097152 {
				t.Errorf("Safari INITIAL_WINDOW_SIZE setting: expected 2097152, got %d", s.Value)
			}
			foundWindowSize = true
		}
	}
	if !foundWindowSize {
		t.Error("Safari should have INITIAL_WINDOW_SIZE in settings")
	}

	// Verify Safari pseudo-header order: :method, :scheme, :path, :authority
	expected := []string{":method", ":scheme", ":path", ":authority"}
	if len(safari.HTTP2.PseudoHeaders) != len(expected) {
		t.Fatalf("expected %d pseudo-headers, got %d", len(expected), len(safari.HTTP2.PseudoHeaders))
	}
	for i, h := range expected {
		if safari.HTTP2.PseudoHeaders[i] != h {
			t.Errorf("pseudo-header[%d]: expected %q, got %q", i, h, safari.HTTP2.PseudoHeaders[i])
		}
	}
}

func TestSignature_Safari17_NoCertCompression(t *testing.T) {
	safari := GetSafari17()

	if safari.TLS.CertCompression != nil {
		t.Errorf("Safari should not have cert compression, got %v", safari.TLS.CertCompression)
	}

	if safari.TLS.ALPS != "" {
		t.Errorf("Safari should not have ALPS, got %q", safari.TLS.ALPS)
	}

	// No client hints for Safari
	if safari.HTTP.ClientHints != nil {
		t.Error("Safari should not have client hints")
	}
}

func TestAllSignatures_Valid(t *testing.T) {
	sigs := LoadDefaultSignatures()

	expectedKeys := []string{"chrome-116", "chrome-146", "firefox-109", "firefox-128", "edge-122", "safari-17"}

	for _, key := range expectedKeys {
		sig, ok := sigs[key]
		if !ok {
			t.Errorf("missing signature: %s", key)
			continue
		}

		// Every signature must have TLS, HTTP2, and HTTP sections
		if sig.TLS == nil {
			t.Errorf("%s: missing TLS section", key)
		}
		if sig.HTTP2 == nil {
			t.Errorf("%s: missing HTTP2 section", key)
		}
		if sig.HTTP == nil {
			t.Errorf("%s: missing HTTP section", key)
		}

		// TLS must have cipher suites and ALPN
		if sig.TLS != nil {
			if len(sig.TLS.CipherSuites) == 0 {
				t.Errorf("%s: TLS has no cipher suites", key)
			}
			if len(sig.TLS.ALPN) == 0 {
				t.Errorf("%s: TLS has no ALPN", key)
			}
		}

		// HTTP2 must have settings and pseudo-headers
		if sig.HTTP2 != nil {
			if len(sig.HTTP2.Settings) == 0 {
				t.Errorf("%s: HTTP2 has no settings", key)
			}
			if len(sig.HTTP2.PseudoHeaders) == 0 {
				t.Errorf("%s: HTTP2 has no pseudo-headers", key)
			}
		}

		// HTTP must have user-agent and accept
		if sig.HTTP != nil {
			if sig.HTTP.UserAgent == "" {
				t.Errorf("%s: HTTP has no user-agent", key)
			}
			if sig.HTTP.Accept == "" {
				t.Errorf("%s: HTTP has no accept", key)
			}
		}
	}

	// Verify we have exactly the expected number
	if len(sigs) != len(expectedKeys) {
		t.Errorf("expected %d signatures, got %d", len(expectedKeys), len(sigs))
	}
}
