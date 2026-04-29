package spoof

import (
	"context"
	"net"
	"testing"

	"golang.org/x/net/http2"
)

func TestNewH2Transport_ChromeSettings(t *testing.T) {
	settings := []http2.Setting{
		{ID: http2.SettingHeaderTableSize, Val: 65536},
		{ID: http2.SettingEnablePush, Val: 0},
		{ID: http2.SettingMaxConcurrentStreams, Val: 1000},
		{ID: http2.SettingInitialWindowSize, Val: 6291456},
		{ID: http2.SettingMaxHeaderListSize, Val: 262144},
	}
	pseudoHeaders := []string{":method", ":authority", ":scheme", ":path"}

	nopDial := func(_ context.Context, _, _ string) (net.Conn, error) {
		return nil, nil
	}

	h2t := newH2Transport(settings, 6291456, pseudoHeaders, nopDial)

	// Verify settings are stored.
	if len(h2t.H2Settings()) != 5 {
		t.Fatalf("expected 5 settings, got %d", len(h2t.H2Settings()))
	}

	// Verify MaxHeaderListSize was applied to the inner transport.
	if h2t.Inner().MaxHeaderListSize != 262144 {
		t.Errorf("MaxHeaderListSize = %d, want 262144", h2t.Inner().MaxHeaderListSize)
	}

	// Verify StrictMaxConcurrentStreams is enabled.
	if !h2t.Inner().StrictMaxConcurrentStreams {
		t.Error("StrictMaxConcurrentStreams should be true")
	}

	// Verify AllowHTTP is disabled (no h2c).
	if h2t.Inner().AllowHTTP {
		t.Error("AllowHTTP should be false")
	}

	// Verify window size and pseudo headers.
	if h2t.WindowSize() != 6291456 {
		t.Errorf("WindowSize = %d, want 6291456", h2t.WindowSize())
	}
	if len(h2t.PseudoHeaders()) != 4 {
		t.Fatalf("expected 4 pseudo headers, got %d", len(h2t.PseudoHeaders()))
	}
	if h2t.PseudoHeaders()[1] != ":authority" {
		t.Errorf("pseudo header[1] = %q, want :authority", h2t.PseudoHeaders()[1])
	}
}

func TestNewH2Transport_FirefoxSettings(t *testing.T) {
	settings := []http2.Setting{
		{ID: http2.SettingHeaderTableSize, Val: 131072},
		{ID: http2.SettingInitialWindowSize, Val: 131072},
		{ID: http2.SettingMaxFrameSize, Val: 16384},
	}
	pseudoHeaders := []string{":method", ":path", ":authority", ":scheme"}

	nopDial := func(_ context.Context, _, _ string) (net.Conn, error) {
		return nil, nil
	}

	h2t := newH2Transport(settings, 131072, pseudoHeaders, nopDial)

	if len(h2t.H2Settings()) != 3 {
		t.Fatalf("expected 3 settings, got %d", len(h2t.H2Settings()))
	}

	// Firefox signature has no MaxHeaderListSize, so it should be 0 (default).
	if h2t.Inner().MaxHeaderListSize != 0 {
		t.Errorf("MaxHeaderListSize = %d, want 0 (default)", h2t.Inner().MaxHeaderListSize)
	}

	if h2t.WindowSize() != 131072 {
		t.Errorf("WindowSize = %d, want 131072", h2t.WindowSize())
	}

	// Firefox uses :method :path :authority :scheme ordering.
	if h2t.PseudoHeaders()[1] != ":path" {
		t.Errorf("pseudo header[1] = %q, want :path", h2t.PseudoHeaders()[1])
	}
}

func TestSpoofEngine_HasH2ALPN(t *testing.T) {
	e := &SpoofEngine{
		signature: &BrowserSignature{
			TLS: &TLSSignature{
				ALPN: []string{"h2", "http/1.1"},
			},
		},
	}
	if !e.hasH2ALPN() {
		t.Error("expected hasH2ALPN to return true for h2 ALPN")
	}

	e2 := &SpoofEngine{
		signature: &BrowserSignature{
			TLS: &TLSSignature{
				ALPN: []string{"http/1.1"},
			},
		},
	}
	if e2.hasH2ALPN() {
		t.Error("expected hasH2ALPN to return false without h2")
	}

	e3 := &SpoofEngine{
		signature: &BrowserSignature{},
	}
	if e3.hasH2ALPN() {
		t.Error("expected hasH2ALPN to return false with nil TLS")
	}
}

func TestSpoofEngine_BuildH2Settings(t *testing.T) {
	sig := GetChrome116()
	e := &SpoofEngine{signature: sig}

	settings := e.buildH2Settings()
	if len(settings) != 5 {
		t.Fatalf("expected 5 settings, got %d", len(settings))
	}

	// Verify order matches the signature.
	expectedIDs := []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxHeaderListSize,
	}
	for i, expected := range expectedIDs {
		if settings[i].ID != expected {
			t.Errorf("settings[%d].ID = %v, want %v", i, settings[i].ID, expected)
		}
	}
}

func TestSpoofEngine_BuildH2Settings_NilHTTP2(t *testing.T) {
	e := &SpoofEngine{
		signature: &BrowserSignature{},
	}
	settings := e.buildH2Settings()
	if settings != nil {
		t.Errorf("expected nil settings for nil HTTP2 signature, got %v", settings)
	}
}

func TestSpoofEngine_ChromeUsesH2Transport(t *testing.T) {
	engine, err := NewChromeSpoof()
	if err != nil {
		t.Fatalf("NewChromeSpoof: %v", err)
	}

	h2t := unwrapH2Transport(engine.transport)
	if h2t == nil {
		t.Fatal("Chrome engine should use h2RoundTripper, got plain transport")
	}

	// Verify it has the correct settings count.
	if len(h2t.H2Settings()) != 5 {
		t.Errorf("expected 5 h2 settings, got %d", len(h2t.H2Settings()))
	}

	// Verify MaxHeaderListSize is applied.
	if h2t.Inner().MaxHeaderListSize != 262144 {
		t.Errorf("MaxHeaderListSize = %d, want 262144", h2t.Inner().MaxHeaderListSize)
	}
}

func TestSpoofEngine_FirefoxUsesH2Transport(t *testing.T) {
	engine, err := NewFirefoxSpoof()
	if err != nil {
		t.Fatalf("NewFirefoxSpoof: %v", err)
	}

	h2t := unwrapH2Transport(engine.transport)
	if h2t == nil {
		t.Fatal("Firefox engine should use h2RoundTripper, got plain transport")
	}

	// Firefox has 3 settings.
	if len(h2t.H2Settings()) != 3 {
		t.Errorf("expected 3 h2 settings, got %d", len(h2t.H2Settings()))
	}
}

func TestUnwrapH2Transport_PlainTransport(t *testing.T) {
	// A signature without h2 ALPN should not produce an h2RoundTripper.
	sig := GetChrome116()
	sig.TLS.ALPN = []string{"http/1.1"} // Remove h2

	engine, err := NewSpoofEngineFromSignature("no-h2", sig)
	if err != nil {
		t.Fatalf("NewSpoofEngineFromSignature: %v", err)
	}

	h2t := unwrapH2Transport(engine.transport)
	if h2t != nil {
		t.Error("expected nil h2Transport for non-h2 signature")
	}
}

func TestH2Transport_FormatSettings(t *testing.T) {
	settings := []http2.Setting{
		{ID: http2.SettingHeaderTableSize, Val: 65536},
		{ID: http2.SettingMaxHeaderListSize, Val: 262144},
	}

	nopDial := func(_ context.Context, _, _ string) (net.Conn, error) {
		return nil, nil
	}

	h2t := newH2Transport(settings, 6291456, nil, nopDial)
	s := h2t.FormatSettings()

	if s == "" {
		t.Error("FormatSettings should return non-empty string")
	}
	t.Logf("FormatSettings output:\n%s", s)
}
