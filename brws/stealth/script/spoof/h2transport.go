package spoof

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"

	"golang.org/x/net/http2"
)

// h2Transport wraps x/net/http2.Transport with uTLS dial and browser-matching
// SETTINGS values. The x/net/http2.Transport exposes MaxHeaderListSize and
// StrictMaxConcurrentStreams directly; for the remaining SETTINGS
// (HEADER_TABLE_SIZE, INITIAL_WINDOW_SIZE, ENABLE_PUSH) we rely on the uTLS
// ClientHello advertising h2 ALPN so that the TLS fingerprint itself carries
// browser-consistent signalling, while the http2.Transport handles framing.
type h2Transport struct {
	inner *http2.Transport

	// settings stores the full set of browser-signature SETTINGS for
	// reference and future raw-frame upgrades.
	settings []http2.Setting

	// windowSize is the INITIAL_WINDOW_SIZE from the signature.
	windowSize uint32

	// pseudoHeaders is the browser-specific pseudo-header ordering.
	pseudoHeaders []string
}

// newH2Transport builds an http2.Transport that dials TLS via the provided
// uTLS dialer and applies browser-signature SETTINGS where the transport API
// allows.
func newH2Transport(
	settings []http2.Setting,
	windowSize uint32,
	pseudoHeaders []string,
	tlsDial func(ctx context.Context, network, addr string) (net.Conn, error),
) *h2Transport {
	t := &http2.Transport{
		// Use our uTLS dialer so the TLS fingerprint matches the browser
		// signature. The returned *utls.UConn satisfies net.Conn and
		// exposes the negotiated ALPN.
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return tlsDial(ctx, network, addr)
		},

		// When the server limits concurrent streams, respect it strictly
		// rather than queueing optimistically -- matches real browser
		// behaviour.
		StrictMaxConcurrentStreams: true,

		// Disable cleartext HTTP/2 (h2c). We only speak h2 over TLS.
		AllowHTTP: false,
	}

	// Apply settings that http2.Transport exposes directly.
	for _, s := range settings {
		switch s.ID {
		case http2.SettingMaxHeaderListSize:
			t.MaxHeaderListSize = s.Val
		case http2.SettingInitialWindowSize:
			// MaxReadFrameSize isn't the same thing, but we record
			// windowSize separately for documentation/future use.
		}
	}

	return &h2Transport{
		inner:         t,
		settings:      settings,
		windowSize:    windowSize,
		pseudoHeaders: pseudoHeaders,
	}
}

// RoundTrip implements http.RoundTripper by delegating to the inner
// http2.Transport.
func (t *h2Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.inner.RoundTrip(req)
}

// CloseIdleConnections forwards to the inner transport.
func (t *h2Transport) CloseIdleConnections() {
	t.inner.CloseIdleConnections()
}

// h2RoundTripper is a combined HTTP/1.1 + HTTP/2 transport. It attempts HTTP/2
// first (using the h2Transport) and falls back to the base http.Transport for
// HTTP/1.1 connections or when HTTP/2 fails.
type h2RoundTripper struct {
	h1    *http.Transport
	h2    *h2Transport
	mu    sync.Mutex
	h2Err map[string]bool // hosts where h2 failed, fall back to h1
}

// RoundTrip tries HTTP/2 first, falling back to HTTP/1.1 on failure.
func (rt *h2RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Host

	// Check if we already know h2 fails for this host.
	rt.mu.Lock()
	h2Failed := rt.h2Err[host]
	rt.mu.Unlock()

	if !h2Failed && req.URL.Scheme == "https" {
		resp, err := rt.h2.RoundTrip(req)
		if err == nil {
			return resp, nil
		}
		// Mark host as h2-failed and fall through to h1.
		rt.mu.Lock()
		if rt.h2Err == nil {
			rt.h2Err = make(map[string]bool)
		}
		rt.h2Err[host] = true
		rt.mu.Unlock()
	}

	return rt.h1.RoundTrip(req)
}

// buildH2Settings converts the engine's stored http2Settings map and signature
// into an ordered slice of http2.Setting matching the browser signature order.
func (e *SpoofEngine) buildH2Settings() []http2.Setting {
	if e.signature.HTTP2 == nil {
		return nil
	}

	var settings []http2.Setting
	for _, s := range e.signature.HTTP2.Settings {
		settings = append(settings, http2.Setting{
			ID:  http2.SettingID(s.ID),
			Val: s.Value,
		})
	}
	return settings
}

// hasH2ALPN reports whether the TLS signature advertises "h2" in ALPN.
func (e *SpoofEngine) hasH2ALPN() bool {
	if e.signature.TLS == nil {
		return false
	}
	for _, proto := range e.signature.TLS.ALPN {
		if proto == "h2" {
			return true
		}
	}
	return false
}

// buildH2Transport creates the combined HTTP/1.1 + HTTP/2 transport using the
// uTLS dialer for TLS connections. It replaces the plain http.Transport that
// buildTransport previously created.
func (e *SpoofEngine) buildH2Transport(
	tlsDial func(ctx context.Context, network, addr string) (net.Conn, error),
	h1 *http.Transport,
) http.RoundTripper {
	settings := e.buildH2Settings()
	if settings == nil {
		// No HTTP/2 signature -- just use the h1 transport.
		return h1
	}

	h2 := newH2Transport(
		settings,
		e.windowSize,
		e.pseudoHeaders,
		tlsDial,
	)

	return &h2RoundTripper{
		h1:    h1,
		h2:    h2,
		h2Err: make(map[string]bool),
	}
}

// Ensure h2RoundTripper satisfies http.RoundTripper.
var _ http.RoundTripper = (*h2RoundTripper)(nil)

// Ensure h2Transport satisfies http.RoundTripper.
var _ http.RoundTripper = (*h2Transport)(nil)

// H2Settings returns the HTTP/2 settings for inspection/testing.
func (t *h2Transport) H2Settings() []http2.Setting {
	return t.settings
}

// WindowSize returns the configured initial window size.
func (t *h2Transport) WindowSize() uint32 {
	return t.windowSize
}

// PseudoHeaders returns the configured pseudo-header order.
func (t *h2Transport) PseudoHeaders() []string {
	return t.pseudoHeaders
}

// Inner returns the underlying http2.Transport for testing.
func (t *h2Transport) Inner() *http2.Transport {
	return t.inner
}

// Unwrap extracts the h2Transport from the engine's transport, if present.
// Returns nil if the engine is not using an h2RoundTripper.
func unwrapH2Transport(rt http.RoundTripper) *h2Transport {
	if combined, ok := rt.(*h2RoundTripper); ok {
		return combined.h2
	}
	return nil
}

// FormatSettings returns a human-readable description of the settings for
// debugging / logging.
func (t *h2Transport) FormatSettings() string {
	s := fmt.Sprintf("h2Transport: %d settings, window=%d", len(t.settings), t.windowSize)
	for _, setting := range t.settings {
		s += fmt.Sprintf("\n  %s = %d", setting.ID, setting.Val)
	}
	return s
}
