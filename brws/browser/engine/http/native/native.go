// Package native implements the Engine interface using Go's standard net/http.
// This engine provides excellent performance and stability but is explicitly
// NOT byte-identical to browser TLS/HTTP2 behavior.
package native

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/google/uuid"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"

	"github.com/skunkworq/stealth/brws/core/constants"
	"github.com/skunkworq/stealth/brws/browser/engine"
	"github.com/skunkworq/stealth/brws/browser/engine/profile"
)

func init() {
	engine.Register("native", New)
}

// Native implements the Engine interface using Go's net/http.
type Native struct {
	client        *http.Client
	trace         *engine.Trace
	stealth       bool
	stealthTLS    bool
	profile       *profiles.Profile
	customHeaders map[string]string
}

// New creates a new native Go HTTP engine.
func New(opts engine.Options) (engine.Engine, error) {
	transport := &http.Transport{
		ForceAttemptHTTP2: opts.HTTP2,
		DisableKeepAlives: false,
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
	}
	if !opts.IPv6 {
		transport.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
			return (&net.Dialer{
				Timeout:   constants.DefaultTimeout,
				KeepAlive: constants.KeepAliveTimeout,
			}).DialContext(ctx, "tcp4", addr)
		}
	}

	// Use uTLS for TLS fingerprint spoofing when StealthTLS is enabled
	if opts.StealthTLS {
		transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			plainConn, err := (&net.Dialer{
				Timeout:   constants.DefaultTimeout,
				KeepAlive: constants.KeepAliveTimeout,
			}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}

			// Parse ServerName from address string
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}

			config := &utls.Config{ServerName: host, InsecureSkipVerify: true}
			uconn := utls.UClient(plainConn, config, utls.HelloChrome_Auto)

			if err := uconn.HandshakeContext(ctx); err != nil {
				plainConn.Close()
				return nil, fmt.Errorf("StealthTLS uTLS Handshake failed: %w", err)
			}

			return uconn, nil
		}
	} else {
		transport.TLSClientConfig = tlsConfig
	}

	// Configure proxy
	if opts.Proxy != "" {
		proxyParsed, err := url.Parse(opts.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyParsed)
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = constants.DefaultTimeout
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	client.Transport = transport

	// Get browser profile
	profileName := opts.ProfileName
	if profileName == "" {
		profileName = "chrome-120-macos" // Default
	}
	profile := profiles.GetByName(profileName)

	// Update TLS fingerprint based on profile
	if opts.StealthTLS {
		client.Transport = newUTLSRoundTripper(profile.TLSFingerprint)
	}

	// Store custom headers
	customHeaders := opts.CustomHeaders
	if customHeaders == nil {
		customHeaders = make(map[string]string)
	}

	return &Native{
		client:        client,
		stealth:       opts.Stealth || opts.StealthTLS,
		stealthTLS:    opts.StealthTLS,
		profile:       profile,
		customHeaders: customHeaders,
	}, nil
}

// Name returns the engine identifier.
func (n *Native) Name() string {
	return "native"
}

// Capabilities returns what this engine supports.
func (n *Native) Capabilities() engine.Capabilities {
	return engine.Capabilities{
		JavaScript:        false,
		HTTP2:             true,
		HTTP3:             false, // Could use quic-go for this
		PersistentProfile: false,
		NetLogExport:      false,
		WebSocket:         true,
		Intercept:         false,
	}
}

// Do executes a request and returns a response.
func (n *Native) Do(ctx context.Context, req *engine.Request) (*engine.Response, error) {
	requestID := uuid.New().String()
	n.trace = &engine.Trace{
		Engine:    n.Name(),
		RequestID: requestID,
		Entries:   []engine.TraceEntry{},
	}

	// Build http.Request
	bodyReader := bytes.NewReader(req.Body)
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Set headers
	for key, values := range req.Headers {
		for _, value := range values {
			httpReq.Header.Add(key, value)
		}
	}

	// Apply stealth headers if enabled and no ExtraHeaders provided
	if n.stealth && len(req.ExtraHeaders) == 0 {
		// Get profile headers
		profileHeaders := n.profile.ToHeaders()

		// Apply custom headers first (they can override profile)
		for key, value := range n.customHeaders {
			profileHeaders[key] = value
		}

		// Apply all headers
		for key, value := range profileHeaders {
			httpReq.Header.Set(key, value)
		}
	}

	// Set extra headers (user-provided overrides)
	for key, value := range req.ExtraHeaders {
		httpReq.Header.Set(key, value)
	}

	// Trace timing
	var timing engine.TimingInfo
	var start, connectStart, tlsStart time.Time

	trace := &httptrace.ClientTrace{
		GetConn: func(_ string) {
			start = time.Now()
		},
		DNSStart: func(_ httptrace.DNSStartInfo) {
			timing.Blocked = time.Since(start)
		},
		DNSDone: func(_ httptrace.DNSDoneInfo) {
			timing.DNS = time.Since(start) - timing.Blocked
		},
		ConnectStart: func(_, _ string) {
			connectStart = time.Now()
		},
		ConnectDone: func(_, _ string, _ error) {
			timing.Connect = time.Since(connectStart)
		},
		TLSHandshakeStart: func() {
			tlsStart = time.Now()
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			timing.SSL = time.Since(tlsStart)
		},
		GotFirstResponseByte: func() {
			timing.Wait = time.Since(start) - timing.Blocked - timing.DNS - timing.Connect - timing.SSL
		},
	}

	httpReq = httpReq.WithContext(httptrace.WithClientTrace(ctx, trace))

	// Execute request
	httpResp, err := n.client.Do(httpReq) //nolint:gosec // Native engine makes requests by design
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	// Read and decompress body if needed.
	// When stealth headers set Accept-Encoding explicitly, Go's transport
	// won't auto-decompress, so we handle it ourselves.
	body, err := readAndDecompress(httpResp)
	if err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}

	timing.Receive = time.Since(start) - timing.Blocked - timing.DNS - timing.Connect - timing.SSL - timing.Wait
	timing.Total = time.Since(start)

	// Convert headers
	headers := make(map[string][]string)
	for key, values := range httpResp.Header {
		headers[key] = values
	}

	// Determine protocol
	protocol := "http/1.1"
	if httpResp.ProtoMajor == 2 {
		protocol = "h2"
	}

	// Build trace entry
	entry := engine.TraceEntry{
		RequestID:   requestID,
		URL:         req.URL,
		Method:      req.Method,
		Status:      httpResp.StatusCode,
		Protocol:    protocol,
		RequestTime: start,
		Timing:      timing,
		Request: engine.TraceRequest{
			Headers:  engine.FlattenHeaders(httpReq.Header),
			BodySize: int64(len(req.Body)),
		},
		Response: engine.TraceResponse{
			Headers:  engine.FlattenHeaders(headers),
			BodySize: int64(len(body)),
			MimeType: httpResp.Header.Get("Content-Type"),
		},
	}
	n.trace.Entries = append(n.trace.Entries, entry)

	return &engine.Response{
		Status:     httpResp.StatusCode,
		StatusText: httpResp.Status,
		Headers:    headers,
		Body:       body,
		FinalURL:   httpResp.Request.URL.String(),
		Protocol:   protocol,
		Trace:      *n.trace,
		Timing:     timing,
	}, nil
}

// Close cleans up resources.
func (n *Native) Close() error {
	n.client.CloseIdleConnections()
	return nil
}

// readAndDecompress reads the response body, decompressing if Content-Encoding
// is set. When stealth headers explicitly set Accept-Encoding, Go's transport
// won't auto-decompress, so we handle gzip/deflate/br ourselves.
func readAndDecompress(resp *http.Response) ([]byte, error) {
	encoding := strings.ToLower(resp.Header.Get("Content-Encoding"))
	var reader io.Reader = resp.Body

	switch encoding {
	case "gzip":
		gr, err := gzip.NewReader(resp.Body)
		if err != nil {
			// If gzip fails, fall back to raw read
			return io.ReadAll(resp.Body)
		}
		defer gr.Close()
		reader = gr
	case "deflate":
		reader = flate.NewReader(resp.Body)
	case "br":
		reader = brotli.NewReader(resp.Body)
	}

	return io.ReadAll(reader)
}


// h2Profile holds browser-specific HTTP/2 settings for the transport layer.
type h2Profile struct {
	maxHeaderListSize         uint32
	maxDecoderHeaderTableSize uint32
	maxReadFrameSize          uint32
	// initialWindowSize is the INITIAL_WINDOW_SIZE to advertise in SETTINGS.
	// Go's http2.Transport hardcodes this to 4MB; to override, we inject
	// custom SETTINGS via a connection wrapper (see settingsInterceptConn).
	initialWindowSize uint32
	// connWindowSize is the connection-level window advertised via WINDOW_UPDATE(stream=0).
	// Chrome: 6225920, Firefox: 12451842, Go default: 1<<30 (~1GB).
	connWindowSize uint32
}

// chromeH2Profile returns HTTP/2 settings matching Chrome 120.
func chromeH2Profile() h2Profile {
	return h2Profile{
		maxHeaderListSize:         262144,  // Chrome: 262144
		maxDecoderHeaderTableSize: 65536,   // Chrome: 65536
		maxReadFrameSize:          16384,   // Chrome: 16384
		initialWindowSize:         6291456, // Chrome: 6MB
		connWindowSize:            6291456, // Chrome: 6MB
	}
}

// firefoxH2Profile returns HTTP/2 settings matching Firefox 120.
func firefoxH2Profile() h2Profile {
	return h2Profile{
		maxHeaderListSize:         0,        // Firefox: not sent
		maxDecoderHeaderTableSize: 131072,   // Firefox: 131072
		maxReadFrameSize:          16384,    // Firefox: 16384
		initialWindowSize:         131072,   // Firefox: 128KB
		connWindowSize:            12517377, // Firefox: ~12MB
	}
}

// h2ProfileForFingerprint returns the HTTP/2 profile matching a uTLS fingerprint.
func h2ProfileForFingerprint(fp utls.ClientHelloID) h2Profile {
	switch {
	case strings.Contains(fp.Client, "Firefox"):
		return firefoxH2Profile()
	default:
		return chromeH2Profile()
	}
}

// uTLSRoundTripper wraps http.Transport to use uTLS for TLS fingerprint spoofing.
// It handles HTTP/2 properly by checking the ALPN-negotiated protocol after
// the uTLS handshake and routing to the appropriate transport.
type uTLSRoundTripper struct {
	fingerprint utls.ClientHelloID
	h2prof      h2Profile

	// h1 transport for HTTP/1.1 connections
	h1 *http.Transport
	// h2 transport for HTTP/2 connections (lazy-initialized)
	h2   *http2.Transport
	h2mu sync.Mutex
}

// newUTLSRoundTripper creates a new uTLSRoundTripper.
func newUTLSRoundTripper(fingerprint utls.ClientHelloID) *uTLSRoundTripper {
	rt := &uTLSRoundTripper{
		fingerprint: fingerprint,
		h2prof:      h2ProfileForFingerprint(fingerprint),
	}

	// HTTP/1.1 transport with uTLS dial
	rt.h1 = &http.Transport{
		ForceAttemptHTTP2: false, // We handle h2 ourselves
		DialTLSContext:    rt.dialTLS,
	}

	return rt
}

// dialTLS performs a uTLS handshake and returns the connection.
func (u *uTLSRoundTripper) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	// Dial TCP connection
	conn, err := (&net.Dialer{
		Timeout:   constants.DefaultTimeout,
		KeepAlive: constants.KeepAliveTimeout,
	}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	// Extract host from address
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	// Create uTLS connection with spoofed fingerprint
	tlsConn := utls.UClient(conn, &utls.Config{
		ServerName: host,
		//nolint:gosec // InsecureSkipVerify required for stealth TLS testing
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}, u.fingerprint)

	// Perform TLS handshake
	if err := tlsConn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	return tlsConn, nil
}

// getH2Transport returns the HTTP/2 transport, creating it lazily.
// Uses browser-specific HTTP/2 SETTINGS derived from the TLS fingerprint profile
// to avoid detection by CF which compares HTTP/2 frame values against the
// User-Agent's expected behavior.
func (u *uTLSRoundTripper) getH2Transport() *http2.Transport {
	u.h2mu.Lock()
	defer u.h2mu.Unlock()
	if u.h2 == nil {
		prof := u.h2prof
		u.h2 = &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return u.dialTLS(ctx, network, addr)
			},
			// Browser-specific HTTP/2 SETTINGS to match the TLS fingerprint profile.
			// CF fingerprints HTTP/2 SETTINGS frames and compares them against the
			// claimed User-Agent. These 3 fields map to SETTINGS frame values:
			//   MaxHeaderListSize         → SETTINGS_MAX_HEADER_LIST_SIZE
			//   MaxDecoderHeaderTableSize → SETTINGS_HEADER_TABLE_SIZE
			//   MaxReadFrameSize          → SETTINGS_MAX_FRAME_SIZE
			// Note: SETTINGS_INITIAL_WINDOW_SIZE and SETTINGS_MAX_CONCURRENT_STREAMS
			// are controlled by Go's http2 internals and cannot be overridden here.
			// For full HTTP/2 fingerprint control, use CustomHTTP2Transport from spoof/.
			MaxHeaderListSize:         prof.maxHeaderListSize,
			MaxDecoderHeaderTableSize: prof.maxDecoderHeaderTableSize,
			MaxReadFrameSize:          prof.maxReadFrameSize,
		}
	}
	return u.h2
}

// RoundTrip implements http.RoundTripper, routing through uTLS.
// For HTTPS requests, it first tries HTTP/2 (since CF servers support h2).
// If the server doesn't support h2, it falls back to HTTP/1.1.
func (u *uTLSRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		return u.h1.RoundTrip(req)
	}

	// Try HTTP/2 first (most CF-protected sites support it)
	resp, err := u.getH2Transport().RoundTrip(req)
	if err != nil {
		// Fall back to HTTP/1.1 if h2 fails
		return u.h1.RoundTrip(req)
	}
	return resp, nil
}
