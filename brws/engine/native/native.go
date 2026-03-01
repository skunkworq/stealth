// Package native implements the Engine interface using Go's standard net/http.
// This engine provides excellent performance and stability but is explicitly
// NOT byte-identical to browser TLS/HTTP2 behavior.
package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"time"

	"github.com/google/uuid"
	utls "github.com/refraction-networking/utls"
	"github.com/stealth/brwslab/brws/constants"
	"github.com/stealth/brwslab/brws/engine"
	"github.com/stealth/brwslab/brws/engine/profiles"
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
	// NOTE: TLS spoofing is experimental - may have issues with some servers
	if opts.StealthTLS {
		// Use standard TLS for now - TLS spoofing needs more work
		transport.TLSClientConfig = &tls.Config{
			//nolint:gosec // InsecureSkipVerify required for stealth TLS testing
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
			MinVersion:         tls.VersionTLS12,
		}
		// TODO: Fix uTLS integration for production use
		// client.Transport = &uTLSRoundTripper{
		// 	base:        transport,
		// 	fingerprint: profile.TLSFingerprint,
		// }
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
		timeout = 30 * time.Second
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
		// Use uTLS wrapper around the transport
		client.Transport = &uTLSRoundTripper{
			base:        transport,
			fingerprint: profile.TLSFingerprint,
		}
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

	// Read body
	body, err := io.ReadAll(httpResp.Body)
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
			Headers:  flattenHeaders(httpReq.Header), // Capture actual headers sent (includes stealth headers)
			BodySize: int64(len(req.Body)),
		},
		Response: engine.TraceResponse{
			Headers:  flattenHeaders(headers),
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

func flattenHeaders(headers map[string][]string) map[string]string {
	result := make(map[string]string)
	for key, values := range headers {
		if len(values) > 0 {
			result[key] = values[0]
		}
	}
	return result
}

// uTLSRoundTripper wraps http.Transport to use uTLS for TLS fingerprint spoofing.
type uTLSRoundTripper struct {
	base        http.RoundTripper
	fingerprint utls.ClientHelloID
}

// RoundTrip implements http.RoundTripper, upgrading TLS to use uTLS fingerprint.
func (u *uTLSRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// For non-HTTPS requests, pass through to base transport
	if req.URL.Scheme != "https" {
		return u.base.RoundTrip(req)
	}

	// Get the underlying transport
	transport, ok := u.base.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("uTLS round tripper requires *http.Transport")
	}

	// Store original dial context and TLS config
	originalDialContext := transport.DialContext
	originalTLSConfig := transport.TLSClientConfig

	// Clear TLSClientConfig so transport doesn't try to do TLS
	transport.TLSClientConfig = nil

	// Create dial function that upgrades to uTLS
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
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
			ServerName:         host,
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

	// Make request
	resp, err := transport.RoundTrip(req)

	// Restore original settings
	transport.DialContext = originalDialContext
	transport.TLSClientConfig = originalTLSConfig

	return resp, err
}
