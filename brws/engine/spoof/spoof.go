// Package spoof implements browser fingerprint spoofing using uTLS and custom transports
package spoof

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/skunkworq/stealth/brws/constants"
)

// SpoofEngine implements browser fingerprint spoofing
// SpoofEngine provides TLS fingerprint spoofing capabilities.

type SpoofEngine struct {
	name            string
	signature       *BrowserSignature
	clientHelloSpec *utls.ClientHelloSpec
	tlsConfig       *utls.Config
	transport       http.RoundTripper
	dialer          *net.Dialer

	// HTTP/2 specific (when we implement custom transport)
	http2Settings map[uint32]uint32
	pseudoHeaders []string
	windowSize    uint32

	// Header ordering from the browser signature
	headerOrder []string

	// Statistics
	requestsMade int
}

// NewChromeSpoof creates a Chrome 116 spoofing engine
func NewChromeSpoof() (*SpoofEngine, error) {
	return NewSpoofEngine("chrome-116")
}

// NewFirefoxSpoof creates a Firefox 109 spoofing engine
func NewFirefoxSpoof() (*SpoofEngine, error) {
	return NewSpoofEngine("firefox-109")
}

// NewSpoofEngine creates a spoofing engine from a signature key
func NewSpoofEngine(signatureKey string) (*SpoofEngine, error) {
	sigs := LoadDefaultSignatures()

	sig, ok := sigs[signatureKey]
	if !ok {
		return nil, fmt.Errorf("signature not found: %s", signatureKey)
	}

	e := &SpoofEngine{
		name:      signatureKey,
		signature: sig,
		dialer: &net.Dialer{
			Timeout:   constants.DefaultTimeout,
			KeepAlive: constants.KeepAliveTimeout,
		},
	}

	// Build TLS config from signature
	if err := e.buildTLSConfig(); err != nil {
		return nil, fmt.Errorf("building TLS config: %w", err)
	}

	// Build HTTP/2 settings from signature
	e.buildHTTP2Settings()

	// Build header order from signature
	e.headerOrder = headerOrderFromSignature(sig.HTTP)

	// Build transport
	if err := e.buildTransport(); err != nil {
		return nil, fmt.Errorf("building transport: %w", err)
	}

	return e, nil
}

// NewSpoofEngineFromSignature creates a spoofing engine using a complete dynamic signature
func NewSpoofEngineFromSignature(name string, sig *BrowserSignature) (*SpoofEngine, error) {
	if sig == nil {
		return nil, fmt.Errorf("signature cannot be nil")
	}

	e := &SpoofEngine{
		name:      name,
		signature: sig,
		dialer: &net.Dialer{
			Timeout:   constants.DefaultTimeout,
			KeepAlive: constants.KeepAliveTimeout,
		},
	}

	if err := e.buildTLSConfig(); err != nil {
		return nil, fmt.Errorf("building TLS config: %w", err)
	}

	e.buildHTTP2Settings()

	// Build header order from signature
	e.headerOrder = headerOrderFromSignature(sig.HTTP)

	if err := e.buildTransport(); err != nil {
		return nil, fmt.Errorf("building transport: %w", err)
	}

	return e, nil
}

// buildTLSConfig creates uTLS config from signature
func (e *SpoofEngine) buildTLSConfig() error {
	if e.signature.TLS == nil {
		return fmt.Errorf("no TLS signature available")
	}

	tlsSig := e.signature.TLS

	// Build cipher suites

	var cipherSuites []uint16
	for _, c := range tlsSig.CipherSuites {
		if !c.IsGREASE {
			cipherSuites = append(cipherSuites, c.Value)
		}
	}

	// Build ClientHello spec

	var extensions []utls.TLSExtension
	seenExtensions := make(map[uint16]bool)

	for _, ext := range tlsSig.Extensions {
		if ext.IsGREASE {
			// Generate random GREASE value
			greaseVal := getGREASEValue(ext.Type)
			extensions = append(extensions, &utls.GenericExtension{Id: greaseVal})
			continue
		}

		if ext.Type == 0x002b {
			if seenExtensions[ext.Type] {
				continue // Prevent utls crashing on duplicate SupportedVersions (0x002b)
			}
			seenExtensions[ext.Type] = true
		}

		switch ext.Type {
		case 0x0000: // server_name
			// Will be set per-request
			extensions = append(extensions, &utls.SNIExtension{})

		case 0x0005: // status_request (OCSP stapling)
			extensions = append(extensions, &utls.StatusRequestExtension{})

		case 0x000a: // supported_groups
			var groups []utls.CurveID
			for _, g := range tlsSig.SupportedGroups {
				if !isGREASEValue(g) {
					groups = append(groups, utls.CurveID(g))
				}
			}
			extensions = append(extensions, &utls.SupportedCurvesExtension{Curves: groups})

		case 0x000b: // ec_point_formats
			extensions = append(extensions, &utls.SupportedPointsExtension{SupportedPoints: []byte{0}})

		case 0x000d: // signature_algorithms
			// Will use defaults

		case 0x0010: // ALPN
			extensions = append(extensions, &utls.ALPNExtension{
				AlpnProtocols: tlsSig.ALPN,
			})

		case 0x0011: // ALPS (Chrome-specific)
			// uTLS doesn't support ALPS natively, use generic
			extensions = append(extensions, &utls.GenericExtension{
				Id:   0x0011,
				Data: []byte{0x00, 0x03, 0x02, 0x68, 0x32}, // h2
			})

		case 0x0012: // signed_certificate_timestamp
			extensions = append(extensions, &utls.SCTExtension{})

		case 0x0015: // padding
			// We skip padding manually here because uTLS often panics or corrupts
			// the rest of the extensions list when padding local addresses with
			// variable length Host headers in Go's native client.
			continue

		case 0x0017: // extended_master_secret
			extensions = append(extensions, &utls.GenericExtension{Id: 0x0017})

		case 0x001b: // compress_certificate
			if len(tlsSig.CertCompression) > 0 {
				algos := []utls.CertCompressionAlgo{}
				for _, algo := range tlsSig.CertCompression {
					switch algo {
					case "zlib":
						algos = append(algos, utls.CertCompressionZlib)
					case "brotli":
						algos = append(algos, utls.CertCompressionBrotli)
					case "zstd":
						algos = append(algos, utls.CertCompressionZstd)
					}
				}
				extensions = append(extensions, &utls.UtlsCompressCertExtension{Algorithms: algos})
			}

		case 0x0023: // session_ticket
			extensions = append(extensions, &utls.SessionTicketExtension{})

		case 0x002b: // supported_versions
			extensions = append(extensions, &utls.SupportedVersionsExtension{
				Versions: []uint16{
					utls.VersionTLS13,
					utls.VersionTLS12,
				},
			})

		case 0x002d: // psk_key_exchange_modes
			extensions = append(extensions, &utls.PSKKeyExchangeModesExtension{
				Modes: []uint8{1}, // PSK with (EC)DHE key establishment
			})

		case 0x0033: // key_share
			var keyShares []utls.KeyShare
			for _, g := range tlsSig.KeyShareGroups {
				if !isGREASEValue(g) {
					switch g {
					case 0x001d: // X25519
						keyShares = append(keyShares, utls.KeyShare{Group: utls.X25519})
					case 0x0017: // P-256
						keyShares = append(keyShares, utls.KeyShare{Group: utls.CurveP256})
					case 0x0018: // P-384
						keyShares = append(keyShares, utls.KeyShare{Group: utls.CurveP384})
					}
				}
			}
			extensions = append(extensions, &utls.KeyShareExtension{KeyShares: keyShares})

		case 0xff01: // renegotiation_info
			extensions = append(extensions, &utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient})
		}
	}

	// Build spec
	spec := &utls.ClientHelloSpec{
		CipherSuites:       cipherSuites,
		CompressionMethods: []byte{0},
		Extensions:         extensions,
	}

	e.clientHelloSpec = spec

	// Build TLS config
	e.tlsConfig = &utls.Config{
		InsecureSkipVerify: true, // Allow local lab evaluation tests
		CipherSuites:       cipherSuites,
		NextProtos:         tlsSig.ALPN,
	}

	return nil
}

// buildHTTP2Settings extracts HTTP/2 settings from signature
func (e *SpoofEngine) buildHTTP2Settings() {
	if e.signature.HTTP2 == nil {
		return
	}

	h2 := e.signature.HTTP2

	// Store settings
	e.http2Settings = make(map[uint32]uint32)
	for _, s := range h2.Settings {
		e.http2Settings[uint32(s.ID)] = s.Value
	}

	// Pseudo-header order
	e.pseudoHeaders = h2.PseudoHeaders

	// Window size
	e.windowSize = h2.InitialWindowSize
}

// buildTransport creates HTTP transport with HTTP/2 support when the browser
// signature advertises h2 in its ALPN list.
func (e *SpoofEngine) buildTransport() error {
	// Create custom TLS dialer using uTLS for fingerprint spoofing.
	tlsDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		plainConn, err := e.dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, fmt.Errorf("dialing: %w", err)
		}

		// Get server name from addr
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}

		// Clone TLS config with server name
		config := e.tlsConfig.Clone()
		config.ServerName = host

		// Create uTLS connection
		uconn := utls.UClient(plainConn, config, utls.HelloCustom)
		if err := uconn.ApplyPreset(e.clientHelloSpec); err != nil {
			_ = plainConn.Close()
			return nil, fmt.Errorf("applying TLS spec: %w", err)
		}

		// Handshake
		if err := uconn.HandshakeContext(ctx); err != nil {
			_ = plainConn.Close()
			return nil, fmt.Errorf("TLS handshake: %w", err)
		}

		return uconn, nil
	}

	// HTTP/1.1 base transport -- used as fallback and for non-TLS requests.
	// ForceAttemptHTTP2 is false because we handle HTTP/2 ourselves via the
	// h2Transport wrapper when the signature includes h2 ALPN.
	h1 := &http.Transport{
		DialContext:           e.dialer.DialContext,
		DialTLSContext:        tlsDial,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// When the signature advertises h2, build a combined transport that
	// attempts HTTP/2 with browser-matching SETTINGS and falls back to h1.
	if e.hasH2ALPN() && e.signature.HTTP2 != nil {
		e.transport = e.buildH2Transport(tlsDial, h1)
	} else {
		e.transport = h1
	}

	return nil
}

// Do executes an HTTP request with spoofed fingerprint
func (e *SpoofEngine) Do(req *http.Request) (*http.Response, error) {
	e.requestsMade++

	// Apply HTTP signature headers
	if e.signature.HTTP != nil {
		for _, h := range e.signature.HTTP.Headers {
			if h.Required {
				value := h.Value
				// Special handling for dynamic values
				switch h.Name {
				case ":method":
					continue // Method is set by request
				case ":authority":
					continue // Set by HTTP/2
				case ":scheme":
					continue // Set by HTTP/2
				case ":path":
					continue // Path is set by request
				}

				if req.Header.Get(h.Name) == "" {
					req.Header.Set(h.Name, value)
				}
			}
		}
	}

	// Apply header ordering from the browser signature
	e.applyHeaderOrder(req)

	// Execute request
	return e.transport.RoundTrip(req)
}

// applyHeaderOrder reorders the request headers to match the browser signature.
func (e *SpoofEngine) applyHeaderOrder(req *http.Request) {
	if len(e.headerOrder) == 0 {
		return
	}

	oh := NewOrderedHeaders(e.headerOrder)

	// First pass: add headers in signature order
	for _, name := range oh.order {
		if vals, ok := req.Header[name]; ok {
			for _, v := range vals {
				oh.Add(name, v)
			}
		}
	}

	// Second pass: add any remaining headers not in the signature order
	for key, vals := range req.Header {
		canonical := http.CanonicalHeaderKey(key)
		if oh.hasKey(canonical) {
			continue
		}
		for _, v := range vals {
			oh.Add(canonical, v)
		}
	}

	oh.ApplyTo(req)
}

// Fetch performs a GET request with the spoofed fingerprint
func (e *SpoofEngine) Fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := e.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}

	return body, nil
}

// Name returns the engine name
func (e *SpoofEngine) Name() string {
	return e.name
}

// Stats returns engine statistics
func (e *SpoofEngine) Stats() map[string]interface{} {
	return map[string]interface{}{
		"requests_made": e.requestsMade,
		"signature":     e.signature.Description,
		"tls_version":   e.signature.TLS.Version,
	}
}

// Helper functions

func getGREASEValue(seed uint16) uint16 {
	// GREASE values are 0x0A0A, 0x1A1A, 0x2A2A, ..., 0xFAFA
	// Return a valid GREASE value based on seed
	if isGREASEValue(seed) {
		return seed
	}
	// Default GREASE
	return 0x5a5a
}

func isGREASEValue(val uint16) bool {
	return (val&0x0F0F) == 0x0A0A && ((val>>4)&0x0F) == ((val>>12)&0x0F)
}

// Engine interface compliance
type Engine interface {
	Fetch(ctx context.Context, url string) ([]byte, error)
	Name() string
}

// Ensure SpoofEngine implements Engine
var _ Engine = (*SpoofEngine)(nil)
