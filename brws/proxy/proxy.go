// Package proxy provides a MITM TLS/HTTP proxy for fingerprint capture
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/stealth/brwslab/brws/constants"
	"github.com/stealth/brwslab/brws/tlsparser"
	"github.com/stealth/brwslab/brws/types"
)

// Proxy is a MITM TLS/HTTP proxy for capturing fingerprints
type Proxy struct {
	config   *ProxyConfig
	logger   *slog.Logger
	listener net.Listener

	// Certificate management
	certManager *CertificateManager

	// Capture callbacks
	onClientHello func(*tlsparser.ClientHello, *types.CompleteFingerprint)
	onHTTPRequest func(*types.HTTPFingerprint)
	onCaptured    func(*types.CompleteFingerprint)

	// Active connections
	mu          sync.RWMutex
	connections map[string]*capturedConn

	// Context for shutdown
	ctx    context.Context
	cancel context.CancelFunc
}

// ProxyConfig configures the proxy
type ProxyConfig struct {
	ListenAddr      string // Proxy listen address (e.g., ":8081")
	HTTPPort        int    // HTTP port for the lab (for PAC file)
	HTTPSPort       int    // HTTPS port for the lab
	CACertFile      string // CA certificate for signing
	CAKeyFile       string // CA private key
	EnableMITM      bool   // Enable TLS MITM
	EnableHTTPTrace bool   // Enable HTTP tracing
	TransparentMode bool   // Transparent pass-through (capture only, no MITM)
}

// DefaultProxyConfig returns default configuration
func DefaultProxyConfig() *ProxyConfig {
	return &ProxyConfig{
		ListenAddr:      ":8081",
		HTTPPort:        8080,
		HTTPSPort:       8443,
		EnableMITM:      true,
		EnableHTTPTrace: true,
	}
}

// NewProxy creates a new fingerprint capture proxy
func NewProxy(config *ProxyConfig, logger *slog.Logger) (*Proxy, error) {
	if config == nil {
		config = DefaultProxyConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Initialize certificate manager
	certManager, err := NewCertificateManager(config.CACertFile, config.CAKeyFile)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("initializing certificate manager: %w", err)
	}

	return &Proxy{
		config:      config,
		logger:      logger,
		certManager: certManager,
		connections: make(map[string]*capturedConn),
		ctx:         ctx,
		cancel:      cancel,
	}, nil
}

// SetCaptureCallbacks sets the callbacks for captured data
func (p *Proxy) SetCaptureCallbacks(
	clientHello func(*tlsparser.ClientHello, *types.CompleteFingerprint),
	httpRequest func(*types.HTTPFingerprint),
	captured func(*types.CompleteFingerprint),
) {
	p.onClientHello = clientHello
	p.onHTTPRequest = httpRequest
	p.onCaptured = captured
}

// Start begins the proxy server
func (p *Proxy) Start() error {
	listener, err := net.Listen("tcp", p.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	p.listener = listener

	p.logger.Info("Starting fingerprint capture proxy",
		"addr", p.config.ListenAddr,
		"mitm", p.config.EnableMITM,
	)

	go p.acceptLoop()
	return nil
}

// Stop gracefully shuts down the proxy
func (p *Proxy) Stop() error {
	p.cancel()
	if p.listener != nil {
		return p.listener.Close()
	}
	return nil
}

// acceptLoop accepts incoming connections
func (p *Proxy) acceptLoop() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.ctx.Done():
				return
			default:
				p.logger.Error("Accept error", "error", err)
				continue
			}
		}

		go p.handleConnection(conn)
	}
}

// handleConnection handles a single client connection
func (p *Proxy) handleConnection(clientConn net.Conn) {
	defer func() { _ = clientConn.Close() }()

	// Create captured connection wrapper
	captured := &capturedConn{
		Conn:       clientConn,
		id:         generateConnID(),
		startTime:  time.Now(),
		clientAddr: clientConn.RemoteAddr().String(),
	}

	p.mu.Lock()
	p.connections[captured.id] = captured
	p.mu.Unlock()

	p.logger.Debug("New proxy connection",
		"conn_id", captured.id,
		"client", captured.clientAddr,
	)

	defer func() {
		p.mu.Lock()
		delete(p.connections, captured.id)
		p.mu.Unlock()

		// Finalize fingerprint capture
		if captured.fingerprint != nil {
			p.finalizeCapture(captured)
		}

		duration := time.Since(captured.startTime)
		p.logger.Debug("Proxy connection closed",
			"conn_id", captured.id,
			"duration_ms", duration.Milliseconds(),
		)
	}()

	// Peek at the first bytes to determine protocol
	buf := make([]byte, 8)
	n, err := clientConn.Read(buf)
	if err != nil || n < 8 {
		return
	}

	// Wrap connection to re-inject peeked bytes
	wrappedConn := &peekedConn{
		Conn:   clientConn,
		peeked: buf[:n],
	}

	// Detect protocol
	if isTLS(buf) {
		// HTTPS CONNECT or direct TLS
		p.handleTLS(wrappedConn, captured)
	} else if isHTTPConnect(buf) {
		// HTTP CONNECT proxy request
		p.handleHTTPConnect(wrappedConn, captured)
	} else {
		// Regular HTTP
		p.handleHTTP(wrappedConn, captured)
	}
}

// handleTLS handles direct TLS connections
func (p *Proxy) handleTLS(clientConn net.Conn, captured *capturedConn) {
	if !p.config.EnableMITM {
		p.logger.Debug("MITM disabled, forwarding TLS directly")
		return
	}

	// Capture the ClientHello
	tlsConn := &tlsCaptureConn{
		Conn: clientConn,
		onCapture: func(ch *tlsparser.ClientHello, raw []byte) {
			captured.clientHello = ch
			captured.fingerprint = &types.CompleteFingerprint{
				ID:         generateConnID(),
				Timestamp:  time.Now(),
				SourceIP:   captured.clientAddr,
				ServerName: ch.ServerName,
			}
			captured.fingerprint.TLS = ch.ToFingerprint()
			captured.fingerprint.TLS.RawClientHello = hexEncode(raw)

			p.logger.Info("Captured TLS ClientHello",
				"conn_id", captured.id,
				"ja3", captured.fingerprint.TLS.JA3Hash,
				"ja4", captured.fingerprint.TLS.JA4,
				"ciphers", len(ch.CipherSuites),
				"extensions", len(ch.Extensions),
				"sni", ch.ServerName,
			)

			if p.onClientHello != nil {
				p.onClientHello(ch, captured.fingerprint)
			}
		},
	}

	// Parse SNI from ClientHello
	serverName := extractSNI(tlsConn.buffer)
	if serverName == "" {
		serverName = "unknown"
	}
	captured.serverName = serverName

	// Get or generate certificate for this host
	cert, err := p.certManager.GetCertificate(serverName)
	if err != nil {
		p.logger.Error("Failed to get certificate", "host", serverName, "error", err)
		return
	}

	// Connect to target server FIRST to determine ALPN
	//nolint:gosec // SSRF protection is the responsibility of the caller - this is a proxy
	targetConn, err := tls.Dial("tcp", net.JoinHostPort(serverName, "443"), getBrowserLikeTLSConfig(serverName))
	if err != nil {
		p.logger.Error("Failed to connect to target", "host", serverName, "error", err)
		return
	}
	defer func() { _ = targetConn.Close() }()

	// Discover negotiated protocol
	negotiatedProtocol := targetConn.ConnectionState().NegotiatedProtocol
	p.logger.Debug("Target negotiated protocol", "alpn", negotiatedProtocol, "host", serverName)

	// Configure client TLS with matching ALPN
	nextProtos := []string{"h2", "http/1.1"}
	if negotiatedProtocol != "" {
		// Force the client to use exactly what the server negotiated
		nextProtos = []string{negotiatedProtocol}
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		//nolint:gosec // InsecureSkipVerify required for MITM proxy functionality
		InsecureSkipVerify: true,
		NextProtos:         nextProtos,
		MinVersion:         tls.VersionTLS12,
	}

	// Complete TLS handshake with client
	clientTLS := tls.Server(tlsConn, tlsConfig)
	if err := clientTLS.Handshake(); err != nil {
		p.logger.Error("Client TLS handshake failed", "error", err)
		return
	}
	defer func() { _ = clientTLS.Close() }()

	// Copy data with HTTP inspection
	p.proxyWithInspection(clientTLS, targetConn, captured)
}

// handleHTTPConnect handles HTTP CONNECT proxy requests
func (p *Proxy) handleHTTPConnect(clientConn net.Conn, captured *capturedConn) {
	reader := bufio.NewReader(clientConn)

	// Read CONNECT request
	req, err := http.ReadRequest(reader)
	if err != nil {
		p.logger.Error("Failed to read CONNECT request", "error", err)
		return
	}

	if req.Method != "CONNECT" {
		// Not a CONNECT, handle as regular HTTP
		p.handleHTTPRequest(clientConn, reader, req, captured)
		return
	}

	// Parse target address
	targetAddr := req.Host
	if targetAddr == "" {
		targetAddr = req.URL.Host
	}

	p.logger.Debug("HTTP CONNECT request",
		"conn_id", captured.id,
		"target", targetAddr,
	)

	// Send 200 Connection established
	_, _ = fmt.Fprintf(clientConn, "HTTP/1.1 200 Connection established\r\n\r\n")

	// Transparent mode: capture ClientHello then forward raw TLS
	if p.config.TransparentMode {
		p.handleTransparentTLS(clientConn, targetAddr, captured)
		return
	}

	// Now handle TLS if MITM enabled
	if p.config.EnableMITM {
		host, _, _ := net.SplitHostPort(targetAddr)
		if host == "" {
			host = targetAddr
		}
		captured.serverName = host

		// Generate certificate for this host
		cert, err := p.certManager.GetCertificate(host)
		if err != nil {
			p.logger.Error("Failed to get certificate", "host", host, "error", err)
			return
		}

		// Wrap connection with TLS capture
		tlsCapture := &tlsCaptureConn{
			Conn: clientConn,
			onCapture: func(ch *tlsparser.ClientHello, raw []byte) {
				captured.clientHello = ch
				captured.fingerprint = &types.CompleteFingerprint{
					ID:         generateConnID(),
					Timestamp:  time.Now(),
					SourceIP:   captured.clientAddr,
					ServerName: ch.ServerName,
				}
				captured.fingerprint.TLS = ch.ToFingerprint()
				captured.fingerprint.TLS.RawClientHello = hexEncode(raw)

				p.logger.Info("Captured TLS handshake via CONNECT",
					"host", host,
					"sni", ch.ServerName,
					"ja3", captured.fingerprint.TLS.JA3Hash,
					"ciphers", len(ch.CipherSuites),
				)

				if p.onClientHello != nil {
					p.onClientHello(ch, captured.fingerprint)
				}
			},
		}

		// 1. Connect to target FIRST to determine ALPN
		targetConn, err := tls.Dial("tcp", targetAddr, getBrowserLikeTLSConfig(host))
		if err != nil {
			p.logger.Error("Failed to connect to target", "addr", targetAddr, "error", err)
			return
		}
		defer func() { _ = targetConn.Close() }()

		// 2. Discover negotiated protocol
		negotiatedProtocol := targetConn.ConnectionState().NegotiatedProtocol
		p.logger.Debug("Target negotiated protocol", "alpn", negotiatedProtocol, "host", host)

		// 3. Configure client TLS with matching ALPN
		nextProtos := []string{"h2", "http/1.1"}
		if negotiatedProtocol != "" {
			// Force the client to use exactly what the server negotiated
			nextProtos = []string{negotiatedProtocol}
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{*cert},
			//nolint:gosec // InsecureSkipVerify required for MITM proxy functionality
			InsecureSkipVerify: true,
			NextProtos:         nextProtos,
			MinVersion:         tls.VersionTLS12,
		}

		// 4. Complete TLS handshake with client
		clientTLS := tls.Server(tlsCapture, tlsConfig)
		if err := clientTLS.Handshake(); err != nil {
			p.logger.Error("Client TLS handshake failed", "error", err)
			return
		}
		defer func() { _ = clientTLS.Close() }()

		// Proxy with inspection
		p.proxyWithInspection(clientTLS, targetConn, captured)
	} else {
		// Direct tunnel without MITM
		//nolint:gosec // SSRF protection is the responsibility of the caller - this is a proxy
		targetConn, err := net.Dial("tcp", targetAddr)
		if err != nil {
			p.logger.Error("Failed to connect to target", "addr", targetAddr, "error", err)
			return
		}
		defer func() { _ = targetConn.Close() }()

		p.pipe(clientConn, targetConn)
	}
}

// handleTransparentTLS captures ClientHello then forwards raw TLS without terminating
func (p *Proxy) handleTransparentTLS(clientConn net.Conn, targetAddr string, captured *capturedConn) {
	// Read the TLS record header first (5 bytes)
	header := make([]byte, 5)
	if _, err := io.ReadFull(clientConn, header); err != nil {
		p.logger.Debug("Failed to read TLS header", "error", err)
		return
	}

	// Check it's a handshake record
	if header[0] != 0x16 {
		p.logger.Debug("Not a TLS handshake")
		return
	}

	// Get record length
	recordLen := int(header[3])<<8 | int(header[4])
	if recordLen > 65536 {
		p.logger.Debug("TLS record too large")
		return
	}

	// Read the full ClientHello
	clientHello := make([]byte, recordLen)
	if _, err := io.ReadFull(clientConn, clientHello); err != nil {
		p.logger.Debug("Failed to read ClientHello", "error", err)
		return
	}

	// Combine header + ClientHello for parsing
	fullClientHello := append(header, clientHello...)

	// Parse ClientHello to extract SNI and fingerprint
	ch, err := tlsparser.ParseClientHello(fullClientHello)
	if err != nil {
		p.logger.Debug("Failed to parse ClientHello", "error", err)
		return
	}

	captured.clientHello = ch
	captured.serverName = ch.ServerName
	captured.fingerprint = &types.CompleteFingerprint{
		ID:         generateConnID(),
		Timestamp:  time.Now(),
		SourceIP:   captured.clientAddr,
		ServerName: ch.ServerName,
	}
	captured.fingerprint.TLS = ch.ToFingerprint()
	captured.fingerprint.TLS.RawClientHello = hexEncode(fullClientHello)

	p.logger.Info("Captured TLS ClientHello (transparent)",
		"sni", ch.ServerName,
		"target", targetAddr,
		"ja3", captured.fingerprint.TLS.JA3Hash,
		"ja4", captured.fingerprint.TLS.JA4,
		"ciphers", len(ch.CipherSuites),
	)

	if p.onClientHello != nil {
		p.onClientHello(ch, captured.fingerprint)
	}

	// Connect to target using the original targetAddr (includes port)
	//nolint:gosec // SSRF protection is the responsibility of the caller - this is a proxy
	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		p.logger.Error("Failed to connect to target", "addr", targetAddr, "error", err)
		return
	}
	defer func() { _ = targetConn.Close() }()

	// Forward the raw ClientHello to the target FIRST
	if _, err := targetConn.Write(fullClientHello); err != nil {
		p.logger.Error("Failed to forward ClientHello", "error", err)
		return
	}

	// We simply use pipe to connect the rest of the stream bidirectionally.
	// clientConn here is already the `peekedConn` which handles internal read buffering smoothly.
	p.pipe(clientConn, targetConn)
}

// handleHTTP handles plain HTTP requests
func (p *Proxy) handleHTTP(clientConn net.Conn, captured *capturedConn) {
	reader := bufio.NewReader(clientConn)

	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				p.logger.Error("Failed to read HTTP request", "error", err)
			}
			return
		}

		p.handleHTTPRequest(clientConn, reader, req, captured)
	}
}

// handleHTTPRequest processes a single HTTP request
func (p *Proxy) handleHTTPRequest(clientConn net.Conn, reader *bufio.Reader, req *http.Request, captured *capturedConn) {
	// Capture HTTP request
	httpCapture := &types.HTTPFingerprint{
		Method:    req.Method,
		Path:      req.URL.Path,
		Protocol:  req.Proto,
		UserAgent: req.UserAgent(),
	}

	// Capture headers
	pos := 1
	for name, values := range req.Header {
		for _, value := range values {
			httpCapture.Headers = append(httpCapture.Headers, types.HeaderInfo{
				Name:     name,
				Value:    value,
				Position: pos,
				IsPseudo: false,
			})
			pos++
		}
	}

	// Update captured fingerprint
	if captured.fingerprint == nil {
		captured.fingerprint = &types.CompleteFingerprint{
			ID:         captured.id,
			Timestamp:  captured.startTime,
			SourceIP:   captured.clientAddr,
			ServerName: req.Host,
		}
	}
	captured.fingerprint.HTTP = httpCapture

	p.logger.Debug("Captured HTTP request",
		"method", req.Method,
		"host", req.Host,
		"path", req.URL.Path,
		"user_agent", req.UserAgent(),
	)

	if p.onHTTPRequest != nil {
		p.onHTTPRequest(httpCapture)
	}

	// Forward request to target
	targetURL := &url.URL{
		Scheme: "http",
		Host:   req.Host,
		Path:   req.URL.Path,
	}
	if req.URL.RawQuery != "" {
		targetURL.RawQuery = req.URL.RawQuery
	}

	// Create new request to target
	//nolint:gosec // SSRF protection is the responsibility of the caller - this is a proxy
	targetReq, err := http.NewRequest(req.Method, targetURL.String(), req.Body)
	if err != nil {
		p.logger.Error("Failed to create target request", "error", err)
		return
	}

	// Copy headers, excluding hop-by-hop headers
	targetReq.Header = make(http.Header)
	for k, vv := range req.Header {
		lowerK := strings.ToLower(k)
		if lowerK == "connection" || lowerK == "proxy-connection" || lowerK == "keep-alive" || lowerK == "proxy-authenticate" || lowerK == "proxy-authorization" || lowerK == "te" || lowerK == "trailer" || lowerK == "transfer-encoding" || lowerK == "upgrade" {
			continue
		}
		for _, v := range vv {
			targetReq.Header.Add(k, v)
		}
	}

	// Execute request
	client := &http.Client{
		Timeout: constants.DefaultTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	//nolint:gosec // SSRF protection is the responsibility of the caller - this is a proxy
	resp, err := client.Do(targetReq)
	if err != nil {
		p.logger.Error("Request to target failed", "error", err)
		_, _ = fmt.Fprintf(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if captured.fingerprint != nil {
		httpResp := &types.HTTPResponseFingerprint{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Protocol:   resp.Proto,
			BodyLength: resp.ContentLength,
		}

		pos := 1
		for name, values := range resp.Header {
			for _, value := range values {
				httpResp.Headers = append(httpResp.Headers, types.HeaderInfo{
					Name:     name,
					Value:    value,
					Position: pos,
					IsPseudo: false,
				})
				pos++
			}
		}

		captured.fingerprint.HTTPResp = httpResp
	}

	// Write response to client
	_ = resp.Write(clientConn)
}

// proxyWithInspection proxies data while inspecting HTTP
func (p *Proxy) proxyWithInspection(clientConn, targetConn net.Conn, captured *capturedConn) {
	errChan := make(chan error, 2)

	// Client -> Target (with inspection)
	go func() {
		if p.config.EnableHTTPTrace {
			// Wrap to capture HTTP
			p.copyWithHTTPInspection(clientConn, targetConn, captured)
		} else {
			_, err := io.Copy(targetConn, clientConn)
			errChan <- err
		}
	}()

	// Target -> Client
	go func() {
		_, err := io.Copy(clientConn, targetConn)
		errChan <- err
	}()

	// Wait for either direction to close
	<-errChan
}

// copyWithHTTPInspection copies data while looking for HTTP requests
func (p *Proxy) copyWithHTTPInspection(src, dst net.Conn, captured *capturedConn) {
	// For now, just do simple copy
	// Full HTTP inspection would require a complete HTTP parser
	_, _ = io.Copy(dst, src)
}

// pipe bidirectionally copies data between two connections
func (p *Proxy) pipe(conn1, conn2 net.Conn) {
	errChan := make(chan error, 2)

	go func() {
		_, err := io.Copy(conn1, conn2)
		errChan <- err
	}()

	go func() {
		_, err := io.Copy(conn2, conn1)
		errChan <- err
	}()

	<-errChan
}

// finalizeCapture completes the fingerprint capture
func (p *Proxy) finalizeCapture(captured *capturedConn) {
	if captured.fingerprint == nil {
		return
	}

	// Ensure ServerName is set — fallback from captured.serverName (CONNECT host)
	if captured.fingerprint.ServerName == "" && captured.serverName != "" {
		captured.fingerprint.ServerName = captured.serverName
	}

	// Infer HTTP/2 if not captured
	if captured.fingerprint.HTTP2 == nil {
		captured.fingerprint.HTTP2 = inferHTTP2Fingerprint()
	}

	// Count headers if HTTP data is available
	headerCount := 0
	if captured.fingerprint.HTTP != nil {
		headerCount = len(captured.fingerprint.HTTP.Headers)
	}

	ja3 := "none"
	if captured.fingerprint.TLS != nil {
		ja3 = captured.fingerprint.TLS.JA3Hash
	}

	p.logger.Info("Fingerprint capture complete",
		"host", captured.fingerprint.ServerName,
		"ja3", ja3,
		"headers", headerCount,
		"duration", time.Since(captured.startTime),
	)

	if p.onCaptured != nil {
		p.onCaptured(captured.fingerprint)
	}
}

// GetPACFile returns a Proxy Auto-Configuration file
func (p *Proxy) GetPACFile() string {
	proxyAddr := p.config.ListenAddr
	if proxyAddr[0] == ':' {
		proxyAddr = "127.0.0.1" + proxyAddr
	}

	return fmt.Sprintf(`function FindProxyForURL(url, host) {
	// Use proxy for all HTTPS connections
	if (url.substring(0, 6) == "https:") {
		return "PROXY %s";
	}
	// Direct connection for HTTP
	return "DIRECT";
}`, proxyAddr)
}

// capturedConn tracks a single connection's capture state
type capturedConn struct {
	net.Conn

	id          string
	startTime   time.Time
	clientAddr  string
	serverName  string
	clientHello *tlsparser.ClientHello
	fingerprint *types.CompleteFingerprint
}

// Helper functions

func isTLS(buf []byte) bool {
	// TLS record starts with 0x16 (handshake)
	return len(buf) > 0 && buf[0] == 0x16
}

func isHTTPConnect(buf []byte) bool {
	return len(buf) > 7 && string(buf[:7]) == "CONNECT"
}

func extractSNI(data []byte) string {
	// Simple SNI extraction from ClientHello
	// This is a simplified version - full parsing is in lab/tls_parser.go
	ch, err := tlsparser.ParseClientHello(data)
	if err != nil {
		return ""
	}
	return ch.ServerName
}

func hexEncode(data []byte) string {
	result := make([]byte, len(data)*2)
	for i, b := range data {
		result[i*2] = "0123456789abcdef"[b>>4]
		result[i*2+1] = "0123456789abcdef"[b&0x0f]
	}
	return string(result)
}

func generateConnID() string {
	return fmt.Sprintf("conn-%d", time.Now().UnixNano())
}

func inferHTTP2Fingerprint() *types.HTTP2Fingerprint {
	// Default to Chrome-like HTTP/2 settings
	return &types.HTTP2Fingerprint{
		Settings: []types.HTTP2Setting{
			{ID: 1, Name: "HEADER_TABLE_SIZE", Value: 65536, Position: 1},
			{ID: 2, Name: "ENABLE_PUSH", Value: 0, Position: 2},
			{ID: 3, Name: "MAX_CONCURRENT_STREAMS", Value: 1000, Position: 3},
			{ID: 4, Name: "INITIAL_WINDOW_SIZE", Value: 6291456, Position: 4},
		},
		PseudoHeaders: []string{
			":method", ":authority", ":scheme", ":path",
		},
	}
}

// getBrowserLikeTLSConfig returns a TLS config that mimics Chrome for outbound connections
func getBrowserLikeTLSConfig(serverName string) *tls.Config {
	return &tls.Config{
		ServerName: serverName,
		//nolint:gosec // InsecureSkipVerify required for browser impersonation proxy
		InsecureSkipVerify: true,
		// Chrome-like cipher suites preference
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		PreferServerCipherSuites: false,
		// Enable ALPN for HTTP/2
		NextProtos: []string{"h2", "http/1.1"},
		// Use TLS 1.3 with 1.2 fallback
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}
}

// peekedConn wraps a connection with peeked data
type peekedConn struct {
	net.Conn

	peeked []byte
	read   int
}

func (c *peekedConn) Read(p []byte) (n int, err error) {
	if c.read < len(c.peeked) {
		n = copy(p, c.peeked[c.read:])
		c.read += n
		if n == len(p) {
			return n, nil
		}
		p = p[n:]
	}

	n2, err := c.Conn.Read(p)
	return n + n2, err
}

// tlsCaptureConn wraps a connection to capture ClientHello
type tlsCaptureConn struct {
	net.Conn

	onCapture func(*tlsparser.ClientHello, []byte)
	buffer    []byte
	captured  bool
}

func (c *tlsCaptureConn) Read(p []byte) (n int, err error) {
	n, err = c.Conn.Read(p)
	if n > 0 && !c.captured {
		c.buffer = append(c.buffer, p[:n]...)

		// Try to parse ClientHello
		if len(c.buffer) >= 5 {
			recordLen := int(c.buffer[3])<<8 | int(c.buffer[4])
			if len(c.buffer) >= 5+recordLen {
				ch, err := tlsparser.ParseClientHello(c.buffer[:5+recordLen])
				if err == nil && c.onCapture != nil {
					c.captured = true
					c.onCapture(ch, c.buffer[:5+recordLen])
				}
			}
		}
	}
	return n, err
}
