package lab

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/stealth/brwslab/brws/adversarial"
	"github.com/stealth/brwslab/brws/constants"
	"github.com/stealth/brwslab/brws/engine/spoof"
	"github.com/stealth/brwslab/brws/proxy"
	"github.com/stealth/brwslab/brws/sniffer"
	"github.com/stealth/brwslab/brws/tlsparser"
	"github.com/stealth/brwslab/brws/types"
	"golang.org/x/net/websocket"
)

//go:embed static/*
var staticFiles embed.FS

// EnhancedServer provides comprehensive fingerprint capture capabilities
type EnhancedServer struct {
	capture         *CaptureServer
	config          *ServerConfig
	logger          *slog.Logger
	listener        net.Listener
	httpServer      *http.Server
	httpServerPlain *http.Server

	// Proxy for intercepting traffic
	proxy       *proxy.Proxy
	proxyConfig *proxy.ProxyConfig

	// Browser (Chrome) process management
	browser   *BrowserController
	browserMu sync.Mutex

	// WebSocket clients for real-time updates
	wsClients map[*websocket.Conn]bool
	wsMu      sync.RWMutex
}

// ServerConfig for the enhanced lab server
type ServerConfig struct {
	BindAddr        string
	HTTPPort        int
	HTTPSPort       int
	ProxyPort       int    // Port for MITM proxy
	ProxyMode       string // "mitm" or "transparent"
	TLSCert         string
	TLSKey          string
	CaptureRawBytes bool
	CaptureTiming   bool
	StoreCaptures   bool
	CaptureDir      string
	EnableProxy     bool // Enable the MITM proxy
}

// DefaultConfig returns default server configuration
func DefaultConfig() *ServerConfig {
	return &ServerConfig{
		BindAddr:        "0.0.0.0",
		HTTPPort:        8080,
		HTTPSPort:       8443,
		ProxyPort:       8081,
		CaptureRawBytes: true,
		CaptureTiming:   true,
		StoreCaptures:   true,
		EnableProxy:     true,
	}
}

// NewEnhancedServer creates a new enhanced fingerprint capture server
func NewEnhancedServer(config *ServerConfig, logger *slog.Logger) *EnhancedServer {
	if config == nil {
		config = DefaultConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}

	capture := NewCaptureServer()
	capture.CaptureRawBytes = config.CaptureRawBytes
	capture.CaptureTiming = config.CaptureTiming

	return &EnhancedServer{
		capture:   capture,
		config:    config,
		logger:    logger,
		wsClients: make(map[*websocket.Conn]bool),
	}
}

// Start begins serving on both HTTP and HTTPS
func (s *EnhancedServer) Start() error {
	mux := http.NewServeMux()
	s.setupRoutes(mux)

	// Start packet sniffer in background
	go func() {
		s.logger.Info("Starting native rust packet sniffer")
		err := sniffer.Start("", s.broadcastPacket)
		if err != nil {
			s.logger.Error("Packet sniffer failed to start", "error", err)
		}
	}()

	errCh := make(chan error, 2)

	// Start HTTP server (redirects to HTTPS or serves capture)
	go func() {
		addr := fmt.Sprintf("%s:%d", s.config.BindAddr, s.config.HTTPPort)
		s.logger.Info("Starting HTTP capture server", "addr", addr)

		server := &http.Server{
			Addr:         addr,
			Handler:      mux,
			ReadTimeout:  constants.DefaultReadTimeout,
			WriteTimeout: constants.DefaultWriteTimeout,
		}
		s.httpServerPlain = server

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	// Start HTTPS server with TLS and raw capture
	go func() {
		if s.config.TLSCert == "" || s.config.TLSKey == "" {
			s.logger.Warn("TLS certificate not configured, HTTPS server disabled")
			return
		}

		addr := fmt.Sprintf("%s:%d", s.config.BindAddr, s.config.HTTPSPort)
		s.logger.Info("Starting HTTPS capture server", "addr", addr)

		// Load certificates
		cert, err := tls.LoadX509KeyPair(s.config.TLSCert, s.config.TLSKey)
		if err != nil {
			errCh <- fmt.Errorf("failed to load TLS certificates: %w", err)
			return
		}

		// Create base listener
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			errCh <- fmt.Errorf("failed to listen on HTTPS: %w", err)
			return
		}

		// Wrap with capturing listener
		capturingListener := &CapturingListener{
			Listener: listener,
			OnClientHello: func(ch *tlsparser.ClientHello, fp *types.CompleteFingerprint) {
				s.logger.Debug("Captured TLS ClientHello",
					"ja3", fp.TLS.JA3Hash,
					"ciphers", len(fp.TLS.CipherSuites),
					"extensions", len(fp.TLS.Extensions),
				)
				// Convert to lab.CompleteFingerprint and store
				s.capture.StoreCaptureTypes(fp.ID, fp)
			},
		}

		// TLS config with certificates
		tlsConfig := &tls.Config{
			Certificates:       []tls.Certificate{cert},
			GetConfigForClient: s.captureClientHello,
		}

		server := &http.Server{
			Handler:      mux,
			TLSConfig:    tlsConfig,
			ReadTimeout:  constants.DefaultReadTimeout,
			WriteTimeout: constants.DefaultWriteTimeout,
		}
		s.httpServer = server

		// Wrap listener with TLS using our config
		tlsListener := tls.NewListener(capturingListener, tlsConfig)

		if err := server.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("HTTPS server error: %w", err)
		}
	}()

	// Start MITM proxy for intercepting traffic
	go func() {
		if err := s.StartProxy(); err != nil {
			s.logger.Error("Failed to start proxy", "error", err)
			// Don't fail completely if proxy can't start
		}
	}()

	return <-errCh
}

// captureClientHello captures raw TLS ClientHello
func (s *EnhancedServer) captureClientHello(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	s.logger.Debug("TLS ClientHello received",
		"server_name", hello.ServerName,
		"cipher_suites", len(hello.CipherSuites),
		"supported_versions", len(hello.SupportedVersions),
	)

	// Build partial TLS fingerprint from ClientHelloInfo
	// Note: Go's standard library limits what we can access here
	// For full capture, we need raw packet capture

	return nil, nil // Use default config
}

// setupRoutes configures all HTTP handlers
func (s *EnhancedServer) setupRoutes(mux *http.ServeMux) {
	// Static files from embedded filesystem
	staticFS, err := fs.Sub(staticFiles, "static")
	if err == nil {
		mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
		// Next.js static export puts its assets under /_next/
		// Serve them from the _next subdirectory of the embedded static dir
		nextFS, nextErr := fs.Sub(staticFiles, "static/_next")
		if nextErr == nil {
			mux.Handle("/_next/", http.StripPrefix("/_next/", http.FileServer(http.FS(nextFS))))
		}
	}

	// Fingerprint capture endpoints
	mux.HandleFunc("/capture", s.handleModernUI)
	mux.HandleFunc("/capture/json", s.handleCaptureJSON)
	mux.HandleFunc("/capture/yaml", s.handleCaptureYAML)

	// Baseline management
	mux.HandleFunc("/baseline", s.handleBaseline)
	mux.HandleFunc("/baseline/", s.handleBaselineDetail)

	// Comparison
	mux.HandleFunc("/compare", s.handleCompare)

	// Health check
	mux.HandleFunc("/health", s.handleHealth)

	// Debug/status endpoint
	mux.HandleFunc("/debug", s.handleDebug)

	// Modern UI at root
	mux.HandleFunc("/", s.handleModernUI)

	// Historical captures list API
	mux.HandleFunc("/captures", s.handleCapturesList)
	mux.HandleFunc("/captures/", s.handleCaptureDetail)

	// Control API for proxy and browser management
	mux.HandleFunc("/api/status", s.handleAPIStatus)
	mux.HandleFunc("/api/proxy/start", s.handleAPIProxyStart)
	mux.HandleFunc("/api/proxy/stop", s.handleAPIProxyStop)
	mux.HandleFunc("/api/chrome/launch", s.handleAPIChromeLaunch)
	mux.HandleFunc("/api/chrome/stop", s.handleAPIChromeStop)
	mux.HandleFunc("/api/test-signature", s.handleTestSignature)
	mux.HandleFunc("/api/stealth-test", adversarial.NewAdvancedStealthServer().HandleRequest)
	mux.HandleFunc("/api/ml/evaluate", s.handleMLEvaluate)

	// Proxy PAC file for browser auto-configuration
	mux.HandleFunc("/proxy.pac", s.handleProxyPAC)

	// WebSocket for real-time updates
	mux.Handle("/ws", websocket.Handler(s.handleWebSocket))
}

// handleCaptureJSON serves JSON fingerprint
func (s *EnhancedServer) handleCaptureJSON(w http.ResponseWriter, r *http.Request) {
	fp := s.capture.CaptureFromRequest(w, r)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Fingerprint-Id", fp.ID)

	if err := json.NewEncoder(w).Encode(fp); err != nil {
		s.logger.Error("Failed to encode JSON", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// handleCaptureYAML serves YAML fingerprint
func (s *EnhancedServer) handleCaptureYAML(w http.ResponseWriter, r *http.Request) {
	fp := s.capture.CaptureFromRequest(w, r)

	data, err := fp.ExportYAML()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("X-Fingerprint-Id", fp.ID)
	//nolint:gosec // Response is HTML-escaped and served as YAML content-type
	_, _ = w.Write([]byte(html.EscapeString(string(data))))
}

// handleBaseline manages baselines
func (s *EnhancedServer) handleBaseline(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		// Store new baseline
		var fp CompleteFingerprint
		if err := json.NewDecoder(r.Body).Decode(&fp); err != nil {
			http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
			return
		}

		name := r.URL.Query().Get("name")
		if name == "" {
			name = fmt.Sprintf("baseline_%d", time.Now().Unix())
		}

		s.capture.StoreBaseline(name, &fp)
		s.logger.Info("Stored baseline", "name", name, "id", fp.ID)

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{
			"name": name,
			"id":   fp.ID,
		}); err != nil {
			http.Error(w, `{"error": "encode failed"}`, http.StatusInternalServerError)
		}

	case "GET":
		// List baselines
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"message": "Use /baseline/{name} to retrieve specific baseline",
		}); err != nil {
			http.Error(w, `{"error": "encode failed"}`, http.StatusInternalServerError)
		}

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleTestSignature receives a capture ID and tests its fingerprint against a real URL
func (s *EnhancedServer) handleTestSignature(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fp, ok := s.capture.GetCapture(req.ID)
	if !ok || fp == nil {
		http.Error(w, "Capture not found", http.StatusNotFound)
		return
	}

	// The lab package redefines CompleteFingerprint so we JSON round-trip it to the generic types package
	var typesFp types.CompleteFingerprint
	fpBody, err := json.Marshal(fp)
	if err != nil {
		http.Error(w, `{"error": "marshal failed"}`, http.StatusInternalServerError)
		return
	}
	if err := json.Unmarshal(fpBody, &typesFp); err != nil {
		http.Error(w, `{"error": "unmarshal failed"}`, http.StatusInternalServerError)
		return
	}

	sig := spoof.SignatureFromFingerprint(&typesFp)
	if sig == nil {
		http.Error(w, "Invalid fingerprint structure", http.StatusInternalServerError)
		return
	}

	engine, err := spoof.NewSpoofEngineFromSignature("dynamic", sig)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to build spoof engine: %v", err), http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, "GET", req.URL, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp, err := engine.Do(httpReq)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		if encErr := json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}); encErr != nil {
			http.Error(w, `{"error": "encode failed"}`, http.StatusInternalServerError)
			return
		}
		return
	}
	defer func() { _ = resp.Body.Close() }()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read response body", "error", err)
	}

	// Phase 11: Machine Consumable Tracing
	// If this was an internal validation test against the WAF shield, 
	// combine the Generator properties with the Shield observations to construct ML-ready pairs!
	if strings.Contains(req.URL, "stealth-test") {
		var mlTrace map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &mlTrace); err == nil {
			mlTrace["source_fingerprint"] = typesFp

			if traceData, err := json.MarshalIndent(mlTrace, "", "  "); err == nil {
				homeDir, _ := os.UserHomeDir()
				traceDir := filepath.Join(homeDir, ".stealth", "traces")
				_ = os.MkdirAll(traceDir, 0750)
				traceFile := filepath.Join(traceDir, fmt.Sprintf("trace_%s_%d.json", typesFp.ID, time.Now().UnixNano()))
				_ = os.WriteFile(traceFile, traceData, 0600)
				s.logger.Info("Saved ML Evasion Trace", "file", traceFile)
			}
		}
	}

	headerMap := make(map[string]string)
	for k, v := range resp.Header {
		headerMap[k] = strings.Join(v, ", ")
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"success":     true,
		"status_code": resp.StatusCode,
		"headers":     headerMap,
		"body":        string(bodyBytes),
	}); err != nil {
		http.Error(w, `{"error": "encode failed"}`, http.StatusInternalServerError)
	}
}

// handleBaselineDetail retrieves specific baseline
func (s *EnhancedServer) handleBaselineDetail(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Path[len("/baseline/"):]
	if name == "" {
		http.Error(w, "Baseline name required", http.StatusBadRequest)
		return
	}

	fp, ok := s.capture.GetBaseline(name)
	if !ok {
		http.Error(w, fmt.Sprintf("Baseline not found: %s", name), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(fp); err != nil {
		http.Error(w, `{"error": "encode failed"}`, http.StatusInternalServerError)
	}
}

// handleCompare compares fingerprints
func (s *EnhancedServer) handleCompare(w http.ResponseWriter, r *http.Request) {
	baselineName := r.URL.Query().Get("baseline")
	testName := r.URL.Query().Get("test")

	baseline, ok := s.capture.GetBaseline(baselineName)
	if !ok {
		http.Error(w, fmt.Sprintf("Baseline not found: %s", baselineName), http.StatusNotFound)
		return
	}

	test, ok := s.capture.GetBaseline(testName)
	if !ok {
		// Use current request as test
		test = s.capture.CaptureFromRequest(w, r)
	}

	diff := CompareFingerprints(baseline, test)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(diff); err != nil {
		http.Error(w, `{"error": "encode failed"}`, http.StatusInternalServerError)
	}
}

// handleHealth provides health check
func (s *EnhancedServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
	}); err != nil {
		http.Error(w, `{"error": "encode failed"}`, http.StatusInternalServerError)
	}
}

// handleDebug returns debug information about the server and proxy
func (s *EnhancedServer) handleDebug(w http.ResponseWriter, r *http.Request) {
	s.wsMu.RLock()
	wsClientCount := len(s.wsClients)
	s.wsMu.RUnlock()

	proxyStatus := "not running"
	proxyAddr := ""
	if s.proxy != nil {
		proxyStatus = "running"
		if s.proxyConfig != nil {
			proxyAddr = s.proxyConfig.ListenAddr
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"server": map[string]interface{}{
			"http_port":  s.config.HTTPPort,
			"https_port": s.config.HTTPSPort,
			"proxy_port": s.config.ProxyPort,
			"bind_addr":  s.config.BindAddr,
		},
		"proxy": map[string]interface{}{
			"status": proxyStatus,
			"addr":   proxyAddr,
		},
		"websocket": map[string]interface{}{
			"connected_clients": wsClientCount,
		},
		"config": map[string]interface{}{
			"capture_raw_bytes": s.config.CaptureRawBytes,
			"capture_timing":    s.config.CaptureTiming,
			"store_captures":    s.config.StoreCaptures,
			"enable_proxy":      s.config.EnableProxy,
		},
		"timestamp": time.Now().Unix(),
	}); err != nil {
		http.Error(w, `{"error": "encode failed"}`, http.StatusInternalServerError)
	}
}

// handleCapturesList returns a list of recent captures
func (s *EnhancedServer) handleCapturesList(w http.ResponseWriter, r *http.Request) {
	// Parse limit from query, default 50
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}

	q := r.URL.Query().Get("q")

	captures := s.capture.ListCaptures(limit, q)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"count":    len(captures),
		"captures": captures,
	}); err != nil {
		http.Error(w, `{"error": "encode failed"}`, http.StatusInternalServerError)
	}
}

// handleCaptureDetail returns the full fingerprint for a specific capture
func (s *EnhancedServer) handleCaptureDetail(w http.ResponseWriter, r *http.Request) {
	// Extract ID from path: /captures/{id}
	id := strings.TrimPrefix(r.URL.Path, "/captures/")
	if id == "" {
		http.Error(w, "Missing capture ID", http.StatusBadRequest)
		return
	}

	fp, ok := s.capture.GetCapture(id)
	if !ok {
		http.Error(w, "Capture not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(fp); err != nil {
		http.Error(w, `{"error": "encode failed"}`, http.StatusInternalServerError)
	}
}

// handleModernUI serves the modern React-like UI
func (s *EnhancedServer) handleModernUI(w http.ResponseWriter, r *http.Request) {
	// Serve the embedded index.html
	data, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		s.logger.Error("Failed to read static file", "error", err)
		// Fallback to simple HTML
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>Browser Fingerprint Lab</title></head>
<body><h1>Browser Fingerprint Lab</h1>
<p><a href="/capture/json">View JSON</a></p></body></html>`)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// Stop gracefully shuts down the server
func (s *EnhancedServer) Stop(ctx context.Context) error {
	var err1, err2 error
	if s.httpServer != nil {
		err1 = s.httpServer.Shutdown(ctx)
	}
	if s.httpServerPlain != nil {
		err2 = s.httpServerPlain.Shutdown(ctx)
	}
	if err1 != nil {
		return err1
	}
	return err2
}

// GetCapture returns the underlying capture server
func (s *EnhancedServer) GetCapture() *CaptureServer {
	return s.capture
}

// StartProxy starts the MITM proxy for intercepting traffic
func (s *EnhancedServer) StartProxy() error {
	if !s.config.EnableProxy {
		s.logger.Info("Proxy disabled")
		return nil
	}

	proxyConfig := &proxy.ProxyConfig{
		ListenAddr:      fmt.Sprintf("%s:%d", s.config.BindAddr, s.config.ProxyPort),
		HTTPPort:        s.config.HTTPPort,
		HTTPSPort:       s.config.HTTPSPort,
		EnableMITM:      s.config.ProxyMode == "mitm",
		TransparentMode: s.config.ProxyMode == "transparent",
	}

	p, err := proxy.NewProxy(proxyConfig, s.logger)
	if err != nil {
		return fmt.Errorf("creating proxy: %w", err)
	}

	// Set up capture callbacks
	p.SetCaptureCallbacks(
		func(ch *tlsparser.ClientHello, fp *types.CompleteFingerprint) {
			s.logger.Info("Proxy captured TLS handshake",
				"ja3", fp.TLS.JA3Hash,
				"ciphers", len(ch.CipherSuites),
			)
			// Note: don't broadcast here — fingerprint is not finalized yet
			// (ServerName may not be set). Wait for onCaptured.
		},
		func(http *types.HTTPFingerprint) {
			s.logger.Debug("Proxy captured HTTP request",
				"method", http.Method,
				"path", http.Path,
			)
		},
		func(fp *types.CompleteFingerprint) {
			ja3 := "none"
			if fp.TLS != nil {
				ja3 = fp.TLS.JA3Hash
			}
			s.logger.Info("Proxy captured complete fingerprint",
				"id", fp.ID,
				"host", fp.ServerName,
				"ja3", ja3,
			)
			// Store in capture server
			s.capture.StoreCaptureTypes(fp.ID, fp)
			// Broadcast finalized fingerprint to WebSocket clients
			s.broadcastFingerprint(fp)
		},
	)

	s.proxy = p
	s.proxyConfig = proxyConfig

	if err := p.Start(); err != nil {
		return fmt.Errorf("starting proxy: %w", err)
	}

	s.logger.Info("MITM proxy started",
		"addr", proxyConfig.ListenAddr,
		"configure_browser", fmt.Sprintf("http://localhost:%d/proxy.pac", s.config.HTTPPort),
	)

	return nil
}

// StopProxy stops the MITM proxy
func (s *EnhancedServer) StopProxy() error {
	if s.proxy != nil {
		return s.proxy.Stop()
	}
	return nil
}

// handleProxyPAC serves the Proxy Auto-Configuration file
func (s *EnhancedServer) handleProxyPAC(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		http.Error(w, "Proxy not running", http.StatusServiceUnavailable)
		return
	}

	pac := s.proxy.GetPACFile()
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	_, _ = w.Write([]byte(pac))
}

// handleWebSocket handles WebSocket connections for real-time updates
func (s *EnhancedServer) handleWebSocket(ws *websocket.Conn) {
	s.logger.Info("WebSocket client connected", "remote", ws.RemoteAddr())

	// Register client
	s.wsMu.Lock()
	s.wsClients[ws] = true
	s.wsMu.Unlock()

	defer func() {
		s.wsMu.Lock()
		delete(s.wsClients, ws)
		s.wsMu.Unlock()
		_ = ws.Close()
		s.logger.Info("WebSocket client disconnected", "remote", ws.RemoteAddr())
	}()

	// Send initial message
	welcome := map[string]string{
		"type":    "connected",
		"message": "Connected to Browser Fingerprint Lab",
	}
	if err := websocket.JSON.Send(ws, welcome); err != nil {
		s.logger.Error("Failed to send WebSocket welcome", "error", err)
		return
	}

	// Keep connection alive and handle incoming messages
	for {
		var msg map[string]interface{}
		if err := websocket.JSON.Receive(ws, &msg); err != nil {
			if err.Error() != "EOF" {
				s.logger.Error("WebSocket receive error", "error", err)
			}
			return
		}

		// Handle client messages if needed
		s.logger.Debug("WebSocket message received", "msg", msg)
	}
}

// broadcastFingerprint sends a fingerprint to all connected WebSocket clients
func (s *EnhancedServer) broadcastFingerprint(fp *types.CompleteFingerprint) {
	s.wsMu.RLock()
	clients := make([]*websocket.Conn, 0, len(s.wsClients))
	for client := range s.wsClients {
		clients = append(clients, client)
	}
	s.wsMu.RUnlock()

	ja3, ja4 := "none", "none"
	cipherCount := 0
	if fp.TLS != nil {
		ja3 = fp.TLS.JA3Hash
		ja4 = fp.TLS.JA4
		cipherCount = len(fp.TLS.CipherSuites)
	}

	msg := map[string]interface{}{
		"type":         "fingerprint",
		"id":           fp.ID,
		"timestamp":    fp.Timestamp,
		"ja3":          ja3,
		"ja4":          ja4,
		"cipher_count": cipherCount,
		"host":         fp.ServerName,
	}

	for _, client := range clients {
		if err := websocket.JSON.Send(client, msg); err != nil {
			s.logger.Debug("Failed to send to WebSocket client, removing", "error", err)
			s.wsMu.Lock()
			delete(s.wsClients, client)
			s.wsMu.Unlock()
			_ = client.Close()
		}
	}
}

// broadcastPacket sends a live packet to all connected WebSocket clients
func (s *EnhancedServer) broadcastPacket(pkt sniffer.Packet) {
	s.wsMu.RLock()
	clients := make([]*websocket.Conn, 0, len(s.wsClients))
	for client := range s.wsClients {
		clients = append(clients, client)
	}
	s.wsMu.RUnlock()

	msg := map[string]interface{}{
		"type":      "packet_event",
		"timestamp": pkt.Timestamp.UnixMilli(),
		"source_ip": pkt.SourceIP,
		"dest_ip":   pkt.DestIP,
		"protocol":  pkt.Protocol,
		"length":    pkt.Length,
		"info":      pkt.Info,
	}

	for _, client := range clients {
		if err := websocket.JSON.Send(client, msg); err != nil {
			s.logger.Debug("Failed to send packet to WebSocket, removing", "error", err)
			s.wsMu.Lock()
			delete(s.wsClients, client)
			s.wsMu.Unlock()
			_ = client.Close()
		}
	}
}

// GetProxyAddr returns the proxy address for display
func (s *EnhancedServer) GetProxyAddr() string {
	if s.proxyConfig != nil {
		return s.proxyConfig.ListenAddr
	}
	return ""
}
