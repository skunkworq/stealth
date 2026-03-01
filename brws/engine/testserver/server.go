// Package testserver provides a mock server for testing browser fingerprints and detection.
package testserver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
)

// RequestInfo contains captured request information
type RequestInfo struct {
	Timestamp  time.Time         `json:"timestamp"`
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	Headers    map[string]string `json:"headers"`
	TLS        *TLSInfo          `json:"tls,omitempty"`
	RemoteAddr string            `json:"remote_addr"`
	Body       string            `json:"body,omitempty"`
}

// TLSInfo contains captured TLS information
type TLSInfo struct {
	Version         string `json:"version"`
	CipherSuite     string `json:"cipher_suite"`
	ServerName      string `json:"server_name"`
	NegotiatedProto string `json:"negotiated_protocol"`
	JA3             string `json:"ja3"`
	JA4             string `json:"ja4"`
	UniqueTLS       string `json:"unique_tls"`
	CertFingerprint string `json:"cert_fingerprint"`
}

// DetectionResult represents the detection analysis
type DetectionResult struct {
	IsBot            bool           `json:"is_bot"`
	Score            float64        `json:"score"`
	DetectionVectors []VectorResult `json:"detection_vectors"`
	Indicators       []Indicator    `json:"indicators"`
	Request          RequestInfo    `json:"request"`
}

// VectorResult represents a single detection vector
type VectorResult struct {
	Vector     string      `json:"vector"`
	Detected   bool        `json:"detected"`
	Score      float64     `json:"score"`
	Indicators []Indicator `json:"indicators"`
}

// Indicator represents a detection indicator
type Indicator struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
}

// Server is a test server that captures fingerprints
type Server struct {
	*httptest.Server

	URL           string
	Requests      []RequestInfo
	RequestsMutex sync.RWMutex
	RequestCount  atomic.Int64

	// TLS configuration
	tlsConfig *tls.Config

	// Detection configuration
	DetectTLSFingerprint  bool
	DetectHTTPFingerprint bool
	StrictHeaders         bool

	// Custom response
	ResponseStatus  int
	ResponseBody    string
	ResponseHeaders map[string]string
}

// New creates a new test server
func New() *Server {
	return NewWithConfig(nil)
}

// NewWithTLS creates a test server with TLS enabled
func NewWithTLS() *Server {
	cert, err := generateTestCert()
	if err != nil {
		// Fall back to using httptest's self-signed cert
		s := &Server{
			DetectTLSFingerprint:  true,
			DetectHTTPFingerprint: true,
			StrictHeaders:         false,
			ResponseStatus:        200,
			ResponseBody:          `{"status": "ok", "message": "Test server response"}`,
			ResponseHeaders:       map[string]string{"Content-Type": "application/json"},
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/", s.handleRequest)
		mux.HandleFunc("/detect", s.handleDetect)
		mux.HandleFunc("/fingerprint", s.handleFingerprint)
		mux.HandleFunc("/headers", s.handleHeaders)
		mux.HandleFunc("/tls", s.handleTLS)
		tlsServer := httptest.NewTLSServer(mux)
		s.Server = tlsServer
		s.URL = tlsServer.URL
		return s
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	return NewWithTLSConfig(tlsConfig)
}

// NewWithTLSConfig creates a test server with custom TLS config
func NewWithTLSConfig(tlsConfig *tls.Config) *Server {
	s := &Server{
		DetectTLSFingerprint:  true,
		DetectHTTPFingerprint: true,
		StrictHeaders:         false,
		ResponseStatus:        200,
		ResponseBody:          `{"status": "ok", "message": "Test server response"}`,
		ResponseHeaders:       map[string]string{"Content-Type": "application/json"},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRequest)
	mux.HandleFunc("/detect", s.handleDetect)
	mux.HandleFunc("/fingerprint", s.handleFingerprint)
	mux.HandleFunc("/headers", s.handleHeaders)
	mux.HandleFunc("/tls", s.handleTLS)

	// If TLS config provided, start TLS server
	if tlsConfig != nil && len(tlsConfig.Certificates) > 0 {
		tlsServer := httptest.NewUnstartedServer(mux)
		tlsServer.TLS = tlsConfig
		tlsServer.StartTLS()
		s.Server = tlsServer
		s.URL = s.Server.URL
	} else {
		// Fall back to non-TLS server
		s.Server = httptest.NewServer(mux)
		s.URL = s.Server.URL
	}

	return s
}

// NewWithConfig creates a server with custom configuration
func NewWithConfig(cfg *ServerConfig) *Server {
	if cfg == nil {
		cfg = &ServerConfig{}
	}

	server := &Server{
		DetectTLSFingerprint:  cfg.DetectTLSFingerprint,
		DetectHTTPFingerprint: cfg.DetectHTTPFingerprint,
		StrictHeaders:         cfg.StrictHeaders,
		ResponseStatus:        cfg.ResponseStatus,
		ResponseBody:          cfg.ResponseBody,
		ResponseHeaders:       cfg.ResponseHeaders,
	}

	// Set defaults if not specified
	if server.ResponseStatus == 0 {
		server.ResponseStatus = 200
	}
	if server.ResponseBody == "" {
		server.ResponseBody = `{"status": "ok", "message": "Test server response"}`
	}
	if server.ResponseHeaders == nil {
		server.ResponseHeaders = map[string]string{"Content-Type": "application/json"}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", server.handleRequest)
	mux.HandleFunc("/detect", server.handleDetect)
	mux.HandleFunc("/fingerprint", server.handleFingerprint)
	mux.HandleFunc("/headers", server.handleHeaders)
	mux.HandleFunc("/tls", server.handleTLS)

	if cfg.TLS {
		cert, _ := generateTestCert()
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		server.tlsConfig = tlsConfig
		tlsServer := httptest.NewUnstartedServer(mux)
		tlsServer.TLS = tlsConfig
		tlsServer.StartTLS()
		server.Server = tlsServer
	} else {
		server.Server = httptest.NewServer(mux)
	}

	server.URL = server.Server.URL

	return server
}

// ServerConfig for creating a test server
type ServerConfig struct {
	TLS                   bool
	DetectTLSFingerprint  bool
	DetectHTTPFingerprint bool
	StrictHeaders         bool
	ResponseStatus        int
	ResponseBody          string
	ResponseHeaders       map[string]string
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	requestInfo := s.captureRequest(r)

	// Store request
	s.RequestsMutex.Lock()
	s.Requests = append(s.Requests, requestInfo)
	s.RequestsMutex.Unlock()

	s.RequestCount.Add(1)

	// Send response
	for k, v := range s.ResponseHeaders {
		w.Header().Set(k, v)
	}
	w.WriteHeader(s.ResponseStatus)
	//nolint:gosec // Response is HTML-escaped and used for test server responses
	_, _ = w.Write([]byte(html.EscapeString(s.ResponseBody)))
}

func (s *Server) handleDetect(w http.ResponseWriter, r *http.Request) {
	requestInfo := s.captureRequest(r)
	result := s.AnalyzeRequest(requestInfo)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		http.Error(w, `{"error": "encode failed"}`, http.StatusInternalServerError)
	}
}

func (s *Server) handleFingerprint(w http.ResponseWriter, r *http.Request) {
	requestInfo := s.captureRequest(r)

	fingerprint := map[string]interface{}{
		"tls": requestInfo.TLS,
		"http": map[string]string{
			"user_agent":      r.Header.Get("User-Agent"),
			"accept":          r.Header.Get("Accept"),
			"accept_language": r.Header.Get("Accept-Language"),
			"sec_ch_ua":       r.Header.Get("Sec-Ch-Ua"),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(fingerprint); err != nil {
		http.Error(w, `{"error": "encode failed"}`, http.StatusInternalServerError)
	}
}

func (s *Server) handleTLS(w http.ResponseWriter, r *http.Request) {
	requestInfo := s.captureRequest(r)

	// Store request
	s.RequestsMutex.Lock()
	s.Requests = append(s.Requests, requestInfo)
	s.RequestsMutex.Unlock()
	s.RequestCount.Add(1)

	w.Header().Set("Content-Type", "application/json")
	if requestInfo.TLS != nil {
		if err := json.NewEncoder(w).Encode(requestInfo.TLS); err != nil {
			http.Error(w, `{"error": "encode failed"}`, http.StatusInternalServerError)
		}
	} else {
		if err := json.NewEncoder(w).Encode(map[string]string{"error": "not a TLS connection"}); err != nil {
			http.Error(w, `{"error": "encode failed"}`, http.StatusInternalServerError)
		}
	}
}

func (s *Server) handleHeaders(w http.ResponseWriter, r *http.Request) {
	requestInfo := s.captureRequest(r)

	// Store request
	s.RequestsMutex.Lock()
	s.Requests = append(s.Requests, requestInfo)
	s.RequestsMutex.Unlock()
	s.RequestCount.Add(1)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(r.Header); err != nil {
		http.Error(w, `{"error": "encode failed"}`, http.StatusInternalServerError)
	}
}

func (s *Server) captureRequest(r *http.Request) RequestInfo {
	info := RequestInfo{
		Timestamp:  time.Now(),
		Method:     r.Method,
		URL:        r.URL.String(),
		Headers:    make(map[string]string),
		RemoteAddr: r.RemoteAddr,
	}

	// Capture headers
	for k, v := range r.Header {
		if len(v) > 0 {
			info.Headers[k] = v[0]
		}
	}

	// Capture TLS info
	if r.TLS != nil {
		info.TLS = s.captureTLSInfo(r.TLS)
	}

	return info
}

func (s *Server) captureTLSInfo(tlsConn *tls.ConnectionState) *TLSInfo {
	info := &TLSInfo{
		Version:         fmt.Sprintf("0x%04x", tlsConn.Version),
		CipherSuite:     fmt.Sprintf("0x%04x", tlsConn.CipherSuite),
		ServerName:      tlsConn.ServerName,
		NegotiatedProto: tlsConn.NegotiatedProtocol,
	}

	// Calculate JA3
	info.JA3 = calculateJA3(tlsConn)

	// Calculate JA4
	info.JA4 = calculateJA4(tlsConn)

	// Certificate fingerprint
	if len(tlsConn.PeerCertificates) > 0 {
		cert := tlsConn.PeerCertificates[0]
		info.CertFingerprint = base64.StdEncoding.EncodeToString(cert.Raw)
	}

	return info
}

func calculateJA3(tlsConn *tls.ConnectionState) string {
	// Simplified JA3 - real implementation would capture all ciphers and extensions
	return fmt.Sprintf("771,%04x,0-1-5-10-11-13-16-23-35-43-45-51,0-10-11-12-13-14-15-16-17-18-19-20-21-22-23-24-25-27-28-29-30-31-32-33-34-35-36-37-38-39-40-41-42-43-44-45-46-47-48-49-50-51-52-53-54-55-56-57-58-59-60-61-62-63-64-65-66-67-68-69-70-71-72-73-74-75-76-77-78-79-80-81-82-83-84-85-86-87-88-89-90-91-92-93-94-95-96-97-98-99-100-101-102-103-104-105-106-107-108-109-110-111-112-113-114-115-116-117-118-119-120-121-122-123-124-125-126-127-128-129-130-131-132-133-134-135-136-137-138-139-140-141-142-143-144-145-146-147-148-149-150-151-152-153-154-155-156-157-158-159-160-161-162-163-164-165-166-167-168-169-170-171-172-173-174-175-176-177-178-179-180-181-182-183-184-185-186-187-188-189-190-191-192-193-194-195-196-197-198-199-200-201-202-203-204-205-206-207-208-209-210-211-212-213-214-215-216-217-218-219-220-221-222-223-224-225-226-227-228-229-230-231-232-233-234-235-236-237-238-239-240-241-242-243-244-245-246-247-248-249-250-251-252-253-254-255", tlsConn.CipherSuite)
}

func calculateJA4(tlsConn *tls.ConnectionState) string {
	ver := "12"
	if tlsConn.Version >= 0x0304 {
		ver = "13"
	}

	alpnStr := "_"
	if tlsConn.NegotiatedProtocol != "" {
		alpnStr = "h2"
	}

	return fmt.Sprintf("t%s%s_%04x", ver, alpnStr, tlsConn.CipherSuite)
}

// AnalyzeRequest performs detection analysis on a request
func (s *Server) AnalyzeRequest(req RequestInfo) *DetectionResult {
	result := &DetectionResult{
		Request:          req,
		DetectionVectors: []VectorResult{},
		Indicators:       []Indicator{},
	}

	// TLS Fingerprint Detection
	if s.DetectTLSFingerprint && req.TLS != nil {
		vector := s.detectTLSFingerprint(req.TLS)
		result.DetectionVectors = append(result.DetectionVectors, vector)
		if vector.Detected {
			result.Score += vector.Score
			result.Indicators = append(result.Indicators, vector.Indicators...)
		}
	}

	// HTTP Fingerprint Detection
	if s.DetectHTTPFingerprint {
		vector := s.detectHTTPFingerprint(req.Headers)
		result.DetectionVectors = append(result.DetectionVectors, vector)
		if vector.Detected {
			result.Score += vector.Score
			result.Indicators = append(result.Indicators, vector.Indicators...)
		}
	}

	result.IsBot = result.Score >= 0.5

	return result
}

func (s *Server) detectTLSFingerprint(tls *TLSInfo) VectorResult {
	vector := VectorResult{Vector: "TLS Fingerprint"}

	// Check for Go TLS fingerprint (unique cipher suite)
	switch tls.CipherSuite {
	case "1301", "1302", "1303":
		// Modern TLS 1.3 ciphers are OK
	case "002f", "0035":
		// Older ciphers might be suspicious
		vector.Indicators = append(vector.Indicators, Indicator{
			Name:     "unusual_cipher",
			Category: "tls",
			Message:  fmt.Sprintf("Unusual cipher suite: %s", tls.CipherSuite),
			Severity: "low",
		})
	}

	// Check for missing SNI
	if tls.ServerName == "" {
		vector.Indicators = append(vector.Indicators, Indicator{
			Name:     "no_sni",
			Category: "tls",
			Message:  "Missing SNI",
			Severity: "medium",
		})
		vector.Detected = true
		vector.Score += 0.3
	}

	// Check for missing ALPN
	if tls.NegotiatedProto == "" {
		vector.Indicators = append(vector.Indicators, Indicator{
			Name:     "no_alpn",
			Category: "tls",
			Message:  "No ALPN protocol negotiated",
			Severity: "low",
		})
	}

	return vector
}

func (s *Server) detectHTTPFingerprint(headers map[string]string) VectorResult {
	vector := VectorResult{Vector: "HTTP Fingerprint"}

	// Check User-Agent
	ua := headers["User-Agent"]
	if ua == "" {
		vector.Indicators = append(vector.Indicators, Indicator{
			Name:     "missing_user_agent",
			Category: "http",
			Message:  "Missing User-Agent header",
			Severity: "high",
		})
		vector.Detected = true
		vector.Score += 0.4
	} else if contains(ua, []string{"python", "curl", "wget", "scrapy", "bot", "go-http"}) {
		vector.Indicators = append(vector.Indicators, Indicator{
			Name:     "suspicious_user_agent",
			Category: "http",
			Message:  fmt.Sprintf("Suspicious User-Agent: %s", ua),
			Severity: "critical",
		})
		vector.Detected = true
		vector.Score += 0.6
	}

	// Check Accept header
	if headers["Accept"] == "" {
		vector.Indicators = append(vector.Indicators, Indicator{
			Name:     "missing_accept",
			Category: "http",
			Message:  "Missing Accept header",
			Severity: "medium",
		})
		vector.Detected = true
		vector.Score += 0.2
	}

	// Check Accept-Language
	if headers["Accept-Language"] == "" {
		vector.Indicators = append(vector.Indicators, Indicator{
			Name:     "missing_accept_language",
			Category: "http",
			Message:  "Missing Accept-Language header",
			Severity: "medium",
		})
		vector.Detected = true
		vector.Score += 0.2
	}

	// Check Client Hints (Chrome)
	if headers["Sec-Ch-Ua"] == "" && s.StrictHeaders {
		vector.Indicators = append(vector.Indicators, Indicator{
			Name:     "missing_client_hints",
			Category: "http",
			Message:  "Missing Client Hints (Sec-Ch-Ua)",
			Severity: "high",
		})
		vector.Detected = true
		vector.Score += 0.3
	}

	// Check Sec-Fetch headers
	if headers["Sec-Fetch-Dest"] == "" && s.StrictHeaders {
		vector.Indicators = append(vector.Indicators, Indicator{
			Name:     "missing_sec_fetch",
			Category: "http",
			Message:  "Missing Sec-Fetch headers",
			Severity: "medium",
		})
		vector.Detected = true
		vector.Score += 0.2
	}

	return vector
}

// GetLastRequest returns the most recent request
func (s *Server) GetLastRequest() *RequestInfo {
	s.RequestsMutex.RLock()
	defer s.RequestsMutex.RUnlock()

	if len(s.Requests) == 0 {
		return nil
	}
	return &s.Requests[len(s.Requests)-1]
}

// GetRequests returns all captured requests
func (s *Server) GetRequests() []RequestInfo {
	s.RequestsMutex.RLock()
	defer s.RequestsMutex.RUnlock()

	result := make([]RequestInfo, len(s.Requests))
	copy(result, s.Requests)
	return result
}

// ClearRequests clears captured requests
func (s *Server) ClearRequests() {
	s.RequestsMutex.Lock()
	defer s.RequestsMutex.Unlock()
	s.Requests = nil
}

// GetTLSConfig returns the TLS configuration for making TLS connections
func (s *Server) GetTLSConfig() *tls.Config {
	if s.tlsConfig != nil {
		return s.tlsConfig
	}
	return &tls.Config{
		//nolint:gosec // InsecureSkipVerify required for test server
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
}

// Client returns an HTTP client configured to use this test server
func (s *Server) Client() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: s.GetTLSConfig(),
		},
	}
}

// TLSClient returns a uTLS connection for testing TLS fingerprints
func (s *Server) TLSClient(fingerprint utls.ClientHelloID) *utls.UConn {
	// Parse host from URL
	host := s.Server.Listener.Addr().String()

	conn, err := net.Dial("tcp", host)
	if err != nil {
		return nil
	}

	uconn := utls.UClient(conn, &utls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
	}, fingerprint)

	if err := uconn.Handshake(); err != nil {
		_ = conn.Close()
		return nil
	}

	return uconn
}

// GenerateTestCertificates generates test certificates for TLS testing
func generateTestCert() (tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	publicKey := privateKey.Public()

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pemEncode(certDER)
	keyPEM := pemEncode(x509.MarshalPKCS1PrivateKey(privateKey))

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}

	return cert, nil
}

func pemEncode(data []byte) []byte {
	return []byte(fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s-----END CERTIFICATE-----",
		base64.StdEncoding.EncodeToString(data)))
}

func contains(s string, substrings []string) bool {
	lower := s
	for _, sub := range substrings {
		if len(lower) >= len(sub) {
			for i := 0; i <= len(lower)-len(sub); i++ {
				if lower[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

// Start creates and starts the server in the background
func (s *Server) Start() {
	// Server is already started via New*
}

// Stop stops the server
func (s *Server) Stop() {
	s.Close()
}

// WithTLS creates a copy of the server with TLS enabled
func (s *Server) WithTLS() *Server {
	newServer := NewWithTLS()
	return newServer
}

// Clone creates a copy of the server with fresh state
func (s *Server) Clone() *Server {
	return NewWithConfig(&ServerConfig{
		TLS:                   s.tlsConfig != nil,
		DetectTLSFingerprint:  s.DetectTLSFingerprint,
		DetectHTTPFingerprint: s.DetectHTTPFingerprint,
		StrictHeaders:         s.StrictHeaders,
		ResponseStatus:        s.ResponseStatus,
		ResponseBody:          s.ResponseBody,
		ResponseHeaders:       s.ResponseHeaders,
	})
}

// TLSConfigWithCA returns a TLS client config that trusts the server's cert
// This allows making requests to self-signed TLS servers
func (s *Server) TLSConfigWithCA() *tls.Config {
	if s.tlsConfig != nil && len(s.tlsConfig.Certificates) > 0 {
		// Get the cert from the server's TLS config
		cert := s.tlsConfig.Certificates[0]

		// Create a cert pool and add the server's cert
		certPool := x509.NewCertPool()
		if len(cert.Certificate) > 0 {
			certPool.AppendCertsFromPEM(cert.Certificate[0])
		}

		return &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    certPool,
			ServerName: "localhost",
		}
	}

	// Fallback: just skip verification (not recommended for production)
	return &tls.Config{
		//nolint:gosec // InsecureSkipVerify fallback for test server
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
}
