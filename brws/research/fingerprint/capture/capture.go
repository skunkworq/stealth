// Package lab provides comprehensive fingerprint capture capabilities
// for analyzing and reproducing browser signatures at all layers.
package capture

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/skunkworq/stealth/brws/core/types"
)

// CompleteFingerprint captures all layers of browser signature
type CompleteFingerprint struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	SourceIP   string    `json:"source_ip"`
	ServerName string    `json:"server_name,omitempty"` // SNI from ClientHello

	// All layers
	TLS      *TLSFingerprint          `json:"tls"`
	HTTP2    *HTTP2Fingerprint        `json:"http2,omitempty"`
	HTTP     *HTTPFingerprint         `json:"http"`
	HTTPResp *HTTPResponseFingerprint `json:"http_response,omitempty"`
	Behavior *BehaviorFingerprint     `json:"behavior"`
}

// TLSFingerprint captures TLS ClientHello details
type TLSFingerprint = types.TLSFingerprint

// CipherInfo with position
type CipherInfo = types.CipherInfo

// ExtensionInfo with position
type ExtensionInfo = types.ExtensionInfo

// GREASEInfo tracks GREASE positions
type GREASEInfo = types.GREASEInfo

// HTTP2Fingerprint captures HTTP/2-specific signals
type HTTP2Fingerprint = types.HTTP2Fingerprint

// HTTP2Setting with position
type HTTP2Setting = types.HTTP2Setting

// WindowUpdateInfo captures WINDOW_UPDATE frames
type WindowUpdateInfo = types.WindowUpdateInfo

// FrameInfo for sequence analysis
type FrameInfo = types.FrameInfo

// StreamPriority info
type StreamPriority = types.StreamPriority

// HTTPFingerprint captures HTTP-layer signals
type HTTPFingerprint = types.HTTPFingerprint

// HTTPResponseFingerprint captures HTTP responses
type HTTPResponseFingerprint = types.HTTPResponseFingerprint

// HeaderInfo preserves order
type HeaderInfo = types.HeaderInfo

// ClientHints for Chrome
type ClientHints = types.ClientHints

// BehaviorFingerprint captures timing and patterns
type BehaviorFingerprint = types.BehaviorFingerprint

// ConnectionTiming details
type ConnectionTiming = types.ConnectionTiming

// RequestPattern analysis
type RequestPattern = types.RequestPattern

// CaptureServer holds capture state
type CaptureServer struct {
	mu            sync.RWMutex
	captures      map[string]*CompleteFingerprint
	proxyCaptures map[string]*CompleteFingerprint // Only proxy-intercepted captures
	baselines     map[string]*CompleteFingerprint

	// Capture configuration
	CaptureRawBytes bool
	CaptureTiming   bool
}

// NewCaptureServer creates a new fingerprint capture server
func NewCaptureServer() *CaptureServer {
	return &CaptureServer{
		captures:        make(map[string]*CompleteFingerprint),
		proxyCaptures:   make(map[string]*CompleteFingerprint),
		baselines:       make(map[string]*CompleteFingerprint),
		CaptureRawBytes: true,
		CaptureTiming:   true,
	}
}

// CaptureFromRequest captures fingerprint from an HTTP request
func (s *CaptureServer) CaptureFromRequest(_ http.ResponseWriter, r *http.Request) *CompleteFingerprint {
	fp := &CompleteFingerprint{
		ID:        generateID(),
		Timestamp: time.Now(),
		SourceIP:  getClientIP(r),
	}

	// Capture HTTP layer
	fp.HTTP = s.captureHTTP(r)

	// Capture TLS info - first check if we have raw capture
	if r.TLS != nil {
		// Try to get pre-captured fingerprint from connection
		if captured := GetTLSCapture(r.RemoteAddr); captured != nil {
			fp.TLS = captured.TLS
		} else {
			// Fall back to state-based capture
			fp.TLS = s.captureTLSFromState(r.TLS)
		}
	}

	// Detect HTTP/2
	if r.ProtoMajor == 2 {
		fp.HTTP2 = s.inferHTTP2FromRequest(r)
	}

	// Store capture
	s.mu.Lock()
	s.captures[fp.ID] = fp
	s.mu.Unlock()

	return fp
}

// captureHTTP extracts HTTP fingerprint
func (s *CaptureServer) captureHTTP(r *http.Request) *HTTPFingerprint {
	h := &HTTPFingerprint{
		Method:   r.Method,
		Path:     r.URL.Path,
		Protocol: r.Proto,
	}

	// Capture headers in order
	pos := 1
	for name, values := range r.Header {
		for _, value := range values {
			h.Headers = append(h.Headers, HeaderInfo{
				Name:     name,
				Value:    value,
				Position: pos,
				IsPseudo: strings.HasPrefix(name, ":"),
			})
			pos++
		}

		// Extract specific headers
		switch name {
		case "User-Agent":
			h.UserAgent = values[0]
		case "Accept":
			h.Accept = values[0]
		case "Accept-Language":
			h.AcceptLang = values[0]
		case "Accept-Encoding":
			h.AcceptEnc = values[0]
		}
	}

	// Capture Client Hints (Chrome-specific)
	h.ClientHints = &ClientHints{
		SecCHUA:         r.Header.Get("Sec-Ch-Ua"),
		SecCHUAMobile:   r.Header.Get("Sec-Ch-Ua-Mobile"),
		SecCHUAPlatform: r.Header.Get("Sec-Ch-Ua-Platform"),
	}
	if h.ClientHints.SecCHUA == "" {
		h.ClientHints = nil
	}

	// Cookie count
	h.CookieCount = len(r.Cookies())

	return h
}

// captureTLSFromState extracts TLS info from connection state
func (s *CaptureServer) captureTLSFromState(state *tls.ConnectionState) *TLSFingerprint {
	t := &TLSFingerprint{
		Version:     state.Version,
		VersionName: tlsVersionName(state.Version),
	}

	// Note: Go's standard library doesn't expose full ClientHello
	// For complete capture, we'd need raw packet capture or uTLS
	// This is a partial capture from the connection state

	// Cipher suite
	cipherName := tls.CipherSuiteName(state.CipherSuite)
	t.CipherSuites = []CipherInfo{
		{
			Value:    state.CipherSuite,
			Name:     cipherName,
			Position: 1,
		},
	}

	// Negotiated protocol (ALPN)
	if state.NegotiatedProtocol != "" {
		t.ALPN = []string{state.NegotiatedProtocol}
	}

	// Server name
	if state.ServerName != "" {
		t.Extensions = append(t.Extensions, ExtensionInfo{
			Type:     0, // server_name
			Name:     "server_name",
			Position: 1,
			Data:     []byte(state.ServerName),
		})
	}

	// Calculate JA3 from available info (simplified)
	t.JA3String = s.calculateJA3(t)
	t.JA3Hash = hashString(t.JA3String)

	return t
}

// inferHTTP2FromRequest infers HTTP/2 behavior from request
func (s *CaptureServer) inferHTTP2FromRequest(r *http.Request) *HTTP2Fingerprint {
	h2 := &HTTP2Fingerprint{}

	// Default Chrome SETTINGS
	h2.Settings = []HTTP2Setting{
		{ID: 1, Name: "HEADER_TABLE_SIZE", Value: 65536, Position: 1},
		{ID: 2, Name: "ENABLE_PUSH", Value: 0, Position: 2},
		{ID: 3, Name: "MAX_CONCURRENT_STREAMS", Value: 1000, Position: 3},
		{ID: 4, Name: "INITIAL_WINDOW_SIZE", Value: 6291456, Position: 4},
	}

	// Pseudo-header order from request
	h2.PseudoHeaders = []string{
		":method",
		":authority",
		":scheme",
		":path",
	}

	// Extract header order
	for _, h := range []string{
		":method",
		":authority",
		":scheme",
		":path",
		"user-agent",
		"accept",
		"accept-encoding",
		"accept-language",
	} {
		if r.Header.Get(h) != "" || h == ":method" {
			h2.HeaderOrder = append(h2.HeaderOrder, h)
		}
	}

	return h2
}

// calculateJA3 computes JA3 from captured TLS info
func (s *CaptureServer) calculateJA3(t *TLSFingerprint) string {
	var parts []string

	// SSLVersion
	parts = append(parts, fmt.Sprintf("%d", t.Version))

	// Cipher suites
	var ciphers []string
	for _, c := range t.CipherSuites {
		if !c.IsGREASE {
			ciphers = append(ciphers, fmt.Sprintf("%d", c.Value))
		}
	}
	parts = append(parts, strings.Join(ciphers, "-"))

	// Extensions (we have limited info here)
	var exts []string
	for _, e := range t.Extensions {
		if !e.IsGREASE {
			exts = append(exts, fmt.Sprintf("%d", e.Type))
		}
	}
	parts = append(parts, strings.Join(exts, "-"))

	// Elliptic curves (from supported groups)
	var groups []string
	for _, g := range t.SupportedGroups {
		groups = append(groups, fmt.Sprintf("%d", g))
	}
	parts = append(parts, strings.Join(groups, "-"))

	// EC point formats (default)
	parts = append(parts, "0") // uncompressed

	return strings.Join(parts, ",")
}

// calculateJA4 computes JA4 fingerprint (currently unused but kept for future use)
//
//nolint:unused
func (s *CaptureServer) calculateJA4(t *TLSFingerprint) string {
	// JA4 format: t[protocol][version][SNI][cipher_count][ext_count][ALPN]_[cipher_hash]_[ext_hash]
	// Example: t13d1516h2_8daaf6152771_02713d6af862

	// Protocol: 't' for TLS
	proto := "t"

	// Version: 13 for TLS 1.3, 12 for TLS 1.2
	version := "12"
	if t.Version == tls.VersionTLS13 {
		version = "13"
	}

	// SNI: 'd' for domain, 'i' for IP
	sni := "d"

	// Cipher count (excluding GREASE)
	cipherCount := 0
	for _, c := range t.CipherSuites {
		if !c.IsGREASE {
			cipherCount++
		}
	}

	// Extension count (excluding GREASE)
	extCount := 0
	for _, e := range t.Extensions {
		if !e.IsGREASE {
			extCount++
		}
	}

	// ALPN first value
	alpn := "00"
	if len(t.ALPN) > 0 {
		alpn = t.ALPN[0]
		if len(alpn) > 2 {
			alpn = alpn[:2]
		}
	}

	// Build first part
	ja4 := fmt.Sprintf("%s%s%s%02d%02d%s", proto, version, sni, cipherCount, extCount, alpn)

	// Cipher hash (truncated SHA256 of sorted cipher list)
	var cipherList []string
	for _, c := range t.CipherSuites {
		if !c.IsGREASE {
			cipherList = append(cipherList, fmt.Sprintf("%04x", c.Value))
		}
	}
	sort.Strings(cipherList)
	cipherHash := hashStringTruncated(strings.Join(cipherList, ","), 12)

	// Extension hash
	var extList []string
	for _, e := range t.Extensions {
		if !e.IsGREASE {
			extList = append(extList, fmt.Sprintf("%d", e.Type))
		}
	}
	sort.Strings(extList)
	extHash := hashStringTruncated(strings.Join(extList, ","), 12)

	return fmt.Sprintf("%s_%s_%s", ja4, cipherHash, extHash)
}

// StoreCapture saves a captured fingerprint
func (s *CaptureServer) StoreCapture(id string, fp *CompleteFingerprint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.captures[id] = fp
}

// StoreCaptureTypes saves a captured fingerprint from types package (proxy captures)
func (s *CaptureServer) StoreCaptureTypes(id string, fp *types.CompleteFingerprint) {
	converted := convertFromTypesFingerprint(fp)
	s.StoreCapture(id, converted)
	// Also store in proxy-only captures for the list endpoint
	s.mu.Lock()
	s.proxyCaptures[id] = converted
	s.mu.Unlock()
}

// GetCapture retrieves a captured fingerprint
func (s *CaptureServer) GetCapture(id string) (*CompleteFingerprint, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	fp, ok := s.captures[id]
	return fp, ok
}

// CaptureSummary for list view
type CaptureSummary struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	SourceIP    string    `json:"source_ip"`
	Host        string    `json:"host"`
	JA3Hash     string    `json:"ja3_hash"`
	JA4         string    `json:"ja4,omitempty"`
	CipherCount int       `json:"cipher_count"`
	ExtCount    int       `json:"ext_count"`
	ALPN        []string  `json:"alpn,omitempty"`
	Protocol    string    `json:"protocol"`
	StatusCode  int       `json:"status_code,omitempty"`
}

// ListCaptures returns recent proxy captures sorted by timestamp (newest first)
func (s *CaptureServer) ListCaptures(limit int, query string) []*CaptureSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()

	q := strings.ToLower(query)

	summaries := make([]*CaptureSummary, 0, len(s.proxyCaptures))
	for _, fp := range s.proxyCaptures {
		summary := &CaptureSummary{
			ID:        fp.ID,
			Timestamp: fp.Timestamp,
			SourceIP:  fp.SourceIP,
			Protocol:  "HTTP/1.1",
		}
		if fp.HTTPResp != nil {
			summary.StatusCode = fp.HTTPResp.StatusCode
		}
		// Use ServerName from fingerprint (SNI)
		if fp.ServerName != "" {
			summary.Host = fp.ServerName
		}
		if fp.TLS != nil {
			summary.JA3Hash = fp.TLS.JA3Hash
			summary.JA4 = fp.TLS.JA4
			summary.CipherCount = len(fp.TLS.CipherSuites)
			summary.ExtCount = len(fp.TLS.Extensions)
			summary.ALPN = fp.TLS.ALPN
			if len(fp.TLS.ALPN) > 0 {
				summary.Protocol = fp.TLS.ALPN[0]
			}
			// Fallback: Extract SNI from extensions if not already set
			if summary.Host == "" {
				for _, ext := range fp.TLS.Extensions {
					if ext.Name == "server_name" || ext.Type == 0 {
						if len(ext.Data) > 5 {
							summary.Host = string(ext.Data[5:])
						}
					}
				}
			}
		}
		if fp.HTTP != nil && summary.Host == "" {
			for _, h := range fp.HTTP.Headers {
				if h.Name == "Host" {
					summary.Host = h.Value
					break
				}
			}
		}

		if q != "" {
			if !strings.Contains(strings.ToLower(summary.Host), q) &&
				!strings.Contains(strings.ToLower(summary.SourceIP), q) &&
				!strings.Contains(strings.ToLower(summary.JA3Hash), q) &&
				!strings.Contains(strings.ToLower(summary.JA4), q) &&
				!strings.Contains(strings.ToLower(summary.Protocol), q) {
				continue
			}
		}

		summaries = append(summaries, summary)
	}

	// Sort by timestamp descending
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Timestamp.After(summaries[j].Timestamp)
	})

	// Apply limit
	if limit > 0 && len(summaries) > limit {
		summaries = summaries[:limit]
	}

	return summaries
}

// StoreBaseline saves a fingerprint as baseline
func (s *CaptureServer) StoreBaseline(name string, fp *CompleteFingerprint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.baselines[name] = fp
}

// GetBaseline retrieves a stored baseline
func (s *CaptureServer) GetBaseline(name string) (*CompleteFingerprint, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	fp, ok := s.baselines[name]
	return fp, ok
}

// CompareFingerprints generates a detailed diff
func CompareFingerprints(baseline, test *CompleteFingerprint) *FingerprintDiff {
	diff := &FingerprintDiff{
		BaselineID: baseline.ID,
		TestID:     test.ID,
	}

	// Compare TLS
	if baseline.TLS != nil && test.TLS != nil {
		diff.TLSMatch = (baseline.TLS.JA3Hash == test.TLS.JA3Hash)
		diff.JA3Match = baseline.TLS.JA3Hash == test.TLS.JA3Hash
		diff.JA4Match = baseline.TLS.JA4 == test.TLS.JA4

		// Detailed comparison
		if !diff.TLSMatch {
			diff.TLSDifferences = compareTLS(baseline.TLS, test.TLS)
		}
	}

	// Compare HTTP/2
	if baseline.HTTP2 != nil && test.HTTP2 != nil {
		diff.HTTP2Match = compareHTTP2Equal(baseline.HTTP2, test.HTTP2)
		if !diff.HTTP2Match {
			diff.HTTP2Differences = compareHTTP2(baseline.HTTP2, test.HTTP2)
		}
	}

	// Compare HTTP
	if baseline.HTTP != nil && test.HTTP != nil {
		diff.HTTPMatch = compareHTTPEqual(baseline.HTTP, test.HTTP)
		if !diff.HTTPMatch {
			diff.HTTPDifferences = compareHTTP(baseline.HTTP, test.HTTP)
		}
	}

	// Calculate overall similarity
	diff.Similarity = calculateSimilarity(diff)

	return diff
}

// FingerprintDiff contains comparison results
type FingerprintDiff struct {
	BaselineID       string       `json:"baseline_id"`
	TestID           string       `json:"test_id"`
	TLSMatch         bool         `json:"tls_match"`
	JA3Match         bool         `json:"ja3_match"`
	JA4Match         bool         `json:"ja4_match"`
	HTTP2Match       bool         `json:"http2_match"`
	HTTPMatch        bool         `json:"http_match"`
	Similarity       float64      `json:"similarity"`
	TLSDifferences   []Difference `json:"tls_differences,omitempty"`
	HTTP2Differences []Difference `json:"http2_differences,omitempty"`
	HTTPDifferences  []Difference `json:"http_differences,omitempty"`
}

// Difference represents a single difference
type Difference struct {
	Field    string      `json:"field"`
	Expected interface{} `json:"expected"`
	Actual   interface{} `json:"actual"`
	Severity string      `json:"severity"` // critical, warning, info
}

// compareTLS compares two TLS fingerprints
func compareTLS(baseline, test *TLSFingerprint) []Difference {
	var diffs []Difference

	// Compare cipher suites
	if !cipherListsEqual(baseline.CipherSuites, test.CipherSuites) {
		diffs = append(diffs, Difference{
			Field:    "cipher_suites",
			Expected: cipherNames(baseline.CipherSuites),
			Actual:   cipherNames(test.CipherSuites),
			Severity: "critical",
		})
	}

	// Compare extensions
	if !extensionListsEqual(baseline.Extensions, test.Extensions) {
		diffs = append(diffs, Difference{
			Field:    "extensions",
			Expected: extensionNames(baseline.Extensions),
			Actual:   extensionNames(test.Extensions),
			Severity: "critical",
		})
	}

	// Compare ALPN
	if !stringSlicesEqual(baseline.ALPN, test.ALPN) {
		diffs = append(diffs, Difference{
			Field:    "alpn",
			Expected: baseline.ALPN,
			Actual:   test.ALPN,
			Severity: "warning",
		})
	}

	return diffs
}

// compareHTTP2 compares HTTP/2 fingerprints
func compareHTTP2(baseline, test *HTTP2Fingerprint) []Difference {
	var diffs []Difference

	// Compare SETTINGS
	if !settingsEqual(baseline.Settings, test.Settings) {
		diffs = append(diffs, Difference{
			Field:    "settings",
			Expected: baseline.Settings,
			Actual:   test.Settings,
			Severity: "critical",
		})
	}

	// Compare pseudo-header order
	if !stringSlicesEqual(baseline.PseudoHeaders, test.PseudoHeaders) {
		diffs = append(diffs, Difference{
			Field:    "pseudo_headers",
			Expected: baseline.PseudoHeaders,
			Actual:   test.PseudoHeaders,
			Severity: "critical",
		})
	}

	return diffs
}

// compareHTTP compares HTTP fingerprints
func compareHTTP(baseline, test *HTTPFingerprint) []Difference {
	var diffs []Difference

	// Compare User-Agent
	if baseline.UserAgent != test.UserAgent {
		diffs = append(diffs, Difference{
			Field:    "user_agent",
			Expected: baseline.UserAgent,
			Actual:   test.UserAgent,
			Severity: "warning",
		})
	}

	// Compare header order
	baselineOrder := headerNames(baseline.Headers)
	testOrder := headerNames(test.Headers)
	if !stringSlicesEqual(baselineOrder, testOrder) {
		diffs = append(diffs, Difference{
			Field:    "header_order",
			Expected: baselineOrder,
			Actual:   testOrder,
			Severity: "warning",
		})
	}

	return diffs
}

// Helper functions

func generateID() string {
	return fmt.Sprintf("fp-%d", time.Now().UnixNano())
}

func getClientIP(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.Header.Get("X-Real-Ip")
	}
	if ip == "" {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	return ip
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func hashString(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return fmt.Sprintf("%x", h.Sum(nil))[:32]
}

//nolint:unused // Called by calculateJA4 which is kept for future use
func hashStringTruncated(s string, length int) string {
	h := sha256.New()
	h.Write([]byte(s))
	sum := fmt.Sprintf("%x", h.Sum(nil))
	if length > len(sum) {
		length = len(sum)
	}
	return sum[:length]
}

func cipherNames(ciphers []CipherInfo) []string {
	var names []string
	for _, c := range ciphers {
		names = append(names, c.Name)
	}
	return names
}

func extensionNames(exts []ExtensionInfo) []string {
	var names []string
	for _, e := range exts {
		names = append(names, e.Name)
	}
	return names
}

func headerNames(headers []HeaderInfo) []string {
	var names []string
	for _, h := range headers {
		names = append(names, h.Name)
	}
	return names
}

func cipherListsEqual(a, b []CipherInfo) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Value != b[i].Value {
			return false
		}
	}
	return true
}

func extensionListsEqual(a, b []ExtensionInfo) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Type != b[i].Type {
			return false
		}
	}
	return true
}

func settingsEqual(a, b []HTTP2Setting) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].Value != b[i].Value {
			return false
		}
	}
	return true
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func compareHTTP2Equal(a, b *HTTP2Fingerprint) bool {
	if a == nil || b == nil {
		return a == b
	}
	return settingsEqual(a.Settings, b.Settings) &&
		stringSlicesEqual(a.PseudoHeaders, b.PseudoHeaders)
}

func compareHTTPEqual(a, b *HTTPFingerprint) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.UserAgent == b.UserAgent
}

func calculateSimilarity(diff *FingerprintDiff) float64 {
	scores := []bool{diff.TLSMatch, diff.HTTP2Match, diff.HTTPMatch}
	matchCount := 0
	for _, s := range scores {
		if s {
			matchCount++
		}
	}
	return float64(matchCount) / float64(len(scores))
}

// ExportYAML exports fingerprint to YAML format for curl-impersonate compatibility
func (fp *CompleteFingerprint) ExportYAML() ([]byte, error) {
	// Convert to curl-impersonate signature format
	sig := map[string]interface{}{
		"name": fmt.Sprintf("captured_%s", fp.ID),
		"browser": map[string]string{
			"name":    "captured",
			"version": "1.0",
			"os":      "unknown",
		},
	}

	if fp.TLS != nil {
		sig["signature"] = map[string]interface{}{
			"tls_client_hello": fp.exportTLSSignature(),
		}
	}

	if fp.HTTP2 != nil {
		sig["http2"] = map[string]interface{}{
			"settings":       fp.HTTP2.Settings,
			"pseudo_headers": fp.HTTP2.PseudoHeaders,
		}
	}

	// Use JSON as intermediate (similar structure)
	return json.MarshalIndent(sig, "", "  ")
}

func (fp *CompleteFingerprint) exportTLSSignature() map[string]interface{} {
	if fp.TLS == nil {
		return nil
	}

	var ciphers []interface{}
	for _, c := range fp.TLS.CipherSuites {
		if c.IsGREASE {
			ciphers = append(ciphers, "GREASE")
		} else {
			ciphers = append(ciphers, fmt.Sprintf("0x%04x", c.Value))
		}
	}

	var extensions []map[string]interface{}
	for _, e := range fp.TLS.Extensions {
		ext := map[string]interface{}{
			"type": e.Name,
		}
		if e.IsGREASE {
			ext["type"] = "GREASE"
		}
		extensions = append(extensions, ext)
	}

	return map[string]interface{}{
		"ciphersuites": ciphers,
		"extensions":   extensions,
	}
}

// EnableRawPacketCapture enables raw packet capture for ClientHello analysis.
// This is a placeholder - actual implementation requires libpcap.
func (s *CaptureServer) EnableRawPacketCapture(_ string) error {
	// Implementation would use:
	// - github.com/google/gopacket
	// - github.com/google/gopacket/pcap
	// - Parse TLS records from captured packets
	return fmt.Errorf("raw packet capture not yet implemented")
}

// WriteJSON writes fingerprint as JSON
func (fp *CompleteFingerprint) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(fp)
}

// ReadJSON reads fingerprint from JSON
func (fp *CompleteFingerprint) ReadJSON(r io.Reader) error {
	return json.NewDecoder(r).Decode(fp)
}

// convertFromTypesFingerprint converts types.CompleteFingerprint to lab.CompleteFingerprint
func convertFromTypesFingerprint(fp *types.CompleteFingerprint) *CompleteFingerprint {
	if fp == nil {
		return nil
	}
	return &CompleteFingerprint{
		ID:         fp.ID,
		Timestamp:  fp.Timestamp,
		SourceIP:   fp.SourceIP,
		ServerName: fp.ServerName,
		TLS:        (*TLSFingerprint)(fp.TLS),
		HTTP2:      (*HTTP2Fingerprint)(fp.HTTP2),
		HTTP:       (*HTTPFingerprint)(fp.HTTP),
		HTTPResp:   (*HTTPResponseFingerprint)(fp.HTTPResp),
		Behavior:   (*BehaviorFingerprint)(fp.Behavior),
	}
}
