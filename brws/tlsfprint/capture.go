package tlsfprint

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// CompleteFingerprint represents a complete browser fingerprint including all protocols.
type CompleteFingerprint struct {
	TraceID         string            `json:"trace_id"`
	Timestamp       time.Time         `json:"timestamp"`
	TLS             *TLSFingerprint   `json:"tls,omitempty"`
	HTTP1           *HTTP1Fingerprint `json:"http1,omitempty"`
	HTTP2           *HTTP2Fingerprint `json:"http2,omitempty"`
	WebSocket       *WSFingerprint    `json:"websocket,omitempty"`
	Behavioral      *BehavioralPrint  `json:"behavioral,omitempty"`
	JA3             string            `json:"ja3,omitempty"`
	JA3H1           string            `json:"ja3h1,omitempty"`
	JA3H2           string            `json:"ja3h2,omitempty"`
	JA3W            string            `json:"ja3w,omitempty"`
	JA4             string            `json:"ja4,omitempty"`
	DetectedBrowser string            `json:"detected_browser"`
	Confidence      float64           `json:"confidence"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// TLSFingerprint represents a TLS handshake fingerprint.
type TLSFingerprint struct {
	Version          string   `json:"version"`
	CipherSuites     []uint16 `json:"cipher_suites"`
	CipherSuiteNames []string `json:"cipher_suite_names"`
	Extensions       []uint16 `json:"extensions"`
	ExtensionNames   []string `json:"extension_names"`
	SupportedGroups  []uint16 `json:"supported_groups"`
	SignatureAlgs    []uint16 `json:"signature_algorithms"`
	ALPN             []string `json:"alpn"`
	SNI              string   `json:"sni"`
	SessionID        string   `json:"session_id"`
	Random           string   `json:"random"`
	JA3              string   `json:"ja3"`
	JA4              string   `json:"ja4"`
	HasGREASE        bool     `json:"has_grease"`
	IsTLS13          bool     `json:"is_tls13"`
}

// WSFingerprint represents a WebSocket handshake fingerprint.
type WSFingerprint struct {
	Version         string   `json:"version"`
	SubProtocols    []string `json:"sub_protocols"`
	Extensions      []string `json:"extensions"`
	Origin          string   `json:"origin"`
	SecWebSocketKey string   `json:"sec_websocket_key"`
	JA3W            string   `json:"ja3w"`
}

// BehavioralPrint represents behavioral biometric fingerprint data.
type BehavioralPrint struct {
	MouseVariance  float64 `json:"mouse_variance"`
	TypingSpeed    float64 `json:"typing_speed"`
	ScrollVelocity float64 `json:"scroll_velocity"`
	CacheRatio     float64 `json:"cache_ratio"`
	IsHumanLike    bool    `json:"is_human_like"`
}

// FingerprintBuilder provides a fluent API for building fingerprints.
type FingerprintBuilder struct {
	fingerprint *CompleteFingerprint
}

// NewFingerprint creates a new fingerprint builder.
func NewFingerprint() *FingerprintBuilder {
	return &FingerprintBuilder{
		fingerprint: &CompleteFingerprint{
			Timestamp:       time.Now(),
			TraceID:         generateTraceID(),
			Metadata:        make(map[string]string),
			DetectedBrowser: "unknown",
			Confidence:      0.0,
		},
	}
}

// WithTLS adds TLS fingerprint data to the builder.
func (b *FingerprintBuilder) WithTLS(tls *TLSFingerprint) *FingerprintBuilder {
	b.fingerprint.TLS = tls
	if tls != nil {
		b.fingerprint.JA3 = tls.JA3
		b.fingerprint.JA4 = tls.JA4
	}
	return b
}

// WithHTTP1 adds HTTP/1.1 fingerprint data to the builder.
func (b *FingerprintBuilder) WithHTTP1(http1 *HTTP1Fingerprint) *FingerprintBuilder {
	b.fingerprint.HTTP1 = http1
	if http1 != nil {
		b.fingerprint.JA3H1 = http1.JA3H1
	}
	return b
}

// WithHTTP2 adds HTTP/2 fingerprint data to the builder.
func (b *FingerprintBuilder) WithHTTP2(http2 *HTTP2Fingerprint) *FingerprintBuilder {
	b.fingerprint.HTTP2 = http2
	if http2 != nil {
		b.fingerprint.JA3H2 = http2.JA3H2
	}
	return b
}

// WithWebSocket adds WebSocket fingerprint data to the builder.
func (b *FingerprintBuilder) WithWebSocket(ws *WSFingerprint) *FingerprintBuilder {
	b.fingerprint.WebSocket = ws
	if ws != nil {
		b.fingerprint.JA3W = ws.JA3W
	}
	return b
}

// WithBehavioral adds behavioral fingerprint data to the builder.
func (b *FingerprintBuilder) WithBehavioral(bh *BehavioralPrint) *FingerprintBuilder {
	b.fingerprint.Behavioral = bh
	return b
}

// WithMetadata adds metadata to the fingerprint.
func (b *FingerprintBuilder) WithMetadata(key, value string) *FingerprintBuilder {
	b.fingerprint.Metadata[key] = value
	return b
}

// WithDetectedBrowser sets the detected browser.
func (b *FingerprintBuilder) WithDetectedBrowser(browser string) *FingerprintBuilder {
	b.fingerprint.DetectedBrowser = browser
	return b
}

// WithConfidence sets the detection confidence.
func (b *FingerprintBuilder) WithConfidence(confidence float64) *FingerprintBuilder {
	b.fingerprint.Confidence = confidence
	return b
}

// Build returns the complete fingerprint.
func (b *FingerprintBuilder) Build() *CompleteFingerprint {
	b.detectBrowser()
	return b.fingerprint
}

func (b *FingerprintBuilder) detectBrowser() {
	scores := make(map[string]float64)

	if b.fingerprint.TLS != nil {
		browser := DetectBrowserFromJA4(b.fingerprint.TLS.JA4)
		if browser != "unknown" {
			scores[browser] += 0.4
		}
	}

	if b.fingerprint.HTTP1 != nil {
		browser := DetectBrowserFromHTTP1(map[string]string{
			"user-agent": b.fingerprint.HTTP1.Headers["user-agent"],
		})
		if browser != "unknown" {
			scores[browser] += 0.3
		}
	}

	if b.fingerprint.HTTP2 != nil {
		browser := DetectBrowserFromHTTP2(map[uint16]uint32{}, nil)
		if browser != "unknown" {
			scores[browser] += 0.2
		}
	}

	if b.fingerprint.WebSocket != nil {
		b.fingerprint.JA3W = b.fingerprint.WebSocket.JA3W
	}

	var maxScore float64
	for browser, score := range scores {
		if score > maxScore {
			maxScore = score
			b.fingerprint.DetectedBrowser = browser
		}
	}

	b.fingerprint.Confidence = maxScore
}

// FingerprintCapture captures and analyzes fingerprint data.
type FingerprintCapture struct {
	analyzer      *TLSAnalyzer
	http1Analyzer *HTTP1Analyzer
	http2Analyzer *HTTP2Analyzer
	wsAnalyzer    *WebSocketAnalyzer
}

// NewFingerprintCapture creates a new fingerprint capture instance.
func NewFingerprintCapture() *FingerprintCapture {
	return &FingerprintCapture{
		analyzer:      NewTLSAnalyzer(),
		http1Analyzer: NewHTTP1Analyzer(),
		http2Analyzer: NewHTTP2Analyzer(),
		wsAnalyzer:    NewWebSocketAnalyzer(),
	}
}

// CaptureTLS captures TLS fingerprint data from a ClientHello.
func (c *FingerprintCapture) CaptureTLS(clientHello interface{}) string {
	var traceID string

	switch ch := clientHello.(type) {
	case *ClientHelloInfo:
		traceID = c.analyzer.RecordClientHello(ch)
	case map[string]interface{}:
		info := &ClientHelloInfo{}
		if v, ok := ch["version"].(uint16); ok {
			info.Version = v
			info.VersionStr = VersionToString(v)
		}
		traceID = c.analyzer.RecordClientHello(info)
	}

	return traceID
}

// CaptureHTTP1 captures HTTP/1.1 fingerprint data from headers.
func (c *FingerprintCapture) CaptureHTTP1(headers map[string]string) {
	c.http1Analyzer.Record(headers)
}

// CaptureHTTP2 captures HTTP/2 fingerprint data from settings.
func (c *FingerprintCapture) CaptureHTTP2(settings map[uint16]uint32, pseudoHeaders []string) {
	c.http2Analyzer.Record(settings, pseudoHeaders, 65535, 16384)
}

// CaptureWebSocket captures WebSocket fingerprint data from headers.
func (c *FingerprintCapture) CaptureWebSocket(headers map[string]string) {
	c.wsAnalyzer.Record(headers)
}

func (c *FingerprintCapture) GetFingerprint() *CompleteFingerprint {
	fp := NewFingerprint().
		WithDetectedBrowser("unknown").
		WithConfidence(0.0).
		Build()

	if len(c.analyzer.handshakes) > 0 {
		lastHS := c.analyzer.handshakes[len(c.analyzer.handshakes)-1]
		if lastHS.ClientHello != nil {
			tlsFP := &TLSFingerprint{
				Version:      lastHS.ClientHello.VersionStr,
				CipherSuites: lastHS.ClientHello.CipherSuites,
				Extensions:   lastHS.ClientHello.ExtensionsList,
				SNI:          lastHS.ClientHello.SNI,
				JA3:          lastHS.ClientHello.JA3,
				JA4:          lastHS.ClientHello.JA4,
				IsTLS13:      lastHS.ClientHello.Version >= 0x0304,
			}
			fp.TLS = tlsFP
			fp.JA3 = tlsFP.JA3
			fp.JA4 = tlsFP.JA4
			fp.TraceID = lastHS.TraceID
		}
	}

	if len(c.http1Analyzer.observations) > 0 {
		lastHTTP1 := c.http1Analyzer.observations[len(c.http1Analyzer.observations)-1]
		http1FP := &HTTP1Fingerprint{
			Headers: lastHTTP1.Headers,
			JA3H1:   lastHTTP1.JA3H1,
		}
		fp.HTTP1 = http1FP
		fp.JA3H1 = http1FP.JA3H1
	}

	return fp
}

func (c *FingerprintCapture) GetTLSAnalyzer() *TLSAnalyzer {
	return c.analyzer
}

func (c *FingerprintCapture) GetHTTP1Analyzer() *HTTP1Analyzer {
	return c.http1Analyzer
}

func (c *FingerprintCapture) GetHTTP2Analyzer() *HTTP2Analyzer {
	return c.http2Analyzer
}

func (c *FingerprintCapture) GetWebSocketAnalyzer() *WebSocketAnalyzer {
	return c.wsAnalyzer
}

func (c *FingerprintCapture) Reset() {
	c.analyzer = NewTLSAnalyzer()
	c.http1Analyzer = NewHTTP1Analyzer()
	c.http2Analyzer = NewHTTP2Analyzer()
	c.wsAnalyzer = NewWebSocketAnalyzer()
}

type FingerprintExporter struct {
	fingerprints []*CompleteFingerprint
}

func NewFingerprintExporter() *FingerprintExporter {
	return &FingerprintExporter{
		fingerprints: make([]*CompleteFingerprint, 0),
	}
}

func (e *FingerprintExporter) Add(fp *CompleteFingerprint) {
	e.fingerprints = append(e.fingerprints, fp)
}

func (e *FingerprintExporter) ToJSON() (string, error) {
	data, err := json.MarshalIndent(e.fingerprints, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (e *FingerprintExporter) ToCSV() string {
	var lines []string
	lines = append(lines, "trace_id,timestamp,tls_version,ja3,ja4,ja3h1,ja3h2,detected_browser,confidence")

	for _, fp := range e.fingerprints {
		lines = append(lines, fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s,%.2f",
			fp.TraceID,
			fp.Timestamp.Format(time.RFC3339),
			getOrEmpty(fp.TLS, "Version"),
			fp.JA3,
			fp.JA4,
			fp.JA3H1,
			fp.JA3H2,
			fp.DetectedBrowser,
			fp.Confidence,
		))
	}

	return strings.Join(lines, "\n")
}

func getOrEmpty(fp *TLSFingerprint, field string) string {
	if fp == nil {
		return ""
	}
	switch field {
	case "Version":
		return fp.Version
	}
	return ""
}

func generateTraceID() string {
	return fmt.Sprintf("%016x-%d", time.Now().UnixNano(), time.Now().Nanosecond())
}

type FingerprintFilter struct {
	minConfidence float64
	browsers      []string
	protocols     []string
	timeRange     *TimeRange
}

type TimeRange struct {
	Start time.Time
	End   time.Time
}

func NewFingerprintFilter() *FingerprintFilter {
	return &FingerprintFilter{
		minConfidence: 0.0,
		browsers:      make([]string, 0),
		protocols:     make([]string, 0),
	}
}

func (f *FingerprintFilter) WithMinConfidence(conf float64) *FingerprintFilter {
	f.minConfidence = conf
	return f
}

func (f *FingerprintFilter) WithBrowsers(browsers ...string) *FingerprintFilter {
	f.browsers = browsers
	return f
}

func (f *FingerprintFilter) WithProtocols(protocols ...string) *FingerprintFilter {
	f.protocols = protocols
	return f
}

func (f *FingerprintFilter) WithTimeRange(start, end time.Time) *FingerprintFilter {
	f.timeRange = &TimeRange{Start: start, End: end}
	return f
}

func (f *FingerprintFilter) Filter(fingerprints []*CompleteFingerprint) []*CompleteFingerprint {
	result := make([]*CompleteFingerprint, 0)

	for _, fp := range fingerprints {
		if fp.Confidence < f.minConfidence {
			continue
		}

		if len(f.browsers) > 0 {
			found := false
			for _, b := range f.browsers {
				if fp.DetectedBrowser == b {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		if f.timeRange != nil {
			if fp.Timestamp.Before(f.timeRange.Start) || fp.Timestamp.After(f.timeRange.End) {
				continue
			}
		}

		result = append(result, fp)
	}

	return result
}

func CompareFingerprints(fp1, fp2 *CompleteFingerprint) *FingerprintComparison {
	comp := &FingerprintComparison{
		Similarity:   0.0,
		Differences:  make([]string, 0),
		MatchDetails: make(map[string]float64),
	}

	if fp1.TLS != nil && fp2.TLS != nil {
		if fp1.TLS.JA3 == fp2.TLS.JA3 {
			comp.MatchDetails["ja3"] = 1.0
			comp.Similarity += 0.3
		}
		if fp1.TLS.JA4 == fp2.TLS.JA4 {
			comp.MatchDetails["ja4"] = 1.0
			comp.Similarity += 0.3
		}
		if fp1.TLS.Version == fp2.TLS.Version {
			comp.MatchDetails["tls_version"] = 1.0
			comp.Similarity += 0.1
		}
	}

	if fp1.HTTP1 != nil && fp2.HTTP1 != nil {
		if fp1.HTTP1.JA3H1 == fp2.HTTP1.JA3H1 {
			comp.MatchDetails["ja3h1"] = 1.0
			comp.Similarity += 0.2
		}
	}

	if fp1.DetectedBrowser == fp2.DetectedBrowser {
		comp.MatchDetails["browser"] = 1.0
		comp.Similarity += 0.1
	}

	return comp
}

type FingerprintComparison struct {
	Similarity   float64            `json:"similarity"`
	Differences  []string           `json:"differences"`
	MatchDetails map[string]float64 `json:"match_details"`
}

func (c *FingerprintComparison) IsMatch(threshold float64) bool {
	return c.Similarity >= threshold
}
