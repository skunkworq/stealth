// Package adversarial provides tools to detect browser fingerprint spoofing.
// It analyzes TLS, HTTP/2, and behavioral fingerprints to identify non-human patterns.
package adversarial

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/skunkworq/stealth/brws/types"
)

// DetectionResult contains the results of fingerprint analysis.
type DetectionResult struct {
	Timestamp  time.Time           `json:"timestamp"`
	IsBot      bool                `json:"is_bot"`
	Confidence float64             `json:"confidence"`
	Score      float64             `json:"score"` // -1.0 to 1.0, positive = suspicious
	Indicators []Indicator         `json:"indicators"`
	TLS        *TLSAnalysis        `json:"tls,omitempty"`
	HTTP2      *HTTP2Analysis      `json:"http2,omitempty"`
	HTTP       *HTTPAnalysis       `json:"http,omitempty"`
	Behavioral *BehavioralAnalysis `json:"behavioral,omitempty"`
}

// Indicator represents a single detection indicator.
type Indicator struct {
	Category string  `json:"category"` // tls, http2, http, behavioral
	Name     string  `json:"name"`
	Severity float64 `json:"severity"` // 0.0 to 1.0
	Message  string  `json:"message"`
}

// TLSAnalysis contains TLS fingerprint analysis.
type TLSAnalysis struct {
	JA4             string   `json:"ja4"`
	CipherSuites    []string `json:"cipher_suites"`
	Extensions      []string `json:"extensions"`
	SignatureAlgs   []string `json:"signature_algs"`
	SupportedGroups []string `json:"supported_groups"`
	ALPN            []string `json:"alpn"`
	SNI             string   `json:"sni"`
	Version         string   `json:"version"`
	IsGREASE        bool     `json:"is_grease"`
	Anomalies       []string `json:"anomalies"`
}

// HTTP2Analysis contains HTTP/2 fingerprint analysis.
type HTTP2Analysis struct {
	Settings       map[string]string `json:"settings"`
	PriorityFrames int               `json:"priority_frames"`
	WindowUpdates  int               `json:"window_updates"`
	Anomalies      []string          `json:"anomalies"`
}

// HTTPAnalysis contains HTTP fingerprint analysis.
type HTTPAnalysis struct {
	Headers         map[string]string `json:"headers"`
	HeaderOrder     []string          `json:"header_order"`
	UserAgent       string            `json:"user_agent"`
	AcceptLanguage  string            `json:"accept_language"`
	SecCHUA         string            `json:"sec_ch_ua,omitempty"`
	SecCHUAPlatform string            `json:"sec_ch_ua_platform,omitempty"`
	Anomalies       []string          `json:"anomalies"`
}

// BehavioralAnalysis contains behavioral fingerprint analysis.
type BehavioralAnalysis struct {
	MouseEvents   int      `json:"mouse_events"`
	ScrollEvents  int      `json:"scroll_events"`
	TypingEvents  int      `json:"typing_events"`
	AvgMouseSpeed float64  `json:"avg_mouse_speed"`
	StdDevMouse   float64  `json:"stddev_mouse"`
	Anomalies     []string `json:"anomalies"`
}

// Detector analyzes fingerprints to detect spoofing/bots.
type Detector struct {
	mu        sync.RWMutex
	results   []DetectionResult
	baselines map[string]*types.CompleteFingerprint
}

// NewDetector creates a new adversarial detector.
func NewDetector() *Detector {
	return &Detector{
		results:   make([]DetectionResult, 0),
		baselines: make(map[string]*types.CompleteFingerprint),
	}
}

// LoadBaseline loads a baseline fingerprint for comparison.
func (d *Detector) LoadBaseline(name string, fp *types.CompleteFingerprint) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.baselines[name] = fp
}

// AnalyzeTLS analyzes a TLS ClientHello for anomalies.
func (d *Detector) AnalyzeTLS(clientHello *tls.ClientHelloInfo) *TLSAnalysis {
	analysis := &TLSAnalysis{
		CipherSuites:    []string{},
		Extensions:      []string{},
		SignatureAlgs:   []string{},
		SupportedGroups: []string{},
		ALPN:            []string{},
		SNI:             clientHello.ServerName,
		Version:         "unknown",
	}

	// Check for GREASE values
	for _, cipher := range clientHello.CipherSuites {
		if isGREASE(cipher) {
			analysis.IsGREASE = true
			break
		}
	}

	// Detect common spoofing patterns
	analysis.Anomalies = d.detectTLSAnomalies(analysis)

	return analysis
}

// AnalyzeHTTP analyzes HTTP headers for anomalies.
func (d *Detector) AnalyzeHTTP(req *http.Request) *HTTPAnalysis {
	analysis := &HTTPAnalysis{
		Headers:     make(map[string]string),
		HeaderOrder: []string{},
	}

	// Collect headers
	for key, values := range req.Header {
		if len(values) > 0 {
			analysis.Headers[key] = values[0]
			analysis.HeaderOrder = append(analysis.HeaderOrder, key)
		}
	}

	analysis.UserAgent = req.Header.Get("User-Agent")
	analysis.AcceptLanguage = req.Header.Get("Accept-Language")
	analysis.SecCHUA = req.Header.Get("Sec-Ch-Ua")
	analysis.SecCHUAPlatform = req.Header.Get("Sec-Ch-Ua-Platform")

	analysis.Anomalies = d.detectHTTPAnomalies(analysis)

	return analysis
}

// DetectFromJA3 calculates bot probability from JA3 string.
func (d *Detector) DetectFromJA3(ja3 string) (bool, float64) {
	indicators := make([]Indicator, 0)
	score := 0.0

	// Known bot patterns in JA3
	botPatterns := []struct {
		pattern string
		weight  float64
	}{
		{"771,", 0.3},  // Chrome uses 772
		{"0xff,", 0.4}, // Unusual cipher
	}

	for _, bp := range botPatterns {
		if strings.Contains(ja3, bp.pattern) {
			score += bp.weight
			indicators = append(indicators, Indicator{
				Category: "tls",
				Name:     "bot_pattern",
				Severity: bp.weight,
				Message:  fmt.Sprintf("Found suspicious JA3 pattern: %s", bp.pattern),
			})
		}
	}

	// Check for perfect fingerprints (unlikely for real browsers)
	if strings.Count(ja3, ",") < 5 {
		score += 0.3
		indicators = append(indicators, Indicator{
			Category: "tls",
			Name:     "minimal_fingerprint",
			Severity: 0.3,
			Message:  "Fingerprint has unusually few elements",
		})
	}

	_ = indicators // indicators collected for future use
	isBot := score > 0.5
	return isBot, score
}

// DetectFromHeaders analyzes HTTP headers for bot detection.
func (d *Detector) DetectFromHeaders(headers http.Header) (bool, float64) {
	score := 0.0

	// Check for missing headers that real browsers send
	missingHeaders := 0
	requiredHeaders := []string{"User-Agent", "Accept", "Accept-Language"}
	for _, h := range requiredHeaders {
		if headers.Get(h) == "" {
			missingHeaders++
		}
	}
	if missingHeaders > 0 {
		score += float64(missingHeaders) * 0.2
	}

	ua := headers.Get("User-Agent")

	// Check for suspicious User-Agent patterns
	if isSuspiciousUserAgent(ua) {
		score += 0.4
	}

	// Check Client Hints consistency
	chUa := headers.Get("Sec-Ch-Ua")
	chPlatform := headers.Get("Sec-Ch-Ua-Platform")
	if chUa != "" && chPlatform != "" {
		if !clientHintsConsistent(chUa, chPlatform) {
			score += 0.3
		}
	}

	isBot := score > 0.5
	return isBot, score
}

// CompareToBaseline compares a fingerprint against a known baseline.
func (d *Detector) CompareToBaseline(name string, fp *types.CompleteFingerprint) *DetectionResult {
	d.mu.RLock()
	baseline := d.baselines[name]
	d.mu.RUnlock()

	result := &DetectionResult{
		Timestamp:  time.Now(),
		IsBot:      false,
		Confidence: 0.0,
		Score:      0.0,
		Indicators: make([]Indicator, 0),
	}

	if baseline == nil {
		result.Indicators = append(result.Indicators, Indicator{
			Category: "system",
			Name:     "no_baseline",
			Severity: 0.5,
			Message:  "No baseline available for comparison",
		})
		return result
	}

	// Compare TLS fingerprints
	if fp.TLS != nil {
		result.TLS = &TLSAnalysis{
			JA4: fp.TLS.JA4,
		}

		if baseline.TLS != nil {
			// JA4 mismatch
			if fp.TLS.JA4 != baseline.TLS.JA4 {
				result.Score += 0.4
				result.Indicators = append(result.Indicators, Indicator{
					Category: "tls",
					Name:     "ja4_mismatch",
					Severity: 0.4,
					Message:  fmt.Sprintf("JA4 differs from baseline: got %s, expected %s", fp.TLS.JA4, baseline.TLS.JA4),
				})
			}
		}
	}

	// Compare HTTP fingerprints
	if fp.HTTP != nil {
		result.HTTP = &HTTPAnalysis{
			UserAgent: fp.HTTP.UserAgent,
		}

		if baseline.HTTP != nil {
			// Check User-Agent match
			if fp.HTTP.UserAgent != baseline.HTTP.UserAgent {
				result.Score += 0.2
				result.Indicators = append(result.Indicators, Indicator{
					Category: "http",
					Name:     "ua_mismatch",
					Severity: 0.2,
					Message:  "User-Agent differs from baseline",
				})
			}
		}
	}

	result.Confidence = minFloat(1.0, result.Score)
	result.IsBot = result.Score > 0.5

	return result
}

// AddResult records a detection result.
func (d *Detector) AddResult(result DetectionResult) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.results = append(d.results, result)
}

// GetResults returns all detection results.
func (d *Detector) GetResults() []DetectionResult {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.results
}

// Helper functions

func (d *Detector) detectTLSAnomalies(analysis *TLSAnalysis) []string {
	anomalies := make([]string, 0)

	// Check for unusual cipher count
	if len(analysis.CipherSuites) < 10 {
		anomalies = append(anomalies, fmt.Sprintf("Unusually few cipher suites: %d", len(analysis.CipherSuites)))
	}

	return anomalies
}

func (d *Detector) detectHTTPAnomalies(analysis *HTTPAnalysis) []string {
	anomalies := make([]string, 0)

	// Check for missing headers
	if analysis.UserAgent == "" {
		anomalies = append(anomalies, "Missing User-Agent header")
	}

	return anomalies
}

func isGREASE(value uint16) bool {
	return (value >= 0x0a0a && value <= 0x0a0f) ||
		(value >= 0x1a0a && value <= 0x1a0f) ||
		(value >= 0x2a0a && value <= 0x2a0f) ||
		(value >= 0x3a0a && value <= 0x3a0f) ||
		(value >= 0x4a0a && value <= 0x4a0f) ||
		(value >= 0x5a0a && value <= 0x5a0f) ||
		(value >= 0x6a0a && value <= 0x6a0f) ||
		(value >= 0x7a0a && value <= 0x7a0f) ||
		(value >= 0x8a0a && value <= 0x8a0f) ||
		(value >= 0x9a0a && value <= 0x9a0f) ||
		(value >= 0xaa0a && value <= 0xaa0f) ||
		(value >= 0xba0a && value <= 0xba0f) ||
		(value >= 0xca0a && value <= 0xca0f) ||
		(value >= 0xda0a && value <= 0xda0f) ||
		(value >= 0xea0a && value <= 0xea0f) ||
		(value >= 0xfa0a && value <= 0xfa0f)
}

func isSuspiciousUserAgent(ua string) bool {
	suspicious := []string{"curl", "wget", "python", "scrapy", "bot", "spider", "headless"}
	uaLower := strings.ToLower(ua)
	for _, s := range suspicious {
		if strings.Contains(uaLower, s) {
			return true
		}
	}
	return false
}

func clientHintsConsistent(chUa, chPlatform string) bool {
	platformLower := strings.ToLower(chPlatform)
	if strings.Contains(chUa, "Windows") && !strings.Contains(platformLower, "windows") {
		return false
	}
	if strings.Contains(chUa, "Mac") && !strings.Contains(platformLower, "macos") && !strings.Contains(platformLower, "mac") {
		return false
	}
	if strings.Contains(chUa, "Linux") && !strings.Contains(platformLower, "linux") {
		return false
	}
	if strings.Contains(chUa, "Not_A Brand") && strings.Contains(platformLower, "linux") {
		return false
	}
	return true
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
