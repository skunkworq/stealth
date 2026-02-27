package adversarial

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/stealth/brwslab/brws/constants"
)

// DetailedTrace provides comprehensive tracing of request characteristics
type DetailedTrace struct {
	Timestamp time.Time

	// HTTP Characteristics
	HTTP HTTPTrace

	// TLS Characteristics
	TLS TLSTrace

	// Behavioral Characteristics
	Behavioral BehavioralTrace

	// Overall assessment
	IsSuspicious     bool
	SuspicionReasons []string
	SuspicionScore   float64
}

// HTTPTrace captures detailed HTTP request characteristics
type HTTPTrace struct {
	UserAgent          string
	UserAgentLength    int
	Accept             string
	AcceptLanguage     string
	AcceptEncoding     string
	SecChUa            string
	SecChUaMobile      string
	SecChUaPlatform    string
	SecChUaFullVersion string
	SecFetchDest       string
	SecFetchMode       string
	SecFetchSite       string
	SecFetchUser       string
	UpgradeInsecure    string

	// Derived
	HeaderCount      int
	ClientHintsCount int
	SecFetchCount    int
	HasAllRequiredCH bool // Has all required Client Hints
	HeaderOrder      []string
}

// TLSTrace captures TLS fingerprint details
type TLSTrace struct {
	Version         string
	CipherSuite     string
	JA4             string
	JA3             string
	ALPN            string
	SNI             string
	HasGREASE       bool
	SignatureAlgs   []string
	SupportedGroups []string
	IsKnownBrowser  bool
	BrowserMatch    string // Which browser this TLS matches
}

// BehavioralTrace captures behavioral patterns
type BehavioralTrace struct {
	HasConsistentTiming bool
	RequestInterval     time.Duration
	HeadersPerSecond    float64
}

// NewDetailedTrace creates a comprehensive trace of a request
func NewDetailedTrace(req *http.Request, tlsConn *tls.ConnectionState) *DetailedTrace {
	dt := &DetailedTrace{
		Timestamp: time.Now(),
		HTTP:      extractHTTPTrace(req),
		TLS:       extractTLSTrace(tlsConn),
	}

	// Analyze for suspicious patterns
	dt.analyzeSuspiciousPatterns()

	return dt
}

func extractHTTPTrace(req *http.Request) HTTPTrace {
	trace := HTTPTrace{
		UserAgent:          req.Header.Get("User-Agent"),
		Accept:             req.Header.Get("Accept"),
		AcceptLanguage:     req.Header.Get("Accept-Language"),
		AcceptEncoding:     req.Header.Get("Accept-Encoding"),
		SecChUa:            req.Header.Get("Sec-Ch-Ua"),
		SecChUaMobile:      req.Header.Get("Sec-Ch-Ua-Mobile"),
		SecChUaPlatform:    req.Header.Get("Sec-Ch-Ua-Platform"),
		SecChUaFullVersion: req.Header.Get("Sec-Ch-Ua-Full-Version"),
		SecFetchDest:       req.Header.Get("Sec-Fetch-Dest"),
		SecFetchMode:       req.Header.Get("Sec-Fetch-Mode"),
		SecFetchSite:       req.Header.Get("Sec-Fetch-Site"),
		SecFetchUser:       req.Header.Get("Sec-Fetch-User"),
		UpgradeInsecure:    req.Header.Get("Upgrade-Insecure-Requests"),
		HeaderCount:        len(req.Header),
	}

	trace.UserAgentLength = len(trace.UserAgent)

	// Count Client Hints
	if trace.SecChUa != "" {
		trace.ClientHintsCount++
	}
	if trace.SecChUaMobile != "" {
		trace.ClientHintsCount++
	}
	if trace.SecChUaPlatform != "" {
		trace.ClientHintsCount++
	}
	if trace.SecChUaFullVersion != "" {
		trace.ClientHintsCount++
	}

	// Count Sec-Fetch headers
	if trace.SecFetchDest != "" {
		trace.SecFetchCount++
	}
	if trace.SecFetchMode != "" {
		trace.SecFetchCount++
	}
	if trace.SecFetchSite != "" {
		trace.SecFetchCount++
	}
	if trace.SecFetchUser != "" {
		trace.SecFetchCount++
	}

	// Check if has all required Client Hints for Chrome
	trace.HasAllRequiredCH = trace.SecChUa != "" && trace.SecChUaPlatform != "" && trace.SecChUaMobile != ""

	// Extract header order
	for k := range req.Header {
		trace.HeaderOrder = append(trace.HeaderOrder, k)
	}

	return trace
}

func extractTLSTrace(tlsConn *tls.ConnectionState) TLSTrace {
	trace := TLSTrace{}

	if tlsConn == nil {
		return trace
	}

	trace.Version = fmt.Sprintf("0x%04x", tlsConn.Version)
	trace.CipherSuite = fmt.Sprintf("0x%04x", tlsConn.CipherSuite)
	trace.ALPN = tlsConn.NegotiatedProtocol
	trace.SNI = tlsConn.ServerName

	// Calculate JA4
	if tlsConn.Version >= 0x0304 {
		trace.JA4 = fmt.Sprintf("t13_%s_%04x", trace.ALPN, tlsConn.CipherSuite)
	} else {
		trace.JA4 = fmt.Sprintf("t12_%s_%04x", trace.ALPN, tlsConn.CipherSuite)
	}

	return trace
}

func (dt *DetailedTrace) analyzeSuspiciousPatterns() {
	var reasons []string
	var score float64

	// Check 1: User-Agent analysis
	if dt.HTTP.UserAgent == "" {
		reasons = append(reasons, "missing_user_agent")
		score += 0.3
	} else if strings.Contains(strings.ToLower(dt.HTTP.UserAgent), "python") ||
		strings.Contains(strings.ToLower(dt.HTTP.UserAgent), "curl") ||
		strings.Contains(strings.ToLower(dt.HTTP.UserAgent), "go-http") {
		reasons = append(reasons, "suspicious_user_agent")
		score += 0.6
	}

	// Check 1b: Very short User-Agent (less than 30 chars is suspicious)
	if dt.HTTP.UserAgentLength > 0 && dt.HTTP.UserAgentLength < 30 {
		reasons = append(reasons, "very_short_user_agent")
		score += 0.4
	} else if dt.HTTP.UserAgentLength > 0 && dt.HTTP.UserAgentLength < 50 {
		reasons = append(reasons, "short_user_agent")
		score += constants.SeverityLow
	}

	// Check 1c: Firefox claims but very short/minimal UA
	if strings.Contains(strings.ToLower(dt.HTTP.UserAgent), "firefox") && dt.HTTP.UserAgentLength < 50 {
		reasons = append(reasons, "firefox_minimal_ua")
		score += constants.SeverityHigh
	}

	// Check 2: Incomplete Client Hints
	if dt.HTTP.SecChUa != "" && !dt.HTTP.HasAllRequiredCH {
		reasons = append(reasons, "incomplete_client_hints")
		score += constants.SeverityMedium
	}

	// Check 3: Chrome headers but unusual UA
	if dt.HTTP.SecChUa != "" && dt.HTTP.SecChUaPlatform == "" {
		reasons = append(reasons, "missing_platform_hint")
		score += 0.2
	}

	// Check 4: Sec-Fetch mismatch - Safari shouldn't have Chrome headers
	if strings.Contains(dt.HTTP.UserAgent, "Safari") && dt.HTTP.SecChUa != "" {
		// Safari sending Chrome Client Hints is very suspicious
		reasons = append(reasons, "safari_sending_chrome_headers")
		score += 0.5
	}

	// Check 4b: Non-Chrome browser sending Chrome-specific headers
	if !strings.Contains(dt.HTTP.UserAgent, "Chrome") && !strings.Contains(dt.HTTP.UserAgent, "Edg") {
		if dt.HTTP.SecChUa != "" {
			reasons = append(reasons, "non_chrome_sending_chrome_client_hints")
			score += 0.45
		}
	}

	// Check 5: Chrome but missing Sec-Fetch (Chrome ALWAYS sends these)
	if strings.Contains(dt.HTTP.UserAgent, "Chrome") && dt.HTTP.SecFetchCount == 0 {
		reasons = append(reasons, "chrome_missing_sec_fetch")
		score += 0.3
	}

	// Check 5b: Sec-Fetch present for non-browser clients
	if dt.HTTP.SecFetchCount > 0 && (dt.HTTP.UserAgentLength < 30 || dt.HTTP.UserAgent == "") {
		reasons = append(reasons, "suspicious_sec_fetch")
		score += constants.SeverityMedium
	}

	// Check 6: No Accept-Language for Chrome
	if strings.Contains(dt.HTTP.UserAgent, "Chrome") && dt.HTTP.AcceptLanguage == "" {
		reasons = append(reasons, "chrome_no_accept_language")
		score += constants.SeverityLow
	}

	// Check 7: Platform inconsistency
	if dt.HTTP.SecChUaPlatform != "" {
		uaPlatform := strings.ToLower(dt.HTTP.UserAgent)
		secPlatform := strings.ToLower(dt.HTTP.SecChUaPlatform)

		if strings.Contains(uaPlatform, "windows") && strings.Contains(secPlatform, "mac") {
			reasons = append(reasons, "platform_mismatch_windows_mac")
			score += 0.5
		}
		if strings.Contains(uaPlatform, "mac") && strings.Contains(secPlatform, "windows") {
			reasons = append(reasons, "platform_mismatch_mac_windows")
			score += 0.5
		}
		if strings.Contains(uaPlatform, "linux") && !strings.Contains(secPlatform, "linux") {
			reasons = append(reasons, "platform_mismatch_linux")
			score += 0.4
		}
	}

	// Check 8: Header order analysis
	// Legitimate browsers have specific header ordering
	if dt.HTTP.HeaderCount > 0 {
		// Very few headers is suspicious for a "real" browser
		if dt.HTTP.HeaderCount < 8 && dt.HTTP.UserAgentLength > 50 {
			reasons = append(reasons, "too_few_headers_for_ua")
			score += 0.2
		}
	}

	// Check 9: TLS fingerprint analysis (if available)
	if dt.TLS.JA4 != "" {
		// Check if TLS looks like Go
		if strings.HasPrefix(dt.TLS.JA4, "t13") && !strings.HasPrefix(dt.TLS.JA4, "t13d") {
			reasons = append(reasons, "go_tls_fingerprint")
			score += 0.4
		}

		// Check for mismatched browser claims
		if strings.Contains(dt.HTTP.UserAgent, "Chrome") && !strings.HasPrefix(dt.TLS.JA4, "t13d") {
			reasons = append(reasons, "chrome_tls_mismatch")
			score += 0.3
		}
	}

	dt.SuspicionReasons = reasons
	dt.SuspicionScore = score
	dt.IsSuspicious = score >= 0.3
}

// GenerateReport creates a detailed detection report
func (dt *DetailedTrace) GenerateReport() string {
	var sb strings.Builder

	sb.WriteString("=== Detailed Detection Report ===\n\n")

	sb.WriteString("HTTP Characteristics:\n")
	_, _ = fmt.Fprintf(&sb, "  User-Agent: %s\n", dt.HTTP.UserAgent)
	_, _ = fmt.Fprintf(&sb, "  User-Agent Length: %d\n", dt.HTTP.UserAgentLength)
	_, _ = fmt.Fprintf(&sb, "  Has Client Hints: %v (%d/4)\n", dt.HTTP.HasAllRequiredCH, dt.HTTP.ClientHintsCount)
	sb.WriteString(fmt.Sprintf("  Has Sec-Fetch: %v (%d/4)\n", dt.HTTP.SecFetchCount > 0, dt.HTTP.SecFetchCount))
	sb.WriteString(fmt.Sprintf("  Accept-Language: %s\n", dt.HTTP.AcceptLanguage))
	sb.WriteString(fmt.Sprintf("  Header Count: %d\n", dt.HTTP.HeaderCount))

	if dt.TLS.JA4 != "" {
		sb.WriteString("\nTLS Characteristics:\n")
		sb.WriteString(fmt.Sprintf("  Version: %s\n", dt.TLS.Version))
		sb.WriteString(fmt.Sprintf("  JA4: %s\n", dt.TLS.JA4))
		sb.WriteString(fmt.Sprintf("  Cipher: %s\n", dt.TLS.CipherSuite))
		sb.WriteString(fmt.Sprintf("  ALPN: %s\n", dt.TLS.ALPN))
		sb.WriteString(fmt.Sprintf("  SNI: %s\n", dt.TLS.SNI))
	}

	sb.WriteString("\nSuspicion Analysis:\n")
	sb.WriteString(fmt.Sprintf("  Is Suspicious: %v\n", dt.IsSuspicious))
	sb.WriteString(fmt.Sprintf("  Suspicion Score: %.2f\n", dt.SuspicionScore))
	sb.WriteString(fmt.Sprintf("  Reasons (%d):\n", len(dt.SuspicionReasons)))
	for _, r := range dt.SuspicionReasons {
		sb.WriteString(fmt.Sprintf("    - %s\n", r))
	}

	return sb.String()
}
