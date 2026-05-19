// Package challenge provides detection and fingerprinting capabilities for adversarial systems.
//
//nolint:gosec // G401/G501: MD5 required for JA3 fingerprinting per JA3 spec
package detection

import (
	//nolint:gosec // MD5 required for JA3 fingerprinting per JA3 spec
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// TLSFingerprinter captures and analyzes TLS fingerprints from TLS connections.
type TLSFingerprinter struct {
	config *utls.Config
}

// NewTLSFingerprinter creates a new TLS fingerprinting instance.
func NewTLSFingerprinter() *TLSFingerprinter {
	return &TLSFingerprinter{
		config: &utls.Config{
			InsecureSkipVerify: true,
		},
	}
}

// CapturedTLSFingerprint is a lightweight live-capture result from a TLS handshake.
// It is distinct from types.TLSFingerprint (core/types), which is the canonical
// archival format used for deep baseline comparison.
type CapturedTLSFingerprint struct {
	JA3        string
	JA3Hash    string
	JA4        string
	Version    string
	Ciphers    []string
	Extensions []string
	ALPN       string
	SNI        string
	GREASE     bool
	UserAgent  string
}

// CaptureFingerprint captures a TLS fingerprint from the given address.
func (t *TLSFingerprinter) CaptureFingerprint(addr, _ string) (*CapturedTLSFingerprint, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer func() { _ = conn.Close() }()

	tlsConn := utls.Client(conn, &utls.Config{
		ServerName:         strings.Split(addr, ":")[0],
		InsecureSkipVerify: true,
	})

	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}

	state := tlsConn.ConnectionState()

	fp := &CapturedTLSFingerprint{
		Version: fmt.Sprintf("0x%04x", state.Version),
		SNI:     state.ServerName,
		ALPN:    state.NegotiatedProtocol,
	}

	// Get cipher suite (single value in uTLS ConnectionState)
	fp.Ciphers = append(fp.Ciphers, fmt.Sprintf("%04x", state.CipherSuite))

	// Calculate JA4
	fp.JA4 = t.calculateJA4(state.Version, state.CipherSuite, state.NegotiatedProtocol)

	// Calculate JA3
	fp.JA3 = t.calculateJA3(state.CipherSuite)
	fp.JA3Hash = md5Hash(fp.JA3)

	return fp, nil
}

func (t *TLSFingerprinter) calculateJA4(version, cipher uint16, alpn string) string {
	ver := "12"
	if version >= 0x0304 {
		ver = "13"
	}

	alpnStr := "_"
	if alpn != "" {
		alpnStr = "h2"
	}

	return fmt.Sprintf("t%s%s_%04x", ver, alpnStr, cipher)
}

func (t *TLSFingerprinter) calculateJA3(cipher uint16) string {
	// Simplified JA3 - real implementation would capture all ciphers and extensions
	return fmt.Sprintf("769,%04x,0-1-5-10-11-13-16-23-35-43-45-51", cipher)
}

// DetectBrowserFromJA4 attempts to detect the browser type from a JA4 fingerprint.
func (t *TLSFingerprinter) DetectBrowserFromJA4(ja4 string) string {
	if strings.HasPrefix(ja4, "t13") || strings.HasPrefix(ja4, "t12") {
		// Check for TLS 1.3 ciphers which indicate modern browsers
		if strings.Contains(ja4, "1301") || strings.Contains(ja4, "1302") || strings.Contains(ja4, "1303") {
			return "chrome" // TLS 1.3 + Chrome-like
		}
		return "chrome" // Default to chrome for modern TLS
	}
	return "unknown"
}

// ValidateFingerprint checks if the JA4 fingerprint matches the expected browser.
func (t *TLSFingerprinter) ValidateFingerprint(ja4, expectedBrowser string) bool {
	detected := t.DetectBrowserFromJA4(ja4)
	return detected == expectedBrowser
}

func md5Hash(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// TLSAnalysisResult contains the analysis results of a TLS fingerprint.
type TLSAnalysisResult struct {
	JA4            string
	JA3            string
	JA3Hash        string
	Browser        string
	IsChrome       bool
	IsFirefox      bool
	IsSafari       bool
	HasGREASE      bool
	Version        string
	CipherCount    int
	ExtensionCount int
	ALPN           string
	SNI            string
	Anomalies      []string
}

// AnalyzeConnection captures and analyzes a TLS connection to the given address.
func (t *TLSFingerprinter) AnalyzeConnection(addr string) (*TLSAnalysisResult, error) {
	fp, err := t.CaptureFingerprint(addr, "chrome")
	if err != nil {
		return nil, err
	}

	result := &TLSAnalysisResult{
		JA4:         fp.JA4,
		JA3:         fp.JA3,
		JA3Hash:     fp.JA3Hash,
		Browser:     t.DetectBrowserFromJA4(fp.JA4),
		IsChrome:    strings.Contains(fp.JA4, "t12d") || strings.Contains(fp.JA4, "t13d"),
		Version:     fp.Version,
		CipherCount: len(fp.Ciphers),
		ALPN:        fp.ALPN,
		SNI:         fp.SNI,
	}

	// Check for anomalies
	if !result.IsChrome && !result.IsFirefox && !result.IsSafari {
		result.Anomalies = append(result.Anomalies, "unknown_tls_fingerprint")
	}

	if result.CipherCount < 1 {
		result.Anomalies = append(result.Anomalies, "few_ciphers")
	}

	if result.SNI == "" {
		result.Anomalies = append(result.Anomalies, "no_sni")
	}

	return result, nil
}

// GetBrowserFingerprint returns the utls ClientHelloID for the specified browser.
func (t *TLSFingerprinter) GetBrowserFingerprint(browser string) (*utls.ClientHelloID, error) {
	switch strings.ToLower(browser) {
	case "chrome":
		return &utls.HelloChrome_120, nil
	case "firefox":
		return &utls.HelloFirefox_120, nil
	case "safari":
		return &utls.HelloSafari_16_0, nil
	default:
		return &utls.HelloChrome_120, nil
	}
}
