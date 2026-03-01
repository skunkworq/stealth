package tlsfprint

import (
	"fmt"
	"strings"
)

// HPACKFingerprint represents an HPACK header compression fingerprint.
type HPACKFingerprint struct {
	DynamicTableSize uint32
	MaxTableSize     uint32
	StaticTableUsed  []int
	IndexingMode     string
	HuffmanUsed      bool
}

// CalculateHPACKFingerprint calculates an HPACK fingerprint from headers.
func CalculateHPACKFingerprint(headers map[string]string) string {
	order := []string{
		":method", ":path", ":scheme", ":authority", ":status",
		"accept", "accept-charset", "accept-encoding", "accept-language",
		"cache-control", "content-type", "cookie", "host", "user-agent",
	}

	var parts []string
	for _, name := range order {
		if value, ok := headers[name]; ok {
			parts = append(parts, fmt.Sprintf("%s:%s", name, value))
		}
	}

	return strings.Join(parts, ";")
}

// GetHPACKSignature returns an HPACK signature for the given headers.
func GetHPACKSignature(headers map[string]string) string {
	fingerprint := CalculateHPACKFingerprint(headers)

	var count int
	for range headers {
		count++
	}

	return fmt.Sprintf("%s;count:%d", fingerprint, count)
}

// HPACKSignatureDetector detects browser type from HPACK signatures.
type HPACKSignatureDetector struct {
	signatures map[string]string
}

// NewHPACKSignatureDetector creates a new HPACKSignatureDetector.
func NewHPACKSignatureDetector() *HPACKSignatureDetector {
	return &HPACKSignatureDetector{
		signatures: map[string]string{
			"chrome":  ";accept:*/*;content-type:",
			"firefox": ";accept:text/html;cache-control:",
			"safari":  ";accept:*/*;user-agent:",
			"curl":    ";accept:*/*;user-agent:curl",
		},
	}
}

// Detect detects the browser type from the given headers.
func (d *HPACKSignatureDetector) Detect(headers map[string]string) string {
	fp := CalculateHPACKFingerprint(headers)

	for sigType, sig := range d.signatures {
		if strings.Contains(fp, sig) {
			return sigType
		}
	}

	return "unknown"
}

// HTTP2TimingAnalyzer analyzes HTTP/2 timing patterns.
type HTTP2TimingAnalyzer struct {
	observations []HTTP2TimingObservation
}

// HTTP2TimingObservation represents a single HTTP/2 timing observation.
type HTTP2TimingObservation struct {
	Event          string
	DurationMs     int64
	Timestamp      int64
	TLSHandshakeMs int64
	TTFB           int64
	Download       int64
	Total          int64
}

// NewHTTP2TimingAnalyzer creates a new HTTP2TimingAnalyzer.
func NewHTTP2TimingAnalyzer() *HTTP2TimingAnalyzer {
	return &HTTP2TimingAnalyzer{
		observations: make([]HTTP2TimingObservation, 0),
	}
}

// RecordTLSHandshake records a TLS handshake timing observation.
func (a *HTTP2TimingAnalyzer) RecordTLSHandshake(durationMs int64) {
	obs := HTTP2TimingObservation{
		Event:      "tls_handshake",
		DurationMs: durationMs,
	}
	a.observations = append(a.observations, obs)
}

// RecordTTFB records a time-to-first-byte (TTFB) observation.
func (a *HTTP2TimingAnalyzer) RecordTTFB(ttfb int64) {
	obs := HTTP2TimingObservation{
		Event:      "ttfb",
		DurationMs: ttfb,
	}
	a.observations = append(a.observations, obs)
}

// RecordDownload records a download duration observation.
func (a *HTTP2TimingAnalyzer) RecordDownload(duration int64) {
	obs := HTTP2TimingObservation{
		Event:      "download",
		DurationMs: duration,
	}
	a.observations = append(a.observations, obs)
}

// RecordTotal records a total request duration observation.
func (a *HTTP2TimingAnalyzer) RecordTotal(duration int64) {
	obs := HTTP2TimingObservation{
		Event:      "total",
		DurationMs: duration,
	}
	a.observations = append(a.observations, obs)
}

// GetAverageHandshakeMs returns the average TLS handshake duration in milliseconds.
func (a *HTTP2TimingAnalyzer) GetAverageHandshakeMs() int64 {
	var total int64
	var count int
	for _, obs := range a.observations {
		if obs.Event == "tls_handshake" {
			total += obs.DurationMs
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return total / int64(count)
}

// GetAverageTTFB returns the average time-to-first-byte in milliseconds.
func (a *HTTP2TimingAnalyzer) GetAverageTTFB() int64 {
	var total int64
	var count int
	for _, obs := range a.observations {
		if obs.Event == "ttfb" {
			total += obs.DurationMs
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return total / int64(count)
}

// GetObservations returns all recorded timing observations.
func (a *HTTP2TimingAnalyzer) GetObservations() []HTTP2TimingObservation {
	return a.observations
}

// TLS13FeatureDetector detects TLS 1.3 specific features from ClientHello information.
type TLS13FeatureDetector struct{}

// NewTLS13FeatureDetector creates a new TLS13FeatureDetector.
func NewTLS13FeatureDetector() *TLS13FeatureDetector {
	return &TLS13FeatureDetector{}
}

// DetectTLS13 detects TLS 1.3 features from the given ClientHelloInfo.
// Returns a list of TLSFeature indicating presence of various TLS 1.3 capabilities.
func (d *TLS13FeatureDetector) DetectTLS13(ch *ClientHelloInfo) []TLSFeature {
	var features []TLSFeature

	features = append(features, TLSFeature{
		Name: "TLS 1.3", Present: ch.Version >= 0x0304,
	})

	features = append(features, TLSFeature{
		Name: "Early Data (0-RTT)", Present: hasExt(ch.ExtensionsList, 35),
	})

	features = append(features, TLSFeature{
		Name: "PSK", Present: hasExt(ch.ExtensionsList, 41),
	})

	features = append(features, TLSFeature{
		Name: "Post-Handshake Auth", Present: hasExt(ch.ExtensionsList, 48),
	})

	features = append(features, TLSFeature{
		Name: "Key Share", Present: hasExt(ch.ExtensionsList, 50),
	})

	features = append(features, TLSFeature{
		Name: "Supported Versions", Present: len(ch.SupportedVersions) > 0,
		Details: fmt.Sprintf("versions: %v", ch.SupportedVersions),
	})

	features = append(features, TLSFeature{
		Name: "GREASE", Present: ch.GreaseDetected,
	})

	return features
}

func hasExt(exts []uint16, target uint16) bool {
	for _, e := range exts {
		if e == target {
			return true
		}
	}
	return false
}

// TLSFeature represents a detected TLS feature with its presence status.
type TLSFeature struct {
	Name    string
	Present bool
	Details string
}

// OCSPResponse represents an OCSP stapling response.
type OCSPResponse struct {
	Stapled     bool
	Status      string
	ThisUpdate  int64
	NextUpdate  int64
	IssuerHash  string
	SubjectHash string
}

// OCSPAnalyzer analyzes OCSP stapling observations.
type OCSPAnalyzer struct {
	observations []OCSPResponse
}

// NewOCSPAnalyzer creates a new OCSPAnalyzer.
func NewOCSPAnalyzer() *OCSPAnalyzer {
	return &OCSPAnalyzer{
		observations: make([]OCSPResponse, 0),
	}
}

// RecordStapling records an OCSP stapling observation with the given status and timestamps.
func (a *OCSPAnalyzer) RecordStapling(status string, thisUpdate, nextUpdate int64) {
	resp := OCSPResponse{
		Stapled:    true,
		Status:     status,
		ThisUpdate: thisUpdate,
		NextUpdate: nextUpdate,
	}
	a.observations = append(a.observations, resp)
}

// GetStaplingRatio returns the ratio of stapled responses to total observations.
func (a *OCSPAnalyzer) GetStaplingRatio() float64 {
	if len(a.observations) == 0 {
		return 0
	}
	stapled := 0
	for _, obs := range a.observations {
		if obs.Stapled {
			stapled++
		}
	}
	return float64(stapled) / float64(len(a.observations))
}

// GetObservations returns all recorded OCSP responses.
func (a *OCSPAnalyzer) GetObservations() []OCSPResponse {
	return a.observations
}
