package tlsfprint

import (
	"fmt"
	"strings"
)

type HPACKFingerprint struct {
	DynamicTableSize uint32
	MaxTableSize     uint32
	StaticTableUsed  []int
	IndexingMode     string
	HuffmanUsed      bool
}

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

func GetHPACKSignature(headers map[string]string) string {
	fingerprint := CalculateHPACKFingerprint(headers)

	var count int
	for range headers {
		count++
	}

	return fmt.Sprintf("%s;count:%d", fingerprint, count)
}

type HPACKSignatureDetector struct {
	signatures map[string]string
}

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

func (d *HPACKSignatureDetector) Detect(headers map[string]string) string {
	fp := CalculateHPACKFingerprint(headers)

	for sigType, sig := range d.signatures {
		if strings.Contains(fp, sig) {
			return sigType
		}
	}

	return "unknown"
}

type HTTP2TimingAnalyzer struct {
	observations []HTTP2TimingObservation
}

type HTTP2TimingObservation struct {
	Event          string
	DurationMs     int64
	Timestamp      int64
	TLSHandshakeMs int64
	TTFB           int64
	Download       int64
	Total          int64
}

func NewHTTP2TimingAnalyzer() *HTTP2TimingAnalyzer {
	return &HTTP2TimingAnalyzer{
		observations: make([]HTTP2TimingObservation, 0),
	}
}

func (a *HTTP2TimingAnalyzer) RecordTLSHandshake(durationMs int64) {
	obs := HTTP2TimingObservation{
		Event:      "tls_handshake",
		DurationMs: durationMs,
	}
	a.observations = append(a.observations, obs)
}

func (a *HTTP2TimingAnalyzer) RecordTTFB(ttfb int64) {
	obs := HTTP2TimingObservation{
		Event:      "ttfb",
		DurationMs: ttfb,
	}
	a.observations = append(a.observations, obs)
}

func (a *HTTP2TimingAnalyzer) RecordDownload(duration int64) {
	obs := HTTP2TimingObservation{
		Event:      "download",
		DurationMs: duration,
	}
	a.observations = append(a.observations, obs)
}

func (a *HTTP2TimingAnalyzer) RecordTotal(duration int64) {
	obs := HTTP2TimingObservation{
		Event:      "total",
		DurationMs: duration,
	}
	a.observations = append(a.observations, obs)
}

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

func (a *HTTP2TimingAnalyzer) GetObservations() []HTTP2TimingObservation {
	return a.observations
}

type TLS13FeatureDetector struct{}

func NewTLS13FeatureDetector() *TLS13FeatureDetector {
	return &TLS13FeatureDetector{}
}

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

type TLSFeature struct {
	Name    string
	Present bool
	Details string
}

type OCSPResponse struct {
	Stapled     bool
	Status      string
	ThisUpdate  int64
	NextUpdate  int64
	IssuerHash  string
	SubjectHash string
}

type OCSPAnalyzer struct {
	observations []OCSPResponse
}

func NewOCSPAnalyzer() *OCSPAnalyzer {
	return &OCSPAnalyzer{
		observations: make([]OCSPResponse, 0),
	}
}

func (a *OCSPAnalyzer) RecordStapling(status string, thisUpdate, nextUpdate int64) {
	resp := OCSPResponse{
		Stapled:    true,
		Status:     status,
		ThisUpdate: thisUpdate,
		NextUpdate: nextUpdate,
	}
	a.observations = append(a.observations, resp)
}

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

func (a *OCSPAnalyzer) GetObservations() []OCSPResponse {
	return a.observations
}
