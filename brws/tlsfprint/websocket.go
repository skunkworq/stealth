package tlsfprint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// WebSocketFingerprint represents a fingerprint of a WebSocket connection,
// capturing the key handshake headers and properties used for browser identification.
type WebSocketFingerprint struct {
	Version           string
	SubProtocols      []string
	Extensions        []string
	Headers           map[string]string
	Origin            string
	SecWebSocketKey   string
	SecWebSocketProto string
	JA3W              string
}

// CalculateWebSocketFingerprint computes a fingerprint string from WebSocket handshake headers.
// It concatenates headers in a specific order to create a consistent identifier.
func CalculateWebSocketFingerprint(headers map[string]string) string {
	var parts []string

	order := []string{
		"host", "origin", "connection", "upgrade",
		"sec-websocket-version", "sec-websocket-key", "sec-websocket-protocol",
		"sec-websocket-extensions", "sec-websocket-origin",
		"user-agent", "accept", "accept-language", "accept-encoding",
	}

	for _, h := range order {
		if v, ok := headers[strings.ToLower(h)]; ok && v != "" {
			parts = append(parts, fmt.Sprintf("%s:%s", h, v))
		}
	}

	return strings.Join(parts, ";")
}

// CalculateJA3W calculates the JA3W hash of WebSocket headers.
// It sorts headers alphabetically and returns a SHA256 hash truncated to 32 characters.
func CalculateJA3W(headers map[string]string) string {
	var parts []string

	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, strings.ToLower(k))
	}
	sort.Strings(keys)

	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s:%s", k, headers[k]))
	}

	combined := strings.Join(parts, ",")
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:])[:32]
}

// WebSocketSignature represents a known browser signature for WebSocket connections,
// used to match and identify the browser type from handshake characteristics.
type WebSocketSignature struct {
	Name                 string
	Browser              string
	Version              string
	SubProtocols         []string
	Extensions           []string
	Origin               string
	SecWebSocketProtocol bool
	JA3W                 string
}

// WebSocketSignatures contains a mapping of known browser signatures for WebSocket fingerprinting.
// These signatures are used to identify browsers based on their WebSocket handshake characteristics.
var WebSocketSignatures = map[string]*WebSocketSignature{
	"chrome-120": {
		Name:                 "Chrome 120 WebSocket",
		Browser:              "chrome",
		Version:              "120.0",
		SubProtocols:         []string{},
		Extensions:           []string{"permessage-deflate", "client_max_window_bits"},
		Origin:               "",
		SecWebSocketProtocol: true,
	},
	"firefox-120": {
		Name:                 "Firefox 120 WebSocket",
		Browser:              "firefox",
		Version:              "120.0",
		SubProtocols:         []string{},
		Extensions:           []string{"permessage-deflate"},
		Origin:               "",
		SecWebSocketProtocol: true,
	},
	"safari-17": {
		Name:                 "Safari 17 WebSocket",
		Browser:              "safari",
		Version:              "17.1",
		SubProtocols:         []string{},
		Extensions:           []string{"permessage-deflate"},
		Origin:               "",
		SecWebSocketProtocol: false,
	},
	"edge-120": {
		Name:                 "Edge 120 WebSocket",
		Browser:              "edge",
		Version:              "120.0",
		SubProtocols:         []string{},
		Extensions:           []string{"permessage-deflate", "client_max_window_bits"},
		Origin:               "",
		SecWebSocketProtocol: true,
	},
}

// DetectBrowserFromWebSocket attempts to identify the browser from WebSocket handshake headers.
// It checks sec-websocket-extensions and the User-Agent header to determine the browser type.
// Returns "chrome", "edge", "firefox", "safari", or "unknown".
func DetectBrowserFromWebSocket(headers map[string]string) string {
	exts := headers["sec-websocket-extensions"]
	extsLower := strings.ToLower(exts)
	if strings.Contains(extsLower, "client_max_window_bits") {
		return "chrome"
	}

	ua := headers["user-agent"]
	if ua == "" {
		ua = headers["User-Agent"]
	}
	if ua == "" {
		return "unknown"
	}

	uaLower := strings.ToLower(ua)

	switch {
	case strings.Contains(uaLower, "edg/"):
		return "edge"
	case strings.Contains(uaLower, "chrome/"):
		return "chrome"
	case strings.Contains(uaLower, "firefox/"):
		return "firefox"
	case strings.Contains(uaLower, "safari/") && !strings.Contains(uaLower, "chrome"):
		return "safari"
	}

	return "unknown"
}

// WebSocketAnalyzer collects and analyzes WebSocket handshake observations
// to identify patterns and browser fingerprints.
type WebSocketAnalyzer struct {
	observations []WebSocketObservation
}

// WebSocketObservation represents a single observed WebSocket handshake
// with extracted metadata and calculated fingerprints.
type WebSocketObservation struct {
	Timestamp       int64
	Headers         map[string]string
	Version         string
	SubProtocols    []string
	Extensions      []string
	Origin          string
	JA3W            string
	DetectedBrowser string
	SignatureMatch  *WebSocketSignature
}

// NewWebSocketAnalyzer creates a new WebSocketAnalyzer with an empty observations list.
func NewWebSocketAnalyzer() *WebSocketAnalyzer {
	return &WebSocketAnalyzer{
		observations: make([]WebSocketObservation, 0),
	}
}

// Record captures a WebSocket handshake observation from the provided headers,
// extracts relevant fields, calculates JA3W fingerprint, and stores the observation.
// Returns the recorded observation.
func (a *WebSocketAnalyzer) Record(headers map[string]string) WebSocketObservation {
	exts := strings.Split(headers["sec-websocket-extensions"], ",")
	for i := range exts {
		exts[i] = strings.TrimSpace(exts[i])
	}

	subProtos := strings.Split(headers["sec-websocket-protocol"], ",")
	for i := range subProtos {
		subProtos[i] = strings.TrimSpace(subProtos[i])
	}

	obs := WebSocketObservation{
		Headers:         headers,
		Version:         headers["sec-websocket-version"],
		SubProtocols:    subProtos,
		Extensions:      exts,
		Origin:          headers["origin"],
		JA3W:            CalculateJA3W(headers),
		DetectedBrowser: DetectBrowserFromWebSocket(headers),
	}
	a.observations = append(a.observations, obs)
	return obs
}

// GetObservations returns all recorded WebSocket observations.
func (a *WebSocketAnalyzer) GetObservations() []WebSocketObservation {
	return a.observations
}

// GetUniqueFingerprints returns a map of unique JA3W fingerprints from all observations.
func (a *WebSocketAnalyzer) GetUniqueFingerprints() map[string]bool {
	unique := make(map[string]bool)
	for _, obs := range a.observations {
		unique[obs.JA3W] = true
	}
	return unique
}

// GetBrowserDistribution returns a count of detected browsers from all observations.
func (a *WebSocketAnalyzer) GetBrowserDistribution() map[string]int {
	dist := make(map[string]int)
	for _, obs := range a.observations {
		dist[obs.DetectedBrowser]++
	}
	return dist
}

var (
	wsVersionPattern = regexp.MustCompile(`^(7|8|13)$`)
	wsKeyPattern     = regexp.MustCompile(`^[A-Za-z0-9+/=]{22,24}$`)
)

// ValidateWebSocketKey validates that a WebSocket key matches the expected format.
// Returns true if the key is valid (22-24 base64 characters).
func ValidateWebSocketKey(key string) bool {
	if key == "" {
		return false
	}
	return wsKeyPattern.MatchString(key)
}

// ValidateWebSocketVersion validates that a WebSocket version is supported.
// Returns true for valid versions: 7, 8, or 13.
func ValidateWebSocketVersion(version string) bool {
	if version == "" {
		return false
	}
	return wsVersionPattern.MatchString(version)
}

// GenerateWebSocketKey generates a new WebSocket key for handshake.
// Returns a 22-character base64-encoded key.
func GenerateWebSocketKey() string {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i * 7 % 256)
	}
	return hex.EncodeToString(key)[:22]
}

// WebSocketHandshakeAnalyzer analyzes WebSocket handshake requests.
type WebSocketHandshakeAnalyzer struct {
	observations []WebSocketHandshakeObservation
}

// WebSocketHandshakeObservation represents a single observed WebSocket handshake.
type WebSocketHandshakeObservation struct {
	Timestamp           int64
	Method              string
	Path                string
	Headers             map[string]string
	Host                string
	Origin              string
	SecWebSocketKey     string
	SecWebSocketVersion string
	Upgrade             string
	Connection          string
	IsValid             bool
}

// NewWebSocketHandshakeAnalyzer creates a new WebSocketHandshakeAnalyzer.
func NewWebSocketHandshakeAnalyzer() *WebSocketHandshakeAnalyzer {
	return &WebSocketHandshakeAnalyzer{
		observations: make([]WebSocketHandshakeObservation, 0),
	}
}

// Record captures a WebSocket handshake observation from the provided request details.
// Validates the handshake and returns the recorded observation.
func (a *WebSocketHandshakeAnalyzer) Record(method, path string, headers map[string]string) WebSocketHandshakeObservation {
	obs := WebSocketHandshakeObservation{
		Method:              method,
		Path:                path,
		Headers:             headers,
		Host:                headers["host"],
		Origin:              headers["origin"],
		SecWebSocketKey:     headers["sec-websocket-key"],
		SecWebSocketVersion: headers["sec-websocket-version"],
		Upgrade:             headers["upgrade"],
		Connection:          headers["connection"],
		IsValid: method == "GET" &&
			strings.ToLower(headers["upgrade"]) == "websocket" &&
			strings.ToLower(headers["connection"]) == "upgrade" &&
			ValidateWebSocketKey(headers["sec-websocket-key"]),
	}
	a.observations = append(a.observations, obs)
	return obs
}

// GetObservations returns all recorded WebSocket handshake observations.
func (a *WebSocketHandshakeAnalyzer) GetObservations() []WebSocketHandshakeObservation {
	return a.observations
}

// GetValidCount returns the number of valid WebSocket handshakes observed.
func (a *WebSocketHandshakeAnalyzer) GetValidCount() int {
	count := 0
	for _, obs := range a.observations {
		if obs.IsValid {
			count++
		}
	}
	return count
}

// GetInvalidCount returns the number of invalid WebSocket handshakes observed.
func (a *WebSocketHandshakeAnalyzer) GetInvalidCount() int {
	count := 0
	for _, obs := range a.observations {
		if !obs.IsValid {
			count++
		}
	}
	return count
}

// GetOriginDistribution returns a count of origins from all observations.
// "none" is used for observations without an origin.
func (a *WebSocketHandshakeAnalyzer) GetOriginDistribution() map[string]int {
	dist := make(map[string]int)
	for _, obs := range a.observations {
		if obs.Origin != "" {
			dist[obs.Origin]++
		} else {
			dist["none"]++
		}
	}
	return dist
}

// WebSocketFrameFingerprint represents a fingerprint of a WebSocket frame.
type WebSocketFrameFingerprint struct {
	OpCode        uint8
	Masked        bool
	PayloadLength int64
	Fin           bool
	RSV1          bool
	RSV2          bool
	RSV3          bool
}

func (f *WebSocketFrameFingerprint) String() string {
	flags := ""
	if f.Fin {
		flags += "FIN "
	}
	if f.RSV1 {
		flags += "RSV1 "
	}
	if f.RSV2 {
		flags += "RSV2 "
	}
	if f.RSV3 {
		flags += "RSV3 "
	}
	if f.Masked {
		flags += "MASKED "
	}
	return fmt.Sprintf("OPCODE:%d FLAGS:[%s] PAYLOAD:%d", f.OpCode, strings.TrimSpace(flags), f.PayloadLength)
}

// WebSocketFrameAnalyzer analyzes WebSocket frame patterns.
type WebSocketFrameAnalyzer struct {
	frames []WebSocketFrameFingerprint
}

// NewWebSocketFrameAnalyzer creates a new WebSocketFrameAnalyzer.
func NewWebSocketFrameAnalyzer() *WebSocketFrameAnalyzer {
	return &WebSocketFrameAnalyzer{
		frames: make([]WebSocketFrameFingerprint, 0),
	}
}

// Record adds a WebSocket frame fingerprint to the analyzer.
func (a *WebSocketFrameAnalyzer) Record(frame WebSocketFrameFingerprint) {
	a.frames = append(a.frames, frame)
}

// GetFrames returns all recorded WebSocket frame fingerprints.
func (a *WebSocketFrameAnalyzer) GetFrames() []WebSocketFrameFingerprint {
	return a.frames
}

// GetOpCodeDistribution returns a count of each opcode from all recorded frames.
func (a *WebSocketFrameAnalyzer) GetOpCodeDistribution() map[uint8]int {
	dist := make(map[uint8]int)
	for _, frame := range a.frames {
		dist[frame.OpCode]++
	}
	return dist
}

// GetMaskedRatio returns the ratio of masked frames to total frames.
func (a *WebSocketFrameAnalyzer) GetMaskedRatio() float64 {
	if len(a.frames) == 0 {
		return 0
	}
	masked := 0
	for _, frame := range a.frames {
		if frame.Masked {
			masked++
		}
	}
	return float64(masked) / float64(len(a.frames))
}
