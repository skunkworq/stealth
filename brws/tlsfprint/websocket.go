package tlsfprint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

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

type WebSocketAnalyzer struct {
	observations []WebSocketObservation
}

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

func NewWebSocketAnalyzer() *WebSocketAnalyzer {
	return &WebSocketAnalyzer{
		observations: make([]WebSocketObservation, 0),
	}
}

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

func (a *WebSocketAnalyzer) GetObservations() []WebSocketObservation {
	return a.observations
}

func (a *WebSocketAnalyzer) GetUniqueFingerprints() map[string]bool {
	unique := make(map[string]bool)
	for _, obs := range a.observations {
		unique[obs.JA3W] = true
	}
	return unique
}

func (a *WebSocketAnalyzer) GetBrowserDistribution() map[string]int {
	dist := make(map[string]int)
	for _, obs := range a.observations {
		dist[obs.DetectedBrowser]++
	}
	return dist
}

var wsVersionPattern = regexp.MustCompile(`^(7|8|13)$`)
var wsKeyPattern = regexp.MustCompile(`^[A-Za-z0-9+/=]{22,24}$`)

func ValidateWebSocketKey(key string) bool {
	if key == "" {
		return false
	}
	return wsKeyPattern.MatchString(key)
}

func ValidateWebSocketVersion(version string) bool {
	if version == "" {
		return false
	}
	return wsVersionPattern.MatchString(version)
}

func GenerateWebSocketKey() string {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i * 7 % 256)
	}
	return hex.EncodeToString(key)[:22]
}

type WebSocketHandshakeAnalyzer struct {
	observations []WebSocketHandshakeObservation
}

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

func NewWebSocketHandshakeAnalyzer() *WebSocketHandshakeAnalyzer {
	return &WebSocketHandshakeAnalyzer{
		observations: make([]WebSocketHandshakeObservation, 0),
	}
}

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

func (a *WebSocketHandshakeAnalyzer) GetObservations() []WebSocketHandshakeObservation {
	return a.observations
}

func (a *WebSocketHandshakeAnalyzer) GetValidCount() int {
	count := 0
	for _, obs := range a.observations {
		if obs.IsValid {
			count++
		}
	}
	return count
}

func (a *WebSocketHandshakeAnalyzer) GetInvalidCount() int {
	count := 0
	for _, obs := range a.observations {
		if !obs.IsValid {
			count++
		}
	}
	return count
}

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

type WebSocketFrameAnalyzer struct {
	frames []WebSocketFrameFingerprint
}

func NewWebSocketFrameAnalyzer() *WebSocketFrameAnalyzer {
	return &WebSocketFrameAnalyzer{
		frames: make([]WebSocketFrameFingerprint, 0),
	}
}

func (a *WebSocketFrameAnalyzer) Record(frame WebSocketFrameFingerprint) {
	a.frames = append(a.frames, frame)
}

func (a *WebSocketFrameAnalyzer) GetFrames() []WebSocketFrameFingerprint {
	return a.frames
}

func (a *WebSocketFrameAnalyzer) GetOpCodeDistribution() map[uint8]int {
	dist := make(map[uint8]int)
	for _, frame := range a.frames {
		dist[frame.OpCode]++
	}
	return dist
}

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
