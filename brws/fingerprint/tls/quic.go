package tlsfprint

import (
	"fmt"
	"strings"
	"time"
)

// QUICFingerprint represents a complete fingerprint of a QUIC connection,
// including TLS handshake parameters and transport characteristics.
type QUICFingerprint struct {
	Version string

	TLSSupportedVersions []string

	CipherSuites []uint16

	Extensions []uint16

	KeyShareGroups []uint16

	ALPN string

	OriginalConnectionID []byte

	StatelessResetToken []byte

	TransportParams *QUICTransportParams
}

// QUICTransportParams contains QUIC transport parameters exchanged during
// the handshake, which can be used for fingerprinting client implementations.
type QUICTransportParams struct {
	InitialMaxStreamDataBidiLocal  uint64
	InitialMaxStreamDataBidiRemote uint64
	InitialMaxStreamDataUni        uint64
	InitialMaxStreamsBidiLocal     uint64
	InitialMaxStreamsBidiRemote    uint64
	InitialMaxStreamsUni           uint64
	MaxAckDelay                    uint64
	MaxIdleTimeout                 uint64
	AckDelayExponent               uint64
	MaxAckDelayExponent            uint64
	ActiveConnectionIDLimit        uint64
	MaxUDPPayloadSize              uint64
	MaxData                        uint64
	MaxStreamData                  uint64

	DisableMigration bool
	EnableQuickUDP   bool

	OriginalConnectionID []byte
	StatelessResetToken  []byte

	PreferredAddress *PreferredAddress

	CustomParameters map[uint64][]byte
}

// PreferredAddress represents a preferred address for connection migration
// as specified in QUIC transport parameters.
type PreferredAddress struct {
	IPv4Address         string
	IPv6Address         string
	Port                uint16
	ConnectionID        []byte
	StatelessResetToken []byte
}

// ToFingerprintString converts the QUIC fingerprint to a string representation
// suitable for comparison and hashing.
func (q *QUICFingerprint) ToFingerprintString() string {
	var parts []string

	parts = append(parts, fmt.Sprintf("v=%s", q.Version))

	if len(q.CipherSuites) > 0 {
		var ciphers []string
		for _, c := range q.CipherSuites {
			ciphers = append(ciphers, fmt.Sprintf("%04x", c))
		}
		parts = append(parts, fmt.Sprintf("c=%s", strings.Join(ciphers, ",")))
	}

	if len(q.Extensions) > 0 {
		var exts []string
		for _, e := range q.Extensions {
			exts = append(exts, fmt.Sprintf("%d", e))
		}
		parts = append(parts, fmt.Sprintf("e=%s", strings.Join(exts, ",")))
	}

	if q.ALPN != "" {
		parts = append(parts, fmt.Sprintf("a=%s", q.ALPN))
	}

	return strings.Join(parts, ";")
}

// Hash returns a SHA-256 hash of the fingerprint string representation.
func (q *QUICFingerprint) Hash() string {
	return sha256Hash(q.ToFingerprintString())
}

// HTTP3Fingerprint extends QUICFingerprint with HTTP/3 specific settings
// and header compression parameters for browser identification.
type HTTP3Fingerprint struct {
	QUICFingerprint

	Settings []HTTP3Setting

	HeaderCompression *HTTP3HeaderCompression

	MaxFieldSectionSize uint64
}

// HTTP3Setting represents a single HTTP/3 SETTINGS frame parameter.
type HTTP3Setting struct {
	ID    uint64
	Value uint64
}

// HTTP3HeaderCompression contains QPACK header compression settings
// used in HTTP/3 connections.
type HTTP3HeaderCompression struct {
	MaxTableSize     uint64
	MaxTableCapacity uint64
	DynamicTableSize uint64
}

// HTTP3Chrome is the known HTTP/3 fingerprint for Google Chrome.
var HTTP3Chrome = HTTP3Fingerprint{
	Settings: []HTTP3Setting{
		{ID: 0x1, Value: 0x1000},
		{ID: 0x2, Value: 0x1000},
		{ID: 0x3, Value: 0x100},
		{ID: 0x4, Value: 0x5},
	},
	HeaderCompression: &HTTP3HeaderCompression{
		MaxTableSize:     0x1000,
		MaxTableCapacity: 0x1000,
		DynamicTableSize: 0x0,
	},
	MaxFieldSectionSize: 0x1000,
}

// HTTP3Firefox is the known HTTP/3 fingerprint for Mozilla Firefox.
var HTTP3Firefox = HTTP3Fingerprint{
	Settings: []HTTP3Setting{
		{ID: 0x1, Value: 0x2000},
		{ID: 0x2, Value: 0x2000},
		{ID: 0x3, Value: 0x100},
		{ID: 0x4, Value: 0x3},
	},
	HeaderCompression: &HTTP3HeaderCompression{
		MaxTableSize:     0x2000,
		MaxTableCapacity: 0x2000,
		DynamicTableSize: 0x0,
	},
	MaxFieldSectionSize: 0x2000,
}

// HTTP3Safari is the known HTTP/3 fingerprint for Apple Safari.
var HTTP3Safari = HTTP3Fingerprint{
	Settings: []HTTP3Setting{
		{ID: 0x1, Value: 0x800},
		{ID: 0x2, Value: 0x800},
		{ID: 0x3, Value: 0x100},
		{ID: 0x4, Value: 0x3},
	},
	HeaderCompression: &HTTP3HeaderCompression{
		MaxTableSize:     0x800,
		MaxTableCapacity: 0x800,
		DynamicTableSize: 0x0,
	},
	MaxFieldSectionSize: 0x800,
}

// GetHTTP3Signatures returns a map of known browser HTTP/3 signatures
// keyed by browser name (chrome, firefox, safari).
func GetHTTP3Signatures() map[string]HTTP3Fingerprint {
	return map[string]HTTP3Fingerprint{
		"chrome":  HTTP3Chrome,
		"firefox": HTTP3Firefox,
		"safari":  HTTP3Safari,
	}
}

// QUICObservation represents a single observed QUIC packet with metadata
// useful for fingerprinting and analysis.
type QUICObservation struct {
	Timestamp    time.Time
	ConnectionID string
	RemoteAddr   string

	Version string

	PacketLength int
	PacketNumber uint64

	LongHeader bool
	PacketType string

	TLSExtensions []uint16

	SpinBit      bool
	ReservedBits uint8

	RawData []byte
}

// ToFingerprintString converts the QUIC observation to a string representation
// for comparison and hashing.
func (q *QUICObservation) ToFingerprintString() string {
	var parts []string

	parts = append(parts, fmt.Sprintf("v=%s", q.Version))
	parts = append(parts, fmt.Sprintf("l=%d", q.PacketLength))
	parts = append(parts, fmt.Sprintf("h=%t", q.LongHeader))
	parts = append(parts, fmt.Sprintf("t=%s", q.PacketType))

	if len(q.TLSExtensions) > 0 {
		var exts []string
		for _, e := range q.TLSExtensions {
			exts = append(exts, fmt.Sprintf("%d", e))
		}
		parts = append(parts, fmt.Sprintf("e=%s", strings.Join(exts, ",")))
	}

	return strings.Join(parts, ";")
}

// DetectBrowser attempts to identify the browser based on TLS extension
// patterns in the QUIC observation. Returns "chrome", "firefox", or "unknown".
func (q *QUICObservation) DetectBrowser() string {
	hasGREASE := false
	for _, e := range q.TLSExtensions {
		if e >= 0x0a0a && e <= 0x0afa {
			hasGREASE = true
			break
		}
	}

	hasALPN := false
	for _, e := range q.TLSExtensions {
		if e == 16 {
			hasALPN = true
			break
		}
	}

	if hasGREASE && hasALPN {
		return "chrome"
	}
	if !hasGREASE && hasALPN {
		return "firefox"
	}

	return "unknown"
}

// QUICAnalyzer collects and analyzes QUIC observations to generate statistics
// about QUIC traffic patterns.
type QUICAnalyzer struct {
	observations []QUICObservation
}

// NewQUICAnalyzer creates a new QUICAnalyzer instance ready to collect observations.
func NewQUICAnalyzer() *QUICAnalyzer {
	return &QUICAnalyzer{
		observations: make([]QUICObservation, 0),
	}
}

// Record adds a QUIC observation to the analyzer's collection.
func (a *QUICAnalyzer) Record(obs *QUICObservation) {
	a.observations = append(a.observations, *obs)
}

// GetStats returns aggregated statistics about all recorded observations.
func (a *QUICAnalyzer) GetStats() *QUICStats {
	stats := &QUICStats{
		TotalPackets: len(a.observations),
		ByVersion:    make(map[string]int),
		ByBrowser:    make(map[string]int),
	}

	for _, obs := range a.observations {
		stats.ByVersion[obs.Version]++
		stats.ByBrowser[obs.DetectBrowser()]++
	}

	return stats
}

// QUICStats contains aggregated statistics from QUIC observations.
type QUICStats struct {
	TotalPackets int
	ByVersion    map[string]int
	ByBrowser    map[string]int
}

// HTTP3SettingsFingerprint represents the fingerprint of HTTP/3 SETTINGS
// frame parameters for browser identification.
type HTTP3SettingsFingerprint struct {
	SettingsField0x1 uint64
	SettingsField0x2 uint64
	SettingsField0x3 uint64
	SettingsField0x4 uint64
	SettingsField0x5 uint64

	MaxFieldSectionSize uint64

	QPACKMaxTableCapacity uint64
	QPACKMaxBlockSize     uint64
	QPACKDynamicCapacity  uint64
}

// ToFingerprintString converts the HTTP/3 settings fingerprint to a string
// representation suitable for comparison.
func (s *HTTP3SettingsFingerprint) ToFingerprintString() string {
	return fmt.Sprintf("s1=%d;s2=%d;s3=%d;s4=%d;s5=%d;m=%d;qt=%d;qb=%d;qd=%d",
		s.SettingsField0x1,
		s.SettingsField0x2,
		s.SettingsField0x3,
		s.SettingsField0x4,
		s.SettingsField0x5,
		s.MaxFieldSectionSize,
		s.QPACKMaxTableCapacity,
		s.QPACKMaxBlockSize,
		s.QPACKDynamicCapacity,
	)
}

// Hash returns a SHA-256 hash of the HTTP/3 settings fingerprint string.
func (s *HTTP3SettingsFingerprint) Hash() string {
	return sha256Hash(s.ToFingerprintString())
}

// ParseHTTP3Settings parses raw HTTP/3 SETTINGS frame data and extracts
// the settings into a fingerprint structure.
func ParseHTTP3Settings(data []byte) (*HTTP3SettingsFingerprint, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("settings too short")
	}

	settings := &HTTP3SettingsFingerprint{}

	offset := 0
	for offset < len(data)-1 {
		settingID := data[offset]
		offset++

		var value uint64
		if settingID&0xc0 == 0xc0 {
			varLength := int(data[offset] & 0x3f)
			offset++
			if offset+varLength > len(data) {
				break
			}
			value = 0
			for i := 0; i < varLength; i++ {
				value = value<<8 | uint64(data[offset+i])
			}
			offset += varLength
		} else {
			if offset+1 > len(data) {
				break
			}
			value = uint64(data[offset])<<8 | uint64(data[offset+1])
			offset += 2
		}

		switch settingID {
		case 0x1:
			settings.SettingsField0x1 = value
		case 0x2:
			settings.SettingsField0x2 = value
		case 0x3:
			settings.SettingsField0x3 = value
		case 0x4:
			settings.SettingsField0x4 = value
		case 0x5:
			settings.SettingsField0x5 = value
		}
	}

	return settings, nil
}

// HTTP3FrameFingerprint represents the fingerprint of an HTTP/3 frame
// for protocol analysis and identification.
type HTTP3FrameFingerprint struct {
	Type string

	Length uint64

	StreamID uint64

	FrameSpecific map[string]interface{}
}

// ToFingerprintString converts the HTTP/3 frame fingerprint to a string
// representation for comparison.
func (f *HTTP3FrameFingerprint) ToFingerprintString() string {
	frameType := f.Type
	if frameType == "" {
		frameType = "unknown"
	}

	result := fmt.Sprintf("t=%s;l=%d", frameType, f.Length)
	if f.StreamID > 0 {
		result += fmt.Sprintf(";s=%d", f.StreamID)
	}

	return result
}

// KnownHTTP3FrameTypes maps HTTP/3 frame type hex values to their human-readable names.
var KnownHTTP3FrameTypes = map[string]string{
	"0x0":  "DATA",
	"0x1":  "HEADERS",
	"0x3":  "CANCEL_PUSH",
	"0x4":  "SETTINGS",
	"0x5":  "PUSH_PROMISE",
	"0x6":  "GOAWAY",
	"0x7":  "MAX_PUSH_ID",
	"0x8":  "WEBTRANSPORT_MAX_DATA",
	"0x9":  "WEBTRANSPORT_MAX_STREAMS",
	"0xa":  "WEBTRANSPORT_SETUP",
	"0xd":  "BLOCKED",
	"0xe":  "STREAMS_BLOCKED",
	"0xf":  "NEW_CONNECTION_ID",
	"0x10": "NEW_TOKEN",
	"0x11": "PATH_RESPONSE",
	"0x12": "PATH_CHALLENGE",
	"0x13": "STOP_SENDING",
	"0x14": "MESSAGE",
	"0x15": "CRYPTO",
	"0x16": "NEW_STREAM",
	"0x17": "MAX_STREAM_DATA",
	"0x18": "STREAM_DATA",
	"0x19": "STREAM_CLOSE",
	"0x1a": "STREAMS_BLOCKED",
	"0x1b": "MAX_DATA",
	"0x1c": "CONNECTION_CLOSE",
	"0x1d": "HANDSHAKE_DONE",
	"0x1e": "EXTENSION",
}

// ParseFrameType converts a frame type byte to its human-readable name.
// Returns the hex representation if the type is not known.
func ParseFrameType(t byte) string {
	if name, ok := KnownHTTP3FrameTypes[fmt.Sprintf("0x%x", t)]; ok {
		return name
	}
	return fmt.Sprintf("0x%x", t)
}

// QUICConnectionAnalyzer tracks packets and frames across a QUIC connection
// to provide connection-level statistics and analysis.
type QUICConnectionAnalyzer struct {
	packets   []QUICObservation
	frames    []HTTP3FrameFingerprint
	startTime time.Time
	endTime   time.Time
}

// NewQUICConnectionAnalyzer creates a new QUICConnectionAnalyzer instance
// ready to track connection data.
func NewQUICConnectionAnalyzer() *QUICConnectionAnalyzer {
	return &QUICConnectionAnalyzer{
		packets: make([]QUICObservation, 0),
		frames:  make([]HTTP3FrameFingerprint, 0),
	}
}

// AddPacket adds a QUIC packet observation to the connection analyzer.
func (a *QUICConnectionAnalyzer) AddPacket(obs QUICObservation) {
	if a.startTime.IsZero() {
		a.startTime = obs.Timestamp
	}
	a.endTime = obs.Timestamp
	a.packets = append(a.packets, obs)
}

// AddFrame adds an HTTP/3 frame fingerprint to the connection analyzer.
func (a *QUICConnectionAnalyzer) AddFrame(frame HTTP3FrameFingerprint) {
	a.frames = append(a.frames, frame)
}

// GetConnectionStats returns aggregated statistics about the tracked connection.
func (a *QUICConnectionAnalyzer) GetConnectionStats() *QUICConnectionStats {
	stats := &QUICConnectionStats{
		Duration:        a.endTime.Sub(a.startTime),
		TotalPackets:    len(a.packets),
		TotalFrames:     len(a.frames),
		FrameTypeCounts: make(map[string]int),
	}

	var totalPacketSize int
	for _, p := range a.packets {
		totalPacketSize += p.PacketLength
		stats.PacketLengths = append(stats.PacketLengths, p.PacketLength)
	}
	if len(a.packets) > 0 {
		stats.AvgPacketSize = totalPacketSize / len(a.packets)
	}

	for _, f := range a.frames {
		stats.FrameTypeCounts[f.Type]++
	}

	return stats
}

// QUICConnectionStats contains aggregated statistics for a QUIC connection.
type QUICConnectionStats struct {
	Duration        time.Duration
	TotalPackets    int
	TotalFrames     int
	AvgPacketSize   int
	PacketLengths   []int
	FrameTypeCounts map[string]int
}
