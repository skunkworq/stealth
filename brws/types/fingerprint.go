// Package types provides shared fingerprint data structures
package types

import (
	"time"
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
	Metadata map[string]string        `json:"metadata,omitempty"` // For FSM ML Labels
}

// TLSFingerprint captures TLS ClientHello details
type TLSFingerprint struct {
	Version         uint16          `json:"version"`
	VersionName     string          `json:"version_name"`
	CipherSuites    []CipherInfo    `json:"cipher_suites"`
	Extensions      []ExtensionInfo `json:"extensions"`
	GREASE          []GREASEInfo    `json:"grease,omitempty"`
	SupportedGroups []uint16        `json:"supported_groups"`
	GroupNames      []string        `json:"group_names"`
	ALPN            []string        `json:"alpn"`
	ALPS            string          `json:"alps,omitempty"`
	CertCompression []string        `json:"cert_compression,omitempty"`
	KeyShareGroups  []uint16        `json:"key_share_groups"`

	// Derived fingerprints
	JA3Hash   string `json:"ja3_hash"`
	JA3String string `json:"ja3_string"`
	JA4       string `json:"ja4"`

	// Raw for exact replay
	RawClientHello string `json:"raw_client_hello,omitempty"`

	// Certificate chain info
	RootCA         string `json:"root_ca,omitempty"`
	IntermediateCA string `json:"intermediate_ca,omitempty"`
}

// CipherInfo with position
type CipherInfo struct {
	Value    uint16 `json:"value"`
	Name     string `json:"name"`
	Position int    `json:"position"`
	IsGREASE bool   `json:"is_grease,omitempty"`
}

// ExtensionInfo with position
type ExtensionInfo struct {
	Type     uint16 `json:"type"`
	Name     string `json:"name"`
	Position int    `json:"position"`
	Data     []byte `json:"data,omitempty"`
	IsGREASE bool   `json:"is_grease,omitempty"`
}

// GREASEInfo tracks GREASE positions
type GREASEInfo struct {
	Value    uint16 `json:"value"`
	Position int    `json:"position"`
	Context  string `json:"context"` // "extension", "cipher", "group"
}

// HTTP2Fingerprint captures HTTP/2-specific signals
type HTTP2Fingerprint struct {
	Settings       []HTTP2Setting     `json:"settings"`
	WindowUpdates  []WindowUpdateInfo `json:"window_updates"`
	PseudoHeaders  []string           `json:"pseudo_header_order"`
	HeaderOrder    []string           `json:"header_order"`
	FrameSequence  []FrameInfo        `json:"frame_sequence"`
	StreamPriority *StreamPriority    `json:"stream_priority,omitempty"`
}

// HTTP2Setting with position
type HTTP2Setting struct {
	ID       uint16 `json:"id"`
	Name     string `json:"name"`
	Value    uint32 `json:"value"`
	Position int    `json:"position"`
}

// WindowUpdateInfo captures WINDOW_UPDATE frames
type WindowUpdateInfo struct {
	StreamID  uint32        `json:"stream_id"`
	Increment uint32        `json:"increment"`
	Timing    time.Duration `json:"timing_ms"`
}

// FrameInfo for sequence analysis
type FrameInfo struct {
	Type     string        `json:"type"`
	TypeID   uint8         `json:"type_id"`
	Flags    uint8         `json:"flags"`
	StreamID uint32        `json:"stream_id"`
	Length   uint32        `json:"length"`
	Timing   time.Duration `json:"timing_ms"`
}

// StreamPriority info
type StreamPriority struct {
	Weight    uint8 `json:"weight"`
	Exclusive bool  `json:"exclusive"`
}

// HTTPFingerprint captures HTTP-layer signals
type HTTPFingerprint struct {
	Method      string       `json:"method"`
	Path        string       `json:"path"`
	Protocol    string       `json:"protocol"`
	Headers     []HeaderInfo `json:"headers"`
	UserAgent   string       `json:"user_agent"`
	Accept      string       `json:"accept"`
	AcceptLang  string       `json:"accept_language"`
	AcceptEnc   string       `json:"accept_encoding"`
	ClientHints *ClientHints `json:"client_hints,omitempty"`
	CookieCount int          `json:"cookie_count"`
}

// HTTPResponseFingerprint captures HTTP response details
type HTTPResponseFingerprint struct {
	StatusCode int          `json:"status_code"`
	Status     string       `json:"status"`
	Protocol   string       `json:"protocol"`
	Headers    []HeaderInfo `json:"headers"`
	BodyLength int64        `json:"body_length"`
}

// HeaderInfo preserves order
type HeaderInfo struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Position int    `json:"position"`
	IsPseudo bool   `json:"is_pseudo,omitempty"`
}

// ClientHints for Chrome
type ClientHints struct {
	SecCHUA         string `json:"sec_ch_ua,omitempty"`
	SecCHUAMobile   string `json:"sec_ch_ua_mobile,omitempty"`
	SecCHUAPlatform string `json:"sec_ch_ua_platform,omitempty"`
}

// BehaviorFingerprint captures timing and patterns
type BehaviorFingerprint struct {
	ConnectionTiming ConnectionTiming `json:"connection_timing"`
	RequestPattern   RequestPattern   `json:"request_pattern"`
}

// ConnectionTiming details
type ConnectionTiming struct {
	TCPEstablished time.Duration `json:"tcp_established_ms"`
	TLSHandshake   time.Duration `json:"tls_handshake_ms"`
	FirstByte      time.Duration `json:"first_byte_ms"`
	TotalTime      time.Duration `json:"total_time_ms"`
}

// RequestPattern analysis
type RequestPattern struct {
	ConcurrentStreams int           `json:"concurrent_streams"`
	StreamDependency  uint32        `json:"stream_dependency,omitempty"`
	RequestPacing     time.Duration `json:"request_pacing_ms"`
}
