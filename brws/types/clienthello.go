// Package types provides shared fingerprint data structures
package types

// TLSExtension represents a single TLS extension
type TLSExtension struct {
	Type uint16 `json:"type"`
	Data []byte `json:"data,omitempty"`
}

// ClientHello represents a parsed TLS ClientHello message
// This is the shared type used by both proxy and lab packages
type ClientHello struct {
	Version            uint16         `json:"version"`
	Random             []byte         `json:"random,omitempty"`
	SessionID          []byte         `json:"session_id,omitempty"`
	CipherSuites       []uint16       `json:"cipher_suites"`
	CompressionMethods []uint8        `json:"compression_methods"`
	Extensions         []TLSExtension `json:"extensions"`
	ServerName         string         `json:"server_name,omitempty"`
	SupportedGroups    []uint16       `json:"supported_groups,omitempty"`
	ALPNProtocols      []string       `json:"alpn_protocols,omitempty"`
	ALPS               string         `json:"alps,omitempty"`
	KeyShareGroups     []uint16       `json:"key_share_groups,omitempty"`

	// Raw bytes for exact replay
	Raw []byte `json:"raw,omitempty"`
}
