// Package config provides configuration structures for fingerprint-based impersonation
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// FingerprintConfig represents a complete fingerprint configuration
type FingerprintConfig struct {
	Name        string          `json:"name"`
	Version     string          `json:"version"`
	Description string          `json:"description"`
	Tags        []string        `json:"tags,omitempty"`
	Browser     BrowserIdentity `json:"browser"`
	OS          OSIdentity      `json:"os"`
	TLS         *TLSConfig      `json:"tls,omitempty"`
	HTTP2       *HTTP2Config    `json:"http2,omitempty"`
	HTTP        *HTTPConfig     `json:"http,omitempty"`
}

// BrowserIdentity identifies the browser
type BrowserIdentity struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Engine  string `json:"engine,omitempty"`
}

// OSIdentity identifies the operating system
type OSIdentity struct {
	Name         string `json:"name"`
	Version      string `json:"version,omitempty"`
	Architecture string `json:"arch,omitempty"`
}

// TLSConfig configures TLS/SSL fingerprinting
type TLSConfig struct {
	Version             TLSVersion           `json:"version"`
	CipherSuites        []CipherSuite        `json:"cipher_suites"`
	Extensions          []TLSExtension       `json:"extensions"`
	SupportedGroups     []NamedGroup         `json:"supported_groups,omitempty"`
	SignatureAlgorithms []SignatureAlgorithm `json:"signature_algorithms,omitempty"`
	ALPN                []string             `json:"alpn,omitempty"`
	ALPS                string               `json:"alps,omitempty"`
	CertCompression     []string             `json:"cert_compression,omitempty"`
}

// TLSVersion represents a TLS version
type TLSVersion struct {
	Min uint16 `json:"min"`
	Max uint16 `json:"max"`
}

// CipherSuite represents a cipher suite
type CipherSuite struct {
	Value    uint16 `json:"value,omitempty"`
	Name     string `json:"name,omitempty"`
	IsGREASE bool   `json:"grease,omitempty"`
}

// TLSExtension represents a TLS extension
type TLSExtension struct {
	Type     uint16          `json:"type,omitempty"`
	Name     string          `json:"name"`
	Data     json.RawMessage `json:"data,omitempty"`
	IsGREASE bool            `json:"grease,omitempty"`
}

// NamedGroup represents an elliptic curve or DH group
type NamedGroup struct {
	Value    uint16 `json:"value,omitempty"`
	Name     string `json:"name,omitempty"`
	IsGREASE bool   `json:"grease,omitempty"`
}

// SignatureAlgorithm represents a signature algorithm
type SignatureAlgorithm struct {
	Value uint16 `json:"value,omitempty"`
	Name  string `json:"name,omitempty"`
}

// HTTP2Config configures HTTP/2 fingerprinting
type HTTP2Config struct {
	Settings          HTTP2Settings `json:"settings"`
	PseudoHeaderOrder []string      `json:"pseudo_header_order"`
}

// HTTP2Settings contains HTTP/2 SETTINGS parameters
type HTTP2Settings struct {
	HeaderTableSize      uint32 `json:"header_table_size,omitempty"`
	EnablePush           uint32 `json:"enable_push,omitempty"`
	MaxConcurrentStreams uint32 `json:"max_concurrent_streams,omitempty"`
	InitialWindowSize    uint32 `json:"initial_window_size,omitempty"`
	MaxFrameSize         uint32 `json:"max_frame_size,omitempty"`
}

// HTTPConfig configures HTTP layer fingerprinting
type HTTPConfig struct {
	Version        string       `json:"version"`
	Headers        []HTTPHeader `json:"headers"`
	UserAgent      string       `json:"user_agent,omitempty"`
	Accept         string       `json:"accept,omitempty"`
	AcceptLanguage string       `json:"accept_language,omitempty"`
	AcceptEncoding string       `json:"accept_encoding,omitempty"`
	ClientHints    *ClientHints `json:"client_hints,omitempty"`
}

// HTTPHeader represents an HTTP header
type HTTPHeader struct {
	Name     string `json:"name"`
	Value    string `json:"value,omitempty"`
	Required bool   `json:"required,omitempty"`
}

// ClientHints configures Client Hints headers
type ClientHints struct {
	SecCHUA         string `json:"sec_ch_ua,omitempty"`
	SecCHUAMobile   string `json:"sec_ch_ua_mobile,omitempty"`
	SecCHUAPlatform string `json:"sec_ch_ua_platform,omitempty"`
}

// Loader loads fingerprint configurations
type Loader struct {
	searchPaths []string
}

// NewLoader creates a new configuration loader
func NewLoader(searchPaths ...string) *Loader {
	if len(searchPaths) == 0 {
		searchPaths = []string{"./fingerprints", "./signatures"}
	}
	return &Loader{searchPaths: searchPaths}
}

// Load loads a fingerprint configuration by name
func (l *Loader) Load(name string) (*FingerprintConfig, error) {
	extensions := []string{".json", ".yaml", ".yml"}

	for _, path := range l.searchPaths {
		for _, ext := range extensions {
			filename := filepath.Join(path, name+ext)
			if cfg, err := l.loadFile(filename); err == nil {
				return cfg, nil
			}
		}
	}

	return nil, fmt.Errorf("fingerprint config not found: %s", name)
}

// sanitizePath validates and cleans a file path to prevent directory traversal
func sanitizePath(path string) (string, error) {
	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		return "", fmt.Errorf("invalid path contains directory traversal: %s", path)
	}
	return cleanPath, nil
}

// loadFile loads a configuration from a file
func (l *Loader) loadFile(filename string) (*FingerprintConfig, error) {
	safePath, err := sanitizePath(filename)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Clean(safePath))
	if err != nil {
		return nil, err
	}

	var cfg FingerprintConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	cfg.ApplyDefaults()
	return &cfg, nil
}

// ApplyDefaults applies default values
func (c *FingerprintConfig) ApplyDefaults() {
	if c.Browser.Name == "" {
		c.Browser.Name = "chrome"
	}
	if c.Browser.Version == "" {
		c.Browser.Version = "116"
	}
	if c.OS.Name == "" {
		c.OS.Name = "windows"
	}

	if c.TLS != nil && len(c.TLS.ALPN) == 0 {
		c.TLS.ALPN = []string{"h2", "http/1.1"}
	}

	if c.HTTP2 != nil && len(c.HTTP2.PseudoHeaderOrder) == 0 {
		c.HTTP2.PseudoHeaderOrder = []string{":method", ":authority", ":scheme", ":path"}
	}
}

// Validate validates the configuration
func (c *FingerprintConfig) Validate() error {
	if c.Name == "" {
		return fmt.Errorf("fingerprint name is required")
	}
	if c.Browser.Name == "" {
		return fmt.Errorf("browser name is required")
	}
	return nil
}

// Save saves the configuration to a file
func (c *FingerprintConfig) Save(filename string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	return os.WriteFile(filename, data, 0600)
}

// GetPreset returns a built-in preset
func GetPreset(name string) (*FingerprintConfig, error) {
	switch name {
	case "chrome-116", "chrome-116-windows":
		cfg := *Chrome116
		return &cfg, nil
	case "firefox-109":
		cfg := *Firefox109
		return &cfg, nil
	default:
		return nil, fmt.Errorf("preset not found: %s", name)
	}
}

// ListPresets returns available preset names
func ListPresets() []string {
	return []string{"chrome-116-windows", "firefox-109"}
}

// Built-in presets
var (
	Chrome116 = &FingerprintConfig{
		Name:        "chrome-116-windows",
		Version:     "1.0",
		Description: "Chrome 116 on Windows 10",
		Tags:        []string{"chrome", "windows", "desktop"},
		Browser:     BrowserIdentity{Name: "chrome", Version: "116", Engine: "blink"},
		OS:          OSIdentity{Name: "windows", Version: "10", Architecture: "x64"},
		TLS: &TLSConfig{
			Version: TLSVersion{Min: 0x0303, Max: 0x0304},
			CipherSuites: []CipherSuite{
				{Value: 0x1301, Name: "TLS_AES_128_GCM_SHA256"},
				{Value: 0x1302, Name: "TLS_AES_256_GCM_SHA384"},
				{Value: 0x1303, Name: "TLS_CHACHA20_POLY1305_SHA256"},
				{IsGREASE: true},
				{Value: 0xc02b, Name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
				{Value: 0xc02f, Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			},
			Extensions: []TLSExtension{
				{IsGREASE: true},
				{Name: "server_name"},
				{Name: "extended_master_secret"},
				{Name: "renegotiation_info"},
				{Name: "supported_groups"},
				{Name: "ec_point_formats"},
				{Name: "signed_certificate_timestamp"},
				{Name: "application_layer_protocol_negotiation"},
				{Name: "status_request"},
				{IsGREASE: true},
				{Name: "key_share"},
				{Name: "psk_key_exchange_modes"},
				{Name: "supported_versions"},
				{Name: "compress_certificate"},
				{Name: "application_settings"},
				{IsGREASE: true},
				{Name: "padding"},
			},
			SupportedGroups: []NamedGroup{
				{IsGREASE: true}, {Value: 0x001d, Name: "x25519"},
				{Value: 0x0017, Name: "secp256r1"},
			},
			ALPN:            []string{"h2", "http/1.1"},
			ALPS:            "h2",
			CertCompression: []string{"brotli"},
		},
		HTTP2: &HTTP2Config{
			Settings: HTTP2Settings{
				HeaderTableSize:      65536,
				EnablePush:           0,
				MaxConcurrentStreams: 1000,
				InitialWindowSize:    6291456,
			},
			PseudoHeaderOrder: []string{
				":method", ":authority", ":scheme", ":path",
			},
		},
		HTTP: &HTTPConfig{
			Version:        "2.0",
			UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
			Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			AcceptLanguage: "en-US,en;q=0.9",
			AcceptEncoding: "gzip, deflate, br",
			Headers: []HTTPHeader{
				{Name: ":method", Required: true},
				{Name: ":authority", Required: true},
				{Name: ":scheme", Value: "https", Required: true},
				{Name: ":path", Required: true},
				{Name: "sec-ch-ua", Value: `"Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"`, Required: true},
				{Name: "sec-ch-ua-mobile", Value: "?0", Required: true},
				{Name: "sec-ch-ua-platform", Value: `"Windows"`, Required: true},
			},
			ClientHints: &ClientHints{
				SecCHUA:         `"Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"`,
				SecCHUAMobile:   "?0",
				SecCHUAPlatform: `"Windows"`,
			},
		},
	}

	Firefox109 = &FingerprintConfig{
		Name:        "firefox-109",
		Version:     "1.0",
		Description: "Firefox 109",
		Tags:        []string{"firefox", "gecko"},
		Browser:     BrowserIdentity{Name: "firefox", Version: "109", Engine: "gecko"},
		OS:          OSIdentity{Name: "windows", Version: "10"},
		TLS: &TLSConfig{
			Version: TLSVersion{Min: 0x0303, Max: 0x0304},
			CipherSuites: []CipherSuite{
				{Value: 0x1301, Name: "TLS_AES_128_GCM_SHA256"},
				{Value: 0x1303, Name: "TLS_CHACHA20_POLY1305_SHA256"},
				{Value: 0x1302, Name: "TLS_AES_256_GCM_SHA384"},
			},
			Extensions: []TLSExtension{
				{Name: "server_name"},
				{Name: "extended_master_secret"},
				{Name: "supported_groups"},
				{Name: "key_share"},
			},
			SupportedGroups: []NamedGroup{
				{Value: 0x001d, Name: "x25519"},
				{Value: 0x0017, Name: "secp256r1"},
			},
			ALPN: []string{"h2", "http/1.1"},
		},
		HTTP2: &HTTP2Config{
			Settings: HTTP2Settings{
				MaxConcurrentStreams: 100,
				InitialWindowSize:    131072,
			},
			PseudoHeaderOrder: []string{
				":method", ":path", ":authority", ":scheme",
			},
		},
		HTTP: &HTTPConfig{
			Version:   "2.0",
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0",
			Headers: []HTTPHeader{
				{Name: "user-agent", Required: true},
				{Name: "accept", Required: true},
			},
		},
	}
)
