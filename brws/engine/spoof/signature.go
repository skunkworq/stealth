// Package spoof provides signature-driven browser impersonation
package spoof

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// BrowserSignature contains all layers of a browser signature
type BrowserSignature struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	OS          string `json:"os"`
	Description string `json:"description,omitempty"`

	TLS   *TLSSignature   `json:"tls"`
	HTTP2 *HTTP2Signature `json:"http2"`
	HTTP  *HTTPSignature  `json:"http"`
}

// TLSSignature contains TLS fingerprint details
type TLSSignature struct {
	Version             uint16           `json:"version"`
	CipherSuites        []CipherEntry    `json:"cipher_suites"`
	Extensions          []ExtensionEntry `json:"extensions"`
	SupportedGroups     []uint16         `json:"supported_groups"`
	SignatureAlgorithms []uint16         `json:"signature_algorithms"`
	ALPN                []string         `json:"alpn"`
	ALPS                string           `json:"alps,omitempty"`
	CertCompression     []string         `json:"cert_compression,omitempty"`
	KeyShareGroups      []uint16         `json:"key_share_groups"`
}

// CipherEntry represents a cipher suite with optional GREASE
type CipherEntry struct {
	Value    uint16 `json:"value"`
	Name     string `json:"name,omitempty"`
	IsGREASE bool   `json:"grease,omitempty"`
}

// ExtensionEntry represents a TLS extension
type ExtensionEntry struct {
	Type     uint16          `json:"type"`
	Name     string          `json:"name,omitempty"`
	Data     json.RawMessage `json:"data,omitempty"`
	IsGREASE bool            `json:"grease,omitempty"`
}

// HTTP2Signature contains HTTP/2 fingerprint details
type HTTP2Signature struct {
	Settings          []HTTP2SettingEntry `json:"settings"`
	PseudoHeaders     []string            `json:"pseudo_headers"`
	HeaderPriority    *HeaderPriority     `json:"header_priority,omitempty"`
	EnablePush        bool                `json:"enable_push"`
	InitialWindowSize uint32              `json:"initial_window_size"`
}

// HTTP2SettingEntry represents a single HTTP/2 setting
type HTTP2SettingEntry struct {
	ID    uint16 `json:"id"`
	Name  string `json:"name,omitempty"`
	Value uint32 `json:"value"`
}

// HeaderPriority for HTTP/2 stream priority
type HeaderPriority struct {
	Weight    uint8 `json:"weight"`
	Exclusive bool  `json:"exclusive"`
}

// HTTPSignature contains HTTP headers and settings
type HTTPSignature struct {
	UserAgent      string            `json:"user_agent"`
	Accept         string            `json:"accept"`
	AcceptLanguage string            `json:"accept_language"`
	AcceptEncoding string            `json:"accept_encoding"`
	Headers        []HeaderEntry     `json:"headers"`
	ClientHints    *ClientHintsEntry `json:"client_hints,omitempty"`
	HTTPVersion    string            `json:"http_version"`
}

// HeaderEntry represents an HTTP header
type HeaderEntry struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Required bool   `json:"required,omitempty"`
}

// ClientHintsEntry for Chrome
type ClientHintsEntry struct {
	SecCHUA         string `json:"sec_ch_ua"`
	SecCHUAMobile   string `json:"sec_ch_ua_mobile"`
	SecCHUAPlatform string `json:"sec_ch_ua_platform"`
}

// SignatureDatabase manages browser signatures
type SignatureDatabase struct {
	signatures map[string]*BrowserSignature
	dir        string
}

// NewSignatureDatabase creates a new signature database
func NewSignatureDatabase(dir string) (*SignatureDatabase, error) {
	db := &SignatureDatabase{
		signatures: make(map[string]*BrowserSignature),
		dir:        dir,
	}

	if dir != "" {
		if err := db.LoadFromDir(dir); err != nil {
			return nil, err
		}
	}

	return db, nil
}

// sanitizePath validates and cleans a file path to prevent directory traversal
func sanitizePath(path string) (string, error) {
	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		return "", fmt.Errorf("invalid path contains directory traversal: %s", path)
	}
	return cleanPath, nil
}

// LoadFromDir loads all signatures from a directory
func (db *SignatureDatabase) LoadFromDir(dir string) error {
	files, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Directory doesn't exist is OK
		}
		return fmt.Errorf("reading signatures directory: %w", err)
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		if filepath.Ext(file.Name()) != ".json" {
			continue
		}

		path := filepath.Join(dir, file.Name())

		safePath, err := sanitizePath(path)
		if err != nil {
			continue
		}
		data, err := os.ReadFile(safePath) //nolint:gosec // Path already sanitized above
		if err != nil {
			return fmt.Errorf("reading %s: %w", safePath, err)
		}

		var sig BrowserSignature
		if err := json.Unmarshal(data, &sig); err != nil {
			return fmt.Errorf("parsing %s: %w", path, err)
		}

		key := fmt.Sprintf("%s-%s", sig.Name, sig.Version)
		db.signatures[key] = &sig
	}

	return nil
}

// Save saves a signature to the database
func (db *SignatureDatabase) Save(key string, sig *BrowserSignature) error {
	db.signatures[key] = sig

	if db.dir != "" {
		// Save to disk
		filename := fmt.Sprintf("%s.json", key)
		path := filepath.Join(db.dir, filename)

		data, err := json.MarshalIndent(sig, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling signature: %w", err)
		}

		if err := os.WriteFile(path, data, 0o600); err != nil {
			return fmt.Errorf("writing signature: %w", err)
		}
	}

	return nil
}

// Get retrieves a signature by key
func (db *SignatureDatabase) Get(key string) (*BrowserSignature, bool) {
	sig, ok := db.signatures[key]
	return sig, ok
}

// List returns all available signature keys
func (db *SignatureDatabase) List() []string {
	keys := make([]string, 0, len(db.signatures))
	for k := range db.signatures {
		keys = append(keys, k)
	}
	return keys
}

// GetChrome116 returns the Chrome 116 signature
func GetChrome116() *BrowserSignature {
	return &BrowserSignature{
		Name:        "chrome",
		Version:     "116",
		OS:          "windows",
		Description: "Chrome 116 on Windows 10",

		TLS: &TLSSignature{
			Version: 0x0303, // TLS 1.2 in hello, actual version in supported_versions
			CipherSuites: []CipherEntry{
				{Value: 0x1301, Name: "TLS_AES_128_GCM_SHA256"},
				{Value: 0x1302, Name: "TLS_AES_256_GCM_SHA384"},
				{Value: 0x1303, Name: "TLS_CHACHA20_POLY1305_SHA256"},
				{Value: 0xc02b, Name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
				{Value: 0xc02f, Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
				{Value: 0xc02c, Name: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
				{Value: 0xc030, Name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
				{Value: 0xcca9, Name: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"},
				{Value: 0xcca8, Name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},
				{Value: 0xc013, Name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"},
				{Value: 0xc014, Name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"},
				{Value: 0x009c, Name: "TLS_RSA_WITH_AES_128_GCM_SHA256"},
				{Value: 0x009d, Name: "TLS_RSA_WITH_AES_256_GCM_SHA384"},
				{Value: 0x002f, Name: "TLS_RSA_WITH_AES_128_CBC_SHA"},
				{Value: 0x0035, Name: "TLS_RSA_WITH_AES_256_CBC_SHA"},
			},
			Extensions: []ExtensionEntry{
				{Type: 0x5a5a, IsGREASE: true},
				{Type: 0x0000, Name: "server_name"},
				{Type: 0x0017, Name: "extended_master_secret"},
				{Type: 0xff01, Name: "renegotiation_info"},
				{Type: 0x000a, Name: "supported_groups"},
				{Type: 0x000b, Name: "ec_point_formats"},
				{Type: 0x0023, Name: "signed_certificate_timestamp"},
				{Type: 0x0010, Name: "application_layer_protocol_negotiation"},
				{Type: 0x0005, Name: "status_request"},
				{Type: 0x0a0a, IsGREASE: true},
				{Type: 0x0012, Name: "signed_certificate_timestamp"},
				{Type: 0x0033, Name: "key_share"},
				{Type: 0x002d, Name: "psk_key_exchange_modes"},
				{Type: 0x002b, Name: "supported_versions"},
				{Type: 0x001d, Name: "compress_certificate"},
				{Type: 0x0011, Name: "application_settings"}, // ALPS
				{Type: 0x0d0d, IsGREASE: true},
				{Type: 0x002b, Name: "supported_versions"},
				{Type: 0x0015, Name: "padding"},
				{Type: 0x0f0f, IsGREASE: true},
			},
			SupportedGroups: []uint16{0x5a5a, 0x001d, 0x0017, 0x0018, 0x001e, 0x0a0a},
			ALPN:            []string{"h2", "http/1.1"},
			ALPS:            "h2",
			CertCompression: []string{"brotli"},
			KeyShareGroups:  []uint16{0x5a5a, 0x001d, 0x0a0a},
		},

		HTTP2: &HTTP2Signature{
			Settings: []HTTP2SettingEntry{
				{ID: 1, Name: "HEADER_TABLE_SIZE", Value: 65536},
				{ID: 2, Name: "ENABLE_PUSH", Value: 0},
				{ID: 3, Name: "MAX_CONCURRENT_STREAMS", Value: 1000},
				{ID: 4, Name: "INITIAL_WINDOW_SIZE", Value: 6291456},
				{ID: 6, Name: "MAX_HEADER_LIST_SIZE", Value: 262144},
			},
			PseudoHeaders: []string{
				":method",
				":authority",
				":scheme",
				":path",
			},
			HeaderPriority: &HeaderPriority{
				Weight:    255,
				Exclusive: true,
			},
			EnablePush:        false,
			InitialWindowSize: 6291456,
		},

		HTTP: &HTTPSignature{
			UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
			Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			AcceptLanguage: "en-US,en;q=0.9",
			AcceptEncoding: "gzip, deflate, br",
			Headers: []HeaderEntry{
				{Name: ":method", Value: "GET", Required: true},
				{Name: ":authority", Value: "", Required: true},
				{Name: ":scheme", Value: "https", Required: true},
				{Name: ":path", Value: "/", Required: true},
				{Name: "sec-ch-ua", Value: `"Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"`, Required: true},
				{Name: "sec-ch-ua-mobile", Value: "?0", Required: true},
				{Name: "sec-ch-ua-platform", Value: `"Windows"`, Required: true},
				{Name: "upgrade-insecure-requests", Value: "1", Required: true},
				{Name: "user-agent", Value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36", Required: true},
				{Name: "accept", Value: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", Required: true},
				{Name: "sec-fetch-site", Value: "none", Required: true},
				{Name: "sec-fetch-mode", Value: "navigate", Required: true},
				{Name: "sec-fetch-user", Value: "?1", Required: true},
				{Name: "sec-fetch-dest", Value: "document", Required: true},
				{Name: "accept-encoding", Value: "gzip, deflate, br", Required: true},
				{Name: "accept-language", Value: "en-US,en;q=0.9", Required: true},
			},
			ClientHints: &ClientHintsEntry{
				SecCHUA:         `"Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"`,
				SecCHUAMobile:   "?0",
				SecCHUAPlatform: `"Windows"`,
			},
			HTTPVersion: "2.0",
		},
	}
}

// GetFirefox109 returns the Firefox 109 signature
func GetFirefox109() *BrowserSignature {
	return &BrowserSignature{
		Name:        "firefox",
		Version:     "109",
		OS:          "windows",
		Description: "Firefox 109 on Windows 10",

		TLS: &TLSSignature{
			Version: 0x0303,
			CipherSuites: []CipherEntry{
				{Value: 0x1301, Name: "TLS_AES_128_GCM_SHA256"},
				{Value: 0x1303, Name: "TLS_CHACHA20_POLY1305_SHA256"},
				{Value: 0x1302, Name: "TLS_AES_256_GCM_SHA384"},
				{Value: 0xc02b, Name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
				{Value: 0xc02f, Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
				{Value: 0xc02c, Name: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
				{Value: 0xc030, Name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
				{Value: 0xcca9, Name: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"},
				{Value: 0xcca8, Name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},
				{Value: 0xc013, Name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"},
				{Value: 0xc014, Name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"},
				{Value: 0x009c, Name: "TLS_RSA_WITH_AES_128_GCM_SHA256"},
				{Value: 0x009d, Name: "TLS_RSA_WITH_AES_256_GCM_SHA384"},
				{Value: 0x002f, Name: "TLS_RSA_WITH_AES_128_CBC_SHA"},
				{Value: 0x0035, Name: "TLS_RSA_WITH_AES_256_CBC_SHA"},
			},
			Extensions: []ExtensionEntry{
				{Type: 0x0000, Name: "server_name"},
				{Type: 0x0017, Name: "extended_master_secret"},
				{Type: 0xff01, Name: "renegotiation_info"},
				{Type: 0x000a, Name: "supported_groups"},
				{Type: 0x000b, Name: "ec_point_formats"},
				{Type: 0x0023, Name: "session_ticket"},
				{Type: 0x0010, Name: "application_layer_protocol_negotiation"},
				{Type: 0x0005, Name: "status_request"},
				{Type: 0x000d, Name: "signature_algorithms"},
				{Type: 0x0012, Name: "signed_certificate_timestamp"},
				{Type: 0x0033, Name: "key_share"},
				{Type: 0x002d, Name: "psk_key_exchange_modes"},
				{Type: 0x002b, Name: "supported_versions"},
				{Type: 0x0015, Name: "padding"},
			},
			SupportedGroups:     []uint16{0x001d, 0x0017, 0x0018, 0x001e},
			SignatureAlgorithms: []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0103, 0x0202, 0x0402, 0x0502, 0x0102},
			ALPN:                []string{"h2", "http/1.1"},
			// No ALPS for Firefox
			CertCompression: nil,
			KeyShareGroups:  []uint16{0x001d, 0x0017},
		},

		HTTP2: &HTTP2Signature{
			Settings: []HTTP2SettingEntry{
				{ID: 3, Name: "MAX_CONCURRENT_STREAMS", Value: 100},
				{ID: 5, Name: "MAX_FRAME_SIZE", Value: 16384},
				{ID: 4, Name: "INITIAL_WINDOW_SIZE", Value: 131072}, // 128KB vs Chrome's 6MB
			},
			PseudoHeaders: []string{
				":method",
				":path",
				":authority",
				":scheme",
			},
			EnablePush:        false,
			InitialWindowSize: 131072,
		},

		HTTP: &HTTPSignature{
			UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0",
			Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			AcceptLanguage: "en-US,en;q=0.5",
			AcceptEncoding: "gzip, deflate, br",
			Headers: []HeaderEntry{
				{Name: "user-agent", Value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0", Required: true},
				{Name: "accept", Value: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", Required: true},
				{Name: "accept-language", Value: "en-US,en;q=0.5", Required: true},
				{Name: "accept-encoding", Value: "gzip, deflate, br", Required: true},
				{Name: "upgrade-insecure-requests", Value: "1", Required: true},
				{Name: "sec-fetch-dest", Value: "document", Required: true},
				{Name: "sec-fetch-mode", Value: "navigate", Required: true},
				{Name: "sec-fetch-site", Value: "none", Required: true},
				{Name: "sec-fetch-user", Value: "?1", Required: true},
				{Name: "te", Value: "trailers", Required: true},
			},
			ClientHints: nil, // Firefox doesn't send client hints by default
			HTTPVersion: "2.0",
		},
	}
}

// LoadDefaultSignatures loads all built-in signatures
func LoadDefaultSignatures() map[string]*BrowserSignature {
	sigs := make(map[string]*BrowserSignature)
	sigs["chrome-116"] = GetChrome116()
	sigs["firefox-109"] = GetFirefox109()
	return sigs
}
