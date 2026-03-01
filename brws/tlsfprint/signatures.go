// Package tlsfprint provides TLS fingerprinting types and signatures.
package tlsfprint

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
)

// TLSLibrary represents the TLS library used by a browser.
type TLSLibrary string

const (
	// LibraryBoringSSL represents the BoringSSL library.
	LibraryBoringSSL       TLSLibrary = "boringssl"
	LibraryOpenSSL         TLSLibrary = "openssl"
	LibraryNSS             TLSLibrary = "nss"
	LibrarySecureTransport TLSLibrary = "securetransport"
	LibraryConscrypt       TLSLibrary = "conscrypt"
	LibraryGo              TLSLibrary = "go"
)

// BrowserFamily represents the browser family.
type BrowserFamily string

const (
	// FamilyChrome represents the Chrome browser family.
	FamilyChrome  BrowserFamily = "chrome"
	FamilyFirefox BrowserFamily = "firefox"
	FamilySafari  BrowserFamily = "safari"
	FamilyEdge    BrowserFamily = "edge"
	FamilyOpera   BrowserFamily = "opera"
	FamilyBrave   BrowserFamily = "brave"
	FamilyIOS     BrowserFamily = "ios"
	FamilyAndroid BrowserFamily = "android"
	FamilyUnknown BrowserFamily = "unknown"
)

// Platform represents the operating system platform.
type Platform string

const (
	// PlatformWindows represents the Windows platform.
	PlatformWindows Platform = "windows"
	PlatformMacOS   Platform = "macos"
	PlatformLinux   Platform = "linux"
	PlatformAndroid Platform = "android"
	PlatformIOS     Platform = "ios"
	PlatformUnknown Platform = "unknown"
)

// BrowserProperties contains browser-specific TLS properties.
type BrowserProperties struct {
	Name           string        `json:"name"`
	Version        string        `json:"version"`
	Platform       Platform      `json:"platform"`
	TLSLibrary     TLSLibrary    `json:"tls_library"`
	BrowserFamily  BrowserFamily `json:"browser_family"`
	IsMobile       bool          `json:"is_mobile"`
	SupportsHTTP3  bool          `json:"supports_http3"`
	SupportsGREASE bool          `json:"supports_grease"`
	SupportsTLS13  bool          `json:"supports_tls13"`
	MinTLSVersion  uint16        `json:"min_tls_version"`
	MaxTLSVersion  uint16        `json:"max_tls_version"`
	CipherSuites   []uint16      `json:"cipher_suites"`
	Extensions     []uint16      `json:"extensions"`
	KeyShareGroups []uint16      `json:"key_share_groups"`
	SignatureAlgs  []uint16      `json:"signature_algs"`
	ALPN           []string      `json:"alpn"`
	PaddingStyle   PaddingStyle  `json:"padding_style"`
	SessionTickets bool          `json:"session_tickets"`
	ECHSupport     bool          `json:"ech_support"`
	QUICSupport    bool          `json:"quic_support"`
}

// PaddingStyle represents the TLS padding style.
type PaddingStyle int

const (
	// PaddingStyleNone represents no padding.
	PaddingStyleNone      PaddingStyle = iota
	PaddingStyleBoringSSL              // Chrome-style random padding
	PaddingStyleFixed                  // Fixed padding
	PaddingStyleMax                    // Max padding to 256 bytes
)

// FingerprintSignature represents a complete TLS fingerprint signature.
type FingerprintSignature struct {
	Name          string            `json:"name"`
	Description   string            `json:"description"`
	BrowserProps  BrowserProperties `json:"browser_properties"`
	ClientHelloID ClientHelloID     `json:"client_hello_id"`
	Weight        float64           `json:"weight"`
	Confidence    float64           `json:"confidence"`
	Labels        []string          `json:"labels"`
}

// NewBrowserProperties creates a new BrowserProperties instance with defaults.
func NewBrowserProperties(name, version string, platform Platform, library TLSLibrary) *BrowserProperties {
	return &BrowserProperties{
		Name:           name,
		Version:        version,
		Platform:       platform,
		TLSLibrary:     library,
		SupportsTLS13:  true,
		MaxTLSVersion:  0x0304,
		MinTLSVersion:  0x0301,
		PaddingStyle:   PaddingStyleBoringSSL,
		SessionTickets: true,
	}
}

// Chrome133Windows is the fingerprint signature for Chrome 133 on Windows.
var Chrome133Windows = FingerprintSignature{
	Name:        "chrome-133-windows",
	Description: "Chrome 133 on Windows 11 with BoringSSL",
	BrowserProps: BrowserProperties{
		Name:           "Chrome",
		Version:        "133.0.0.0",
		Platform:       PlatformWindows,
		TLSLibrary:     LibraryBoringSSL,
		BrowserFamily:  FamilyChrome,
		IsMobile:       false,
		SupportsHTTP3:  true,
		SupportsGREASE: true,
		SupportsTLS13:  true,
		MaxTLSVersion:  0x0304,
		MinTLSVersion:  0x0301,
		CipherSuites:   []uint16{0x1301, 0x1302, 0x1303, 0xcca9, 0xc02c, 0xc02b, 0x002f, 0x0035},
		Extensions:     []uint16{0, 1, 3, 5, 10, 13, 16, 23, 27, 35, 43, 45, 51, 57, 65281},
		KeyShareGroups: []uint16{0x001d, 0x0017, 0x0018, 0x0019},
		SignatureAlgs:  []uint16{0x0804, 0x0803, 0x0802, 0x0403, 0x0402, 0x0401, 0x0203, 0x0202, 0x0201},
		ALPN:           []string{"h2", "http/1.1"},
		PaddingStyle:   PaddingStyleBoringSSL,
		SessionTickets: true,
		ECHSupport:     true,
		QUICSupport:    true,
	},
	ClientHelloID: HelloChrome_133,
	Weight:        1.0,
	Confidence:    0.95,
	Labels:        []string{"chrome", "windows", "boringssl", "modern"},
}

// Chrome133MacOS is the fingerprint signature for Chrome 133 on macOS.
var Chrome133MacOS = FingerprintSignature{
	Name:        "chrome-133-macos",
	Description: "Chrome 133 on macOS with BoringSSL",
	BrowserProps: BrowserProperties{
		Name:           "Chrome",
		Version:        "133.0.0.0",
		Platform:       PlatformMacOS,
		TLSLibrary:     LibraryBoringSSL,
		BrowserFamily:  FamilyChrome,
		IsMobile:       false,
		SupportsHTTP3:  true,
		SupportsGREASE: true,
		SupportsTLS13:  true,
		MaxTLSVersion:  0x0304,
		MinTLSVersion:  0x0301,
		CipherSuites:   []uint16{0x1301, 0x1302, 0x1303, 0xcca9, 0xc02c, 0xc02b, 0x002f, 0x0035},
		Extensions:     []uint16{0, 1, 3, 5, 10, 13, 16, 23, 27, 35, 43, 45, 51, 57, 65281},
		KeyShareGroups: []uint16{0x001d, 0x0017, 0x0018, 0x0019},
		SignatureAlgs:  []uint16{0x0804, 0x0803, 0x0802, 0x0403, 0x0402, 0x0401, 0x0203, 0x0202, 0x0201},
		ALPN:           []string{"h2", "http/1.1"},
		PaddingStyle:   PaddingStyleBoringSSL,
		SessionTickets: true,
		ECHSupport:     true,
		QUICSupport:    true,
	},
	ClientHelloID: HelloChrome_133,
	Weight:        1.0,
	Confidence:    0.95,
	Labels:        []string{"chrome", "macos", "boringssl", "modern"},
}

// Chrome120Android is the fingerprint signature for Chrome 120 on Android.
var Chrome120Android = FingerprintSignature{
	Name:        "chrome-120-android",
	Description: "Chrome 120 on Android with BoringSSL",
	BrowserProps: BrowserProperties{
		Name:           "Chrome",
		Version:        "120.0.6099.210",
		Platform:       PlatformAndroid,
		TLSLibrary:     LibraryBoringSSL,
		BrowserFamily:  FamilyChrome,
		IsMobile:       true,
		SupportsHTTP3:  true,
		SupportsGREASE: true,
		SupportsTLS13:  true,
		MaxTLSVersion:  0x0304,
		MinTLSVersion:  0x0301,
		CipherSuites:   []uint16{0x1301, 0x1302, 0x1303, 0xcca9, 0xc02c, 0xc02b, 0x002f, 0x0035},
		Extensions:     []uint16{0, 1, 3, 5, 10, 13, 16, 23, 27, 35, 43, 45, 51, 57, 65281},
		KeyShareGroups: []uint16{0x001d, 0x0017, 0x0018},
		SignatureAlgs:  []uint16{0x0804, 0x0803, 0x0403, 0x0402, 0x0203, 0x0202, 0x0201},
		ALPN:           []string{"h2", "http/1.1"},
		PaddingStyle:   PaddingStyleBoringSSL,
		SessionTickets: true,
		ECHSupport:     true,
		QUICSupport:    true,
	},
	ClientHelloID: HelloChrome_120,
	Weight:        1.0,
	Confidence:    0.90,
	Labels:        []string{"chrome", "android", "boringssl", "mobile"},
}

// Firefox120Windows is the fingerprint signature for Firefox 120 on Windows.
var Firefox120Windows = FingerprintSignature{
	Name:        "firefox-120-windows",
	Description: "Firefox 120 on Windows with NSS",
	BrowserProps: BrowserProperties{
		Name:           "Firefox",
		Version:        "120.0",
		Platform:       PlatformWindows,
		TLSLibrary:     LibraryNSS,
		BrowserFamily:  FamilyFirefox,
		IsMobile:       false,
		SupportsHTTP3:  false,
		SupportsGREASE: false,
		SupportsTLS13:  true,
		MaxTLSVersion:  0x0304,
		MinTLSVersion:  0x0301,
		CipherSuites:   []uint16{0x1301, 0x1302, 0x1303, 0xcca9, 0x002f, 0x0035, 0xc02b, 0xc02c},
		Extensions:     []uint16{0, 1, 3, 5, 10, 13, 16, 23, 35, 43, 45, 51},
		KeyShareGroups: []uint16{0x001d, 0x0017, 0x0018},
		SignatureAlgs:  []uint16{0x0804, 0x0803, 0x0403, 0x0402, 0x0203, 0x0202, 0x0201, 0x0401},
		ALPN:           []string{"h2", "http/1.1"},
		PaddingStyle:   PaddingStyleNone,
		SessionTickets: true,
		ECHSupport:     false,
		QUICSupport:    false,
	},
	ClientHelloID: HelloFirefox_120,
	Weight:        1.0,
	Confidence:    0.90,
	Labels:        []string{"firefox", "windows", "nss", "modern"},
}

// Firefox120MacOS is the fingerprint signature for Firefox 120 on macOS.
var Firefox120MacOS = FingerprintSignature{
	Name:        "firefox-120-macos",
	Description: "Firefox 120 on macOS with NSS",
	BrowserProps: BrowserProperties{
		Name:           "Firefox",
		Version:        "120.0",
		Platform:       PlatformMacOS,
		TLSLibrary:     LibraryNSS,
		BrowserFamily:  FamilyFirefox,
		IsMobile:       false,
		SupportsHTTP3:  false,
		SupportsGREASE: false,
		SupportsTLS13:  true,
		MaxTLSVersion:  0x0304,
		MinTLSVersion:  0x0301,
		CipherSuites:   []uint16{0x1301, 0x1302, 0x1303, 0xcca9, 0x002f, 0x0035, 0xc02b, 0xc02c},
		Extensions:     []uint16{0, 1, 3, 5, 10, 13, 16, 23, 35, 43, 45, 51},
		KeyShareGroups: []uint16{0x001d, 0x0017, 0x0018},
		SignatureAlgs:  []uint16{0x0804, 0x0803, 0x0403, 0x0402, 0x0203, 0x0202, 0x0201, 0x0401},
		ALPN:           []string{"h2", "http/1.1"},
		PaddingStyle:   PaddingStyleNone,
		SessionTickets: true,
		ECHSupport:     false,
		QUICSupport:    false,
	},
	ClientHelloID: HelloFirefox_120,
	Weight:        1.0,
	Confidence:    0.90,
	Labels:        []string{"firefox", "macos", "nss", "modern"},
}

var Safari16MacOS = FingerprintSignature{
	Name:        "safari-16-macos",
	Description: "Safari 16 on macOS with Secure Transport",
	BrowserProps: BrowserProperties{
		Name:           "Safari",
		Version:        "16.6",
		Platform:       PlatformMacOS,
		TLSLibrary:     LibrarySecureTransport,
		BrowserFamily:  FamilySafari,
		IsMobile:       false,
		SupportsHTTP3:  false,
		SupportsGREASE: false,
		SupportsTLS13:  true,
		MaxTLSVersion:  0x0304,
		MinTLSVersion:  0x0301,
		CipherSuites:   []uint16{0x1301, 0x1302, 0x1303, 0xcca9, 0x002f, 0x0035, 0xc02b, 0xc02c},
		Extensions:     []uint16{0, 1, 3, 5, 10, 13, 16, 23, 35, 43, 51},
		KeyShareGroups: []uint16{0x001d, 0x0017, 0x0018},
		SignatureAlgs:  []uint16{0x0804, 0x0803, 0x0403, 0x0402, 0x0203, 0x0202, 0x0201},
		ALPN:           []string{"h2", "http/1.1"},
		PaddingStyle:   PaddingStyleNone,
		SessionTickets: true,
		ECHSupport:     false,
		QUICSupport:    false,
	},
	ClientHelloID: HelloSafari_16_0,
	Weight:        1.0,
	Confidence:    0.85,
	Labels:        []string{"safari", "macos", "securetransport"},
}

var SafariIOS17 = FingerprintSignature{
	Name:        "safari-ios-17",
	Description: "Safari 17 on iOS with Secure Transport",
	BrowserProps: BrowserProperties{
		Name:           "Safari",
		Version:        "17.0",
		Platform:       PlatformIOS,
		TLSLibrary:     LibrarySecureTransport,
		BrowserFamily:  FamilySafari,
		IsMobile:       true,
		SupportsHTTP3:  false,
		SupportsGREASE: false,
		SupportsTLS13:  true,
		MaxTLSVersion:  0x0304,
		MinTLSVersion:  0x0301,
		CipherSuites:   []uint16{0x1301, 0x1302, 0x1303, 0xcca9, 0x002f, 0x0035},
		Extensions:     []uint16{0, 1, 3, 5, 10, 13, 16, 23, 35, 43, 51},
		KeyShareGroups: []uint16{0x001d, 0x0017},
		SignatureAlgs:  []uint16{0x0804, 0x0803, 0x0403, 0x0402, 0x0203, 0x0202},
		ALPN:           []string{"h2", "http/1.1"},
		PaddingStyle:   PaddingStyleNone,
		SessionTickets: true,
		ECHSupport:     false,
		QUICSupport:    false,
	},
	ClientHelloID: HelloIOS_14,
	Weight:        1.0,
	Confidence:    0.85,
	Labels:        []string{"safari", "ios", "mobile", "securetransport"},
}

var Edge130Windows = FingerprintSignature{
	Name:        "edge-130-windows",
	Description: "Edge 130 on Windows with BoringSSL",
	BrowserProps: BrowserProperties{
		Name:           "Edge",
		Version:        "130.0.0.0",
		Platform:       PlatformWindows,
		TLSLibrary:     LibraryBoringSSL,
		BrowserFamily:  FamilyEdge,
		IsMobile:       false,
		SupportsHTTP3:  true,
		SupportsGREASE: true,
		SupportsTLS13:  true,
		MaxTLSVersion:  0x0304,
		MinTLSVersion:  0x0301,
		CipherSuites:   []uint16{0x1301, 0x1302, 0x1303, 0xcca9, 0xc02c, 0xc02b, 0x002f, 0x0035},
		Extensions:     []uint16{0, 1, 3, 5, 10, 13, 16, 23, 27, 35, 43, 45, 51, 57, 65281},
		KeyShareGroups: []uint16{0x001d, 0x0017, 0x0018, 0x0019},
		SignatureAlgs:  []uint16{0x0804, 0x0803, 0x0802, 0x0403, 0x0402, 0x0401, 0x0203, 0x0202, 0x0201},
		ALPN:           []string{"h2", "http/1.1"},
		PaddingStyle:   PaddingStyleBoringSSL,
		SessionTickets: true,
		ECHSupport:     true,
		QUICSupport:    true,
	},
	ClientHelloID: HelloEdge_106,
	Weight:        1.0,
	Confidence:    0.90,
	Labels:        []string{"edge", "windows", "boringssl", "modern"},
}

var Edge133Windows = FingerprintSignature{
	Name:        "Edge 133",
	Description: "Edge 133 on Windows 11 with BoringSSL",
	BrowserProps: BrowserProperties{
		Name:           "Edge",
		Version:        "133.0.2999.100",
		Platform:       PlatformWindows,
		TLSLibrary:     LibraryBoringSSL,
		BrowserFamily:  FamilyEdge,
		IsMobile:       false,
		SupportsHTTP3:  true,
		SupportsGREASE: true,
		SupportsTLS13:  true,
		MaxTLSVersion:  0x0304,
	},
	ClientHelloID: HelloEdge_106,
	Weight:        1.0,
	Confidence:    0.92,
	Labels:        []string{"edge", "windows", "boringssl", "modern", "chromium"},
}

var Edge133MacOS = FingerprintSignature{
	Name:        "Edge 133",
	Description: "Edge 133 on macOS with BoringSSL",
	BrowserProps: BrowserProperties{
		Name:           "Edge",
		Version:        "133.0.2999.100",
		Platform:       PlatformMacOS,
		TLSLibrary:     LibraryBoringSSL,
		BrowserFamily:  FamilyEdge,
		IsMobile:       false,
		SupportsHTTP3:  true,
		SupportsGREASE: true,
		SupportsTLS13:  true,
		MaxTLSVersion:  0x0304,
	},
	ClientHelloID: HelloEdge_106,
	Weight:        1.0,
	Confidence:    0.92,
	Labels:        []string{"edge", "macos", "boringssl", "modern", "chromium"},
}

var Safari18MacOS = FingerprintSignature{
	Name:        "Safari 18",
	Description: "Safari 18 on macOS with Secure Transport",
	BrowserProps: BrowserProperties{
		Name:           "Safari",
		Version:        "18.0",
		Platform:       PlatformMacOS,
		TLSLibrary:     LibrarySecureTransport,
		BrowserFamily:  FamilySafari,
		IsMobile:       false,
		SupportsHTTP3:  true,
		SupportsGREASE: true,
		SupportsTLS13:  true,
		MaxTLSVersion:  0x0304,
	},
	ClientHelloID: HelloSafari_16_0,
	Weight:        1.0,
	Confidence:    0.91,
	Labels:        []string{"safari", "macos", "securetransport", "modern", "apple"},
}

var Safari18iOS = FingerprintSignature{
	Name:        "Safari 18",
	Description: "Safari 18 on iOS with Secure Transport",
	BrowserProps: BrowserProperties{
		Name:           "Safari",
		Version:        "18.0",
		Platform:       PlatformIOS,
		TLSLibrary:     LibrarySecureTransport,
		BrowserFamily:  FamilySafari,
		IsMobile:       true,
		SupportsHTTP3:  true,
		SupportsGREASE: true,
		SupportsTLS13:  true,
		MaxTLSVersion:  0x0304,
	},
	ClientHelloID: HelloIOS_14,
	Weight:        1.0,
	Confidence:    0.91,
	Labels:        []string{"safari", "ios", "securetransport", "modern", "apple"},
}

var Chrome134Windows = FingerprintSignature{
	Name:        "Chrome 134",
	Description: "Chrome 134 on Windows 11 with BoringSSL",
	BrowserProps: BrowserProperties{
		Name:           "Chrome",
		Version:        "134.0.6998.35",
		Platform:       PlatformWindows,
		TLSLibrary:     LibraryBoringSSL,
		BrowserFamily:  FamilyChrome,
		IsMobile:       false,
		SupportsHTTP3:  true,
		SupportsGREASE: true,
		SupportsTLS13:  true,
		MaxTLSVersion:  0x0304,
	},
	ClientHelloID: HelloChrome_133,
	Weight:        1.0,
	Confidence:    0.93,
	Labels:        []string{"chrome", "windows", "boringssl", "modern", "chromium"},
}

var Chrome134MacOS = FingerprintSignature{
	Name:        "Chrome 134",
	Description: "Chrome 134 on macOS with BoringSSL",
	BrowserProps: BrowserProperties{
		Name:           "Chrome",
		Version:        "134.0.6998.35",
		Platform:       PlatformMacOS,
		TLSLibrary:     LibraryBoringSSL,
		BrowserFamily:  FamilyChrome,
		IsMobile:       false,
		SupportsHTTP3:  true,
		SupportsGREASE: true,
		SupportsTLS13:  true,
		MaxTLSVersion:  0x0304,
	},
	ClientHelloID: HelloChrome_133,
	Weight:        1.0,
	Confidence:    0.93,
	Labels:        []string{"chrome", "macos", "boringssl", "modern", "chromium"},
}

func GetAllSignatures() []FingerprintSignature {
	return []FingerprintSignature{
		Chrome133Windows,
		Chrome133MacOS,
		Chrome120Android,
		Chrome134Windows,
		Chrome134MacOS,
		Firefox120Windows,
		Firefox120MacOS,
		Safari16MacOS,
		SafariIOS17,
		Safari18MacOS,
		Safari18iOS,
		Edge130Windows,
		Edge133Windows,
		Edge133MacOS,
	}
}

func GetSignatureByName(name string) *FingerprintSignature {
	for _, sig := range GetAllSignatures() {
		if sig.Name == name {
			return &sig
		}
	}
	return nil
}

func GetSignaturesByLabel(label string) []FingerprintSignature {
	var results []FingerprintSignature
	for _, sig := range GetAllSignatures() {
		for _, l := range sig.Labels {
			if l == label {
				results = append(results, sig)
				break
			}
		}
	}
	return results
}

func GetSignaturesByPlatform(platform Platform) []FingerprintSignature {
	var results []FingerprintSignature
	for _, sig := range GetAllSignatures() {
		if sig.BrowserProps.Platform == platform {
			results = append(results, sig)
		}
	}
	return results
}

func GetSignaturesByLibrary(library TLSLibrary) []FingerprintSignature {
	var results []FingerprintSignature
	for _, sig := range GetAllSignatures() {
		if sig.BrowserProps.TLSLibrary == library {
			results = append(results, sig)
		}
	}
	return results
}

type SignatureConfig struct {
	PreferredBrowser  BrowserFamily `json:"preferred_browser"`
	PreferredPlatform Platform      `json:"preferred_platform"`
	PreferredLibrary  TLSLibrary    `json:"preferred_library"`
	RequireMobile     bool          `json:"require_mobile"`
	RequireHTTP3      bool          `json:"require_http3"`
	RequireGREASE     bool          `json:"require_grease"`
	MinConfidence     float64       `json:"min_confidence"`
	Labels            []string      `json:"labels"`
	ExcludeLabels     []string      `json:"exclude_labels"`
}

func (c *SignatureConfig) Matches(sig *FingerprintSignature) bool {
	if c.PreferredBrowser != "" && sig.BrowserProps.BrowserFamily != c.PreferredBrowser {
		return false
	}
	if c.PreferredPlatform != "" && sig.BrowserProps.Platform != c.PreferredPlatform {
		return false
	}
	if c.PreferredLibrary != "" && sig.BrowserProps.TLSLibrary != c.PreferredLibrary {
		return false
	}
	if c.RequireMobile && !sig.BrowserProps.IsMobile {
		return false
	}
	if c.RequireHTTP3 && !sig.BrowserProps.SupportsHTTP3 {
		return false
	}
	if c.RequireGREASE && !sig.BrowserProps.SupportsGREASE {
		return false
	}
	if c.MinConfidence > 0 && sig.Confidence < c.MinConfidence {
		return false
	}
	if len(c.Labels) > 0 {
		found := false
		for _, l := range c.Labels {
			for _, sl := range sig.Labels {
				if l == sl {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(c.ExcludeLabels) > 0 {
		for _, l := range c.ExcludeLabels {
			for _, sl := range sig.Labels {
				if l == sl {
					return false
				}
			}
		}
	}
	return true
}

func FilterSignatures(config SignatureConfig) []FingerprintSignature {
	var results []FingerprintSignature
	for _, sig := range GetAllSignatures() {
		if config.Matches(&sig) {
			results = append(results, sig)
		}
	}
	return results
}

type MLPrediction struct {
	SignatureName string    `json:"signature_name"`
	Confidence    float64   `json:"confidence"`
	Features      []float64 `json:"features"`
	Labels        []string  `json:"labels"`
}

type AdaptiveSpoofer struct {
	signatures   []FingerprintSignature
	rng          *rand.Rand
	config       SignatureConfig
	mlPrediction *MLPrediction
	history      []SignatureSelection
}

type SignatureSelection struct {
	Signature string  `json:"signature"`
	Success   bool    `json:"success"`
	Latency   int64   `json:"latency_ms"`
	Score     float64 `json:"score"`
}

func NewAdaptiveSpoofer() *AdaptiveSpoofer {
	return &AdaptiveSpoofer{
		signatures: GetAllSignatures(),
		rng:        rand.New(rand.NewSource(1)), //nolint:gosec // G404: math/rand is sufficient for signature selection
		config:     SignatureConfig{},
		history:    make([]SignatureSelection, 0),
	}
}

func (a *AdaptiveSpoofer) WithConfig(config SignatureConfig) *AdaptiveSpoofer {
	a.config = config
	return a
}

func (a *AdaptiveSpoofer) WithSeed(seed int64) *AdaptiveSpoofer {
	a.rng = rand.New(rand.NewSource(seed)) //nolint:gosec // G404: math/rand is sufficient for signature selection
	return a
}

func (a *AdaptiveSpoofer) SetMLPrediction(prediction *MLPrediction) *AdaptiveSpoofer {
	a.mlPrediction = prediction
	return a
}

func (a *AdaptiveSpoofer) RecordSelection(selection SignatureSelection) {
	a.history = append(a.history, selection)
}

func (a *AdaptiveSpoofer) GetBestSignature() FingerprintSignature {
	candidates := FilterSignatures(a.config)
	if len(candidates) == 0 {
		return Chrome133Windows
	}

	if a.mlPrediction != nil {
		for _, c := range candidates {
			if c.Name == a.mlPrediction.SignatureName {
				return c
			}
		}
	}

	if len(a.history) > 0 {
		var bestScore float64
		var bestSig FingerprintSignature
		for _, c := range candidates {
			score := c.Confidence
			for _, h := range a.history {
				if h.Signature == c.Name {
					if h.Success {
						score += 0.1
					} else {
						score -= 0.2
					}
					score -= float64(h.Latency) / 10000.0
				}
			}
			if score > bestScore {
				bestScore = score
				bestSig = c
			}
		}
		return bestSig
	}

	return candidates[a.rng.Intn(len(candidates))]
}

func (a *AdaptiveSpoofer) GetSignatureByName(name string) *FingerprintSignature {
	for _, sig := range a.signatures {
		if sig.Name == name {
			return &sig
		}
	}
	return nil
}

func (a *AdaptiveSpoofer) GetAllSignatures() []FingerprintSignature {
	return a.signatures
}

func (a *AdaptiveSpoofer) GetHistory() []SignatureSelection {
	return a.history
}

type FeatureExtractor struct{}

func (f *FeatureExtractor) ExtractFromSignature(sig *FingerprintSignature) []float64 {
	features := make([]float64, 0)

	features = append(features, float64(len(sig.BrowserProps.CipherSuites)))
	features = append(features, float64(len(sig.BrowserProps.Extensions)))
	features = append(features, float64(len(sig.BrowserProps.KeyShareGroups)))
	features = append(features, float64(len(sig.BrowserProps.SignatureAlgs)))
	features = append(features, float64(len(sig.BrowserProps.ALPN)))

	features = append(features, boolToFloat(sig.BrowserProps.IsMobile))
	features = append(features, boolToFloat(sig.BrowserProps.SupportsHTTP3))
	features = append(features, boolToFloat(sig.BrowserProps.SupportsGREASE))
	features = append(features, boolToFloat(sig.BrowserProps.SupportsTLS13))
	features = append(features, boolToFloat(sig.BrowserProps.SessionTickets))
	features = append(features, boolToFloat(sig.BrowserProps.ECHSupport))
	features = append(features, boolToFloat(sig.BrowserProps.QUICSupport))

	features = append(features, float64(sig.BrowserProps.MaxTLSVersion))
	features = append(features, float64(sig.BrowserProps.MinTLSVersion))

	features = append(features, sig.Confidence)
	features = append(features, sig.Weight)

	features = append(features, platformToFloat(sig.BrowserProps.Platform))
	features = append(features, libraryToFloat(sig.BrowserProps.TLSLibrary))
	features = append(features, familyToFloat(sig.BrowserProps.BrowserFamily))

	return features
}

func boolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

func platformToFloat(p Platform) float64 {
	switch p {
	case PlatformWindows:
		return 1.0
	case PlatformMacOS:
		return 2.0
	case PlatformLinux:
		return 3.0
	case PlatformAndroid:
		return 4.0
	case PlatformIOS:
		return 5.0
	case PlatformUnknown:
		return 0.0
	default:
		return 0.0
	}
}

func libraryToFloat(l TLSLibrary) float64 {
	switch l {
	case LibraryBoringSSL:
		return 1.0
	case LibraryOpenSSL:
		return 2.0
	case LibraryNSS:
		return 3.0
	case LibrarySecureTransport:
		return 4.0
	case LibraryConscrypt:
		return 5.0
	case LibraryGo:
		return 6.0
	default:
		return 0.0
	}
}

func familyToFloat(f BrowserFamily) float64 {
	switch f {
	case FamilyChrome:
		return 1.0
	case FamilyFirefox:
		return 2.0
	case FamilySafari:
		return 3.0
	case FamilyEdge:
		return 4.0
	case FamilyOpera:
		return 5.0
	case FamilyBrave:
		return 6.0
	case FamilyIOS:
		return 7.0
	case FamilyAndroid:
		return 8.0
	case FamilyUnknown:
		return 0.0
	default:
		return 0.0
	}
}

func (f *FeatureExtractor) ExtractFromJA4(ja4 string) []float64 {
	features := make([]float64, 20)

	parts := strings.Split(ja4, "_")
	if len(parts) < 2 {
		return features
	}

	if strings.HasPrefix(parts[0], "t13") {
		features[0] = 1.0
	} else if strings.HasPrefix(parts[0], "t12") {
		features[0] = 0.5
	}

	if strings.Contains(parts[0], "h2") {
		features[1] = 1.0
	}

	if len(parts) > 2 {
		if strings.HasSuffix(parts[len(parts)-1], "d") {
			features[2] = 1.0
		}
	}

	return features
}

type SignatureSimilarity struct {
	Signature1 string  `json:"signature_1"`
	Signature2 string  `json:"signature_2"`
	Similarity float64 `json:"similarity"`
}

func CalculateSimilarity(sig1, sig2 *FingerprintSignature) float64 {
	extractor := FeatureExtractor{}
	features1 := extractor.ExtractFromSignature(sig1)
	features2 := extractor.ExtractFromSignature(sig2)

	if len(features1) != len(features2) {
		return 0.0
	}

	var sumSquaredDiff float64
	for i := range features1 {
		diff := features1[i] - features2[i]
		sumSquaredDiff += diff * diff
	}

	similarity := 1.0 / (1.0 + sumSquaredDiff)
	return similarity
}

func FindMostSimilar(target *FingerprintSignature, candidates []FingerprintSignature) *FingerprintSignature {
	var bestMatch *FingerprintSignature
	var bestSimilarity float64

	for i := range candidates {
		if candidates[i].Name == target.Name {
			continue
		}
		sim := CalculateSimilarity(target, &candidates[i])
		if sim > bestSimilarity {
			bestSimilarity = sim
			bestMatch = &candidates[i]
		}
	}

	return bestMatch
}

type SignatureRegistry struct {
	signatures map[string]FingerprintSignature
}

func NewSignatureRegistry() *SignatureRegistry {
	return &SignatureRegistry{
		signatures: make(map[string]FingerprintSignature),
	}
}

func (r *SignatureRegistry) Register(sig FingerprintSignature) {
	r.signatures[sig.Name] = sig
}

func (r *SignatureRegistry) Get(name string) *FingerprintSignature {
	if sig, ok := r.signatures[name]; ok {
		return &sig
	}
	return nil
}

func (r *SignatureRegistry) List() []FingerprintSignature {
	sigs := make([]FingerprintSignature, 0, len(r.signatures))
	for _, sig := range r.signatures {
		sigs = append(sigs, sig)
	}
	return sigs
}

func (r *SignatureRegistry) ToJSON() (string, error) {
	data, err := json.MarshalIndent(r.signatures, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (r *SignatureRegistry) FromJSON(data string) error {
	return json.Unmarshal([]byte(data), &r.signatures)
}

func (r *SignatureRegistry) Merge(other *SignatureRegistry) {
	for _, sig := range other.signatures {
		r.signatures[sig.Name] = sig
	}
}

type SignatureGenerator struct {
	rng       *rand.Rand
	registry  *SignatureRegistry
	modifiers []func(*BrowserProperties)
}

func NewSignatureGenerator() *SignatureGenerator {
	registry := NewSignatureRegistry()
	for _, sig := range GetAllSignatures() {
		registry.Register(sig)
	}

	return &SignatureGenerator{
		rng:       rand.New(rand.NewSource(1)), //nolint:gosec // G404: math/rand is sufficient for testing/fingerprint generation
		registry:  registry,
		modifiers: make([]func(*BrowserProperties), 0),
	}
}

func (g *SignatureGenerator) WithSeed(seed int64) *SignatureGenerator {
	g.rng = rand.New(rand.NewSource(seed)) //nolint:gosec // G404: math/rand is sufficient for testing/fingerprint generation
	return g
}

func (g *SignatureGenerator) AddModifier(modifier func(*BrowserProperties)) *SignatureGenerator {
	g.modifiers = append(g.modifiers, modifier)
	return g
}

func (g *SignatureGenerator) GenerateFromBase(baseName string) *FingerprintSignature {
	base := g.registry.Get(baseName)
	if base == nil {
		base = &Chrome133Windows
	}

	generated := *base
	generated.Name = fmt.Sprintf("%s-custom-%d", base.Name, g.rng.Intn(10000))
	generated.Description = fmt.Sprintf("Custom variation of %s", base.Name)

	for _, mod := range g.modifiers {
		mod(&generated.BrowserProps)
	}

	return &generated
}

func (g *SignatureGenerator) GenerateRandom() *FingerprintSignature {
	sigs := g.registry.List()
	if len(sigs) == 0 {
		return &Chrome133Windows
	}
	return g.GenerateFromBase(sigs[g.rng.Intn(len(sigs))].Name)
}

var DefaultRegistry = func() *SignatureRegistry {
	registry := NewSignatureRegistry()
	for _, sig := range GetAllSignatures() {
		registry.Register(sig)
	}
	return registry
}()
