// Package tlsfprint provides TLS fingerprinting capabilities.
//
//nolint:gosec // G501, G404: crypto/md5 and math/rand used intentionally for fingerprinting
package tlsfprint

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// Browser represents a browser type for TLS fingerprint selection.
type Browser string

const (
	// Chrome represents the Chrome browser.
	Chrome Browser = "chrome"
	// Firefox represents the Firefox browser.
	Firefox Browser = "firefox"
	// Safari represents the Safari browser.
	Safari Browser = "safari"
	// Edge represents the Edge browser.
	Edge Browser = "edge"
	// IOS represents iOS browser fingerprint.
	IOS Browser = "ios"
	// Android represents Android browser fingerprint.
	Android Browser = "android"
)

// ClientHelloID is an alias for utls.ClientHelloID, identifying a specific ClientHello fingerprint.
type ClientHelloID = utls.ClientHelloID

var ( //nolint:revive // Variable names match utls library naming convention
	// HelloGolang represents the default Go TLS fingerprint.
	HelloGolang = utls.HelloGolang
	// HelloChrome_Auto represents auto-detected Chrome fingerprint.
	HelloChrome_Auto = utls.HelloChrome_Auto
	// HelloChrome_120 represents Chrome 120 fingerprint.
	HelloChrome_120 = utls.HelloChrome_120
	// HelloChrome_133 represents Chrome 133 fingerprint.
	HelloChrome_133 = utls.HelloChrome_133
	// HelloFirefox_Auto represents auto-detected Firefox fingerprint.
	HelloFirefox_Auto = utls.HelloFirefox_Auto
	// HelloFirefox_120 represents Firefox 120 fingerprint.
	HelloFirefox_120 = utls.HelloFirefox_120
	// HelloFirefox_105 represents Firefox 105 fingerprint.
	HelloFirefox_105 = utls.HelloFirefox_105
	// HelloSafari_16_0 represents Safari 16.0 fingerprint.
	HelloSafari_16_0 = utls.HelloSafari_16_0
	// HelloEdge_Auto represents auto-detected Edge fingerprint.
	HelloEdge_Auto = utls.HelloEdge_Auto
	// HelloEdge_106 represents Edge 106 fingerprint.
	HelloEdge_106 = utls.HelloEdge_106
	// HelloIOS_14 represents iOS 14 fingerprint.
	HelloIOS_14 = utls.HelloIOS_14
	// HelloIOS_13 represents iOS 13 fingerprint.
	HelloIOS_13 = utls.HelloIOS_13
	// HelloAndroid_11_OkHttp represents Android 11 OkHttp fingerprint.
	HelloAndroid_11_OkHttp = utls.HelloAndroid_11_OkHttp
	// HelloRandomized represents a fully randomized fingerprint.
	HelloRandomized = utls.HelloRandomized
	// HelloRandomizedALPN represents a randomized fingerprint with ALPN.
	HelloRandomizedALPN = utls.HelloRandomizedALPN
	// HelloRandomizedNoALPN represents a randomized fingerprint without ALPN.
	HelloRandomizedNoALPN = utls.HelloRandomizedNoALPN
	// HelloCustom represents a custom fingerprint configuration.
	HelloCustom = utls.HelloCustom
)

// FingerprintInfo contains detailed information about a TLS fingerprint.
type FingerprintInfo struct {
	JA3        string
	JA3Hash    string
	JA4        string
	Version    string
	Ciphers    []string
	Extensions []string
	ALPN       string
	SNI        string
	GREASE     bool
	Browser    string
	OS         string
	IsRandom   bool
}

// Spoofer provides TLS fingerprint spoofing capabilities for browser impersonation.
type Spoofer struct {
	rng *rand.Rand
}

// New creates a new Spoofer with default configuration.
func New() *Spoofer {
	return &Spoofer{
		rng: rand.New(rand.NewSource(1)),
	}
}

// WithSeed sets a custom random seed for fingerprint rotation.
// Returns the Spoofer for method chaining.
func (s *Spoofer) WithSeed(seed int64) *Spoofer {
	s.rng = rand.New(rand.NewSource(seed))
	return s
}

// GetClientHelloID returns the appropriate ClientHelloID for the given browser and version.
func (s *Spoofer) GetClientHelloID(browser Browser, version string) ClientHelloID {
	switch browser {
	case Chrome:
		return s.getChromeID(version)
	case Firefox:
		return s.getFirefoxID(version)
	case Safari:
		return HelloSafari_16_0
	case Edge:
		return s.getEdgeID(version)
	case IOS:
		return s.getIOSID(version)
	case Android:
		return HelloAndroid_11_OkHttp
	default:
		return HelloChrome_Auto
	}
}

func (s *Spoofer) getChromeID(version string) ClientHelloID {
	switch version {
	case "133":
		return HelloChrome_133
	case "120":
		return HelloChrome_120
	default:
		return HelloChrome_Auto
	}
}

func (s *Spoofer) getFirefoxID(version string) ClientHelloID {
	switch version {
	case "120":
		return HelloFirefox_120
	case "105":
		return HelloFirefox_105
	default:
		return HelloFirefox_Auto
	}
}

func (s *Spoofer) getEdgeID(version string) ClientHelloID {
	switch version {
	case "106":
		return HelloEdge_106
	default:
		return HelloEdge_Auto
	}
}

func (s *Spoofer) getIOSID(version string) ClientHelloID {
	switch version {
	case "14":
		return HelloIOS_14
	case "13":
		return HelloIOS_13
	default:
		return HelloIOS_14
	}
}

// GetRandomized returns a randomized ClientHelloID.
// If alpn is true, includes ALPN extension.
func (s *Spoofer) GetRandomized(alpn bool) ClientHelloID {
	if alpn {
		return HelloRandomizedALPN
	}
	return HelloRandomizedNoALPN
}

// GetRotatingFingerprint returns a random ClientHelloID from a pool of browser fingerprints.
func (s *Spoofer) GetRotatingFingerprint() ClientHelloID {
	fingerprints := []ClientHelloID{
		HelloChrome_Auto,
		HelloChrome_120,
		HelloFirefox_Auto,
		HelloFirefox_120,
		HelloSafari_16_0,
		HelloEdge_Auto,
		HelloEdge_106,
		HelloIOS_14,
		HelloAndroid_11_OkHttp,
	}
	return fingerprints[s.rng.Intn(len(fingerprints))]
}

// DetectBrowserFromJA4 attempts to detect the browser type from a JA4 fingerprint string.
// Returns "chrome", "modern_browser", "tls12_browser", or "unknown".
func (s *Spoofer) DetectBrowserFromJA4(ja4 string) string {
	parts := strings.Split(ja4, "_")
	if len(parts) < 2 {
		return "unknown"
	}

	prefix := parts[0]
	cipher := parts[len(parts)-1]

	switch {
	case strings.HasPrefix(prefix, "t13"):
		if cipher == "1301" || cipher == "1302" || cipher == "1303" {
			return "chrome"
		}
		return "modern_browser"
	case strings.HasPrefix(prefix, "t12"):
		return "tls12_browser"
	}

	return "unknown"
}

func (s *Spoofer) CalculateJA3(cipherSuites, extensions []uint16, version uint16) string {
	var cipherStrs []string
	for _, c := range cipherSuites {
		cipherStrs = append(cipherStrs, fmt.Sprintf("%04x", c))
	}

	var extStrs []string
	for _, e := range extensions {
		extStrs = append(extStrs, fmt.Sprintf("%d", e))
	}

	ja3 := fmt.Sprintf("%04x,%s,%s", version, strings.Join(cipherStrs, "-"), strings.Join(extStrs, "-"))
	return ja3
}

func (s *Spoofer) CalculateJA3Hash(ja3 string) string {
	hash := md5.Sum([]byte(ja3))
	return hex.EncodeToString(hash[:])
}

func (s *Spoofer) CalculateJA4(version, cipherSuite uint16, alpn string, extensions []uint16) string {
	var verStr string
	switch version {
	case 0x0304:
		verStr = "13"
	case 0x0303:
		verStr = "12"
	default:
		verStr = "00"
	}

	alpnStr := "_"
	if alpn == "h2" {
		alpnStr = "h2"
	}

	grease := hasGREASE(extensions)

	ja4 := fmt.Sprintf("t%s%s_%04x%s", verStr, alpnStr, cipherSuite, greaseSuffix(grease))
	return ja4
}

func hasGREASE(extensions []uint16) bool {
	for _, ext := range extensions {
		if ext >= 0x0a0a && ext <= 0x0afa {
			return true
		}
	}
	return false
}

func greaseSuffix(hasGREASE bool) string {
	if hasGREASE {
		return "d"
	}
	return ""
}

func (s *Spoofer) GetConfig(serverName string, alpn []string) *utls.Config {
	return &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		NextProtos:         alpn,
	}
}

func (s *Spoofer) GetSupportedBrowsers() []string {
	return []string{
		"chrome-auto",
		"chrome-133",
		"chrome-120",
		"firefox-auto",
		"firefox-120",
		"firefox-105",
		"safari-16.0",
		"edge-auto",
		"edge-106",
		"ios-14",
		"ios-13",
		"android-11-okhttp",
		"randomized",
		"randomized-alpn",
		"randomized-noalpn",
	}
}

func ParseBrowserVersion(input string) (Browser, string) {
	parts := strings.SplitN(input, "-", 2)
	if len(parts) != 2 {
		return Browser(strings.TrimSuffix(input, "-auto")), ""
	}

	browser := Browser(parts[0])
	version := parts[1]

	if version == "auto" {
		return browser, ""
	}

	return browser, version
}

type FingerprintGenerator struct {
	spoofer *Spoofer
	browser Browser
	version string
	alpn    bool
	seed    int64
}

func NewFingerprintGenerator() *FingerprintGenerator {
	return &FingerprintGenerator{
		spoofer: New(),
	}
}

func (fg *FingerprintGenerator) Browser(browser Browser) *FingerprintGenerator {
	fg.browser = browser
	return fg
}

func (fg *FingerprintGenerator) Version(version string) *FingerprintGenerator {
	fg.version = version
	return fg
}

func (fg *FingerprintGenerator) ALPN(enabled bool) *FingerprintGenerator {
	fg.alpn = enabled
	return fg
}

func (fg *FingerprintGenerator) Seed(seed int64) *FingerprintGenerator {
	fg.seed = seed
	fg.spoofer = fg.spoofer.WithSeed(seed)
	return fg
}

func (fg *FingerprintGenerator) Build() ClientHelloID {
	if fg.version == "" {
		switch fg.browser {
		case Chrome:
			return HelloChrome_Auto
		case Firefox:
			return HelloFirefox_Auto
		case Safari:
			return HelloSafari_16_0
		case Edge:
			return HelloEdge_Auto
		case IOS:
			return HelloIOS_14
		case Android:
			return HelloAndroid_11_OkHttp
		}
	}
	return fg.spoofer.GetClientHelloID(fg.browser, fg.version)
}

func (fg *FingerprintGenerator) BuildRandomized() ClientHelloID {
	if fg.seed != 0 {
		fg.spoofer = fg.spoofer.WithSeed(fg.seed)
	}
	return fg.spoofer.GetRandomized(fg.alpn)
}

func (fg *FingerprintGenerator) BuildRotating() ClientHelloID {
	return fg.spoofer.GetRotatingFingerprint()
}

func (s *Spoofer) CreateChromeFingerprint() ClientHelloID {
	versions := []ClientHelloID{HelloChrome_120, HelloChrome_133, HelloChrome_Auto}
	return versions[s.rng.Intn(len(versions))]
}

func (s *Spoofer) CreateFirefoxFingerprint() ClientHelloID {
	versions := []ClientHelloID{HelloFirefox_120, HelloFirefox_105, HelloFirefox_Auto}
	return versions[s.rng.Intn(len(versions))]
}

func (s *Spoofer) CreateMobileFingerprint() ClientHelloID {
	mobile := []ClientHelloID{
		HelloIOS_14,
		HelloIOS_13,
		HelloAndroid_11_OkHttp,
	}
	return mobile[s.rng.Intn(len(mobile))]
}

func (s *Spoofer) AnalyzeJA4(ja4 string) *FingerprintInfo {
	info := &FingerprintInfo{JA4: ja4}

	parts := strings.Split(ja4, "_")
	if len(parts) < 2 {
		return info
	}

	if strings.HasPrefix(parts[0], "t13") {
		info.Version = "TLS 1.3"
	} else if strings.HasPrefix(parts[0], "t12") {
		info.Version = "TLS 1.2"
	}

	if len(parts) > 2 {
		cipher := parts[len(parts)-2]
		info.Ciphers = []string{cipher}
		if strings.HasSuffix(parts[len(parts)-1], "d") {
			info.GREASE = true
		}
	}

	info.Browser = s.DetectBrowserFromJA4(ja4)

	return info
}

func FingerprintToJA3Hash(ja3 string) string {
	hash := sha256.Sum256([]byte(ja3))
	return hex.EncodeToString(hash[:])
}

type Rotator struct {
	fingerprints []ClientHelloID
	current      int
	rng          *rand.Rand
}

func NewRotator(fingerprints []ClientHelloID) *Rotator {
	if len(fingerprints) == 0 {
		fingerprints = []ClientHelloID{
			HelloChrome_Auto,
			HelloFirefox_Auto,
			HelloSafari_16_0,
			HelloEdge_Auto,
		}
	}
	return &Rotator{
		fingerprints: fingerprints,
		current:      0,
		rng:          rand.New(rand.NewSource(1)),
	}
}

func (r *Rotator) Next() ClientHelloID {
	fp := r.fingerprints[r.current]
	r.current = (r.current + 1) % len(r.fingerprints)
	return fp
}

func (r *Rotator) Random() ClientHelloID {
	return r.fingerprints[r.rng.Intn(len(r.fingerprints))]
}

func (r *Rotator) SetSeed(seed int64) {
	r.rng = rand.New(rand.NewSource(seed))
}

type FingerprintPool struct {
	fingerprints map[string]*Rotator
	defaultFP    ClientHelloID
}

func NewFingerprintPool() *FingerprintPool {
	return &FingerprintPool{
		fingerprints: make(map[string]*Rotator),
		defaultFP:    HelloChrome_Auto,
	}
}

func (p *FingerprintPool) AddRotator(name string, fps []ClientHelloID) {
	p.fingerprints[name] = NewRotator(fps)
}

func (p *FingerprintPool) SetDefault(fp ClientHelloID) {
	p.defaultFP = fp
}

func (p *FingerprintPool) Get(name string) ClientHelloID {
	if rotator, ok := p.fingerprints[name]; ok {
		return rotator.Next()
	}
	return p.defaultFP
}

func (p *FingerprintPool) GetRandom(name string) ClientHelloID {
	if rotator, ok := p.fingerprints[name]; ok {
		return rotator.Random()
	}
	return p.defaultFP
}
