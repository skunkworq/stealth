// Package profiles provides configurable browser fingerprint profiles
//nolint:gosec // G404: math/rand used intentionally for non-cryptographic profile selection/mutation
package profiles

import (
	//nolint:gosec // math/rand is used intentionally for non-cryptographic profile selection
	"math/rand"

	utls "github.com/refraction-networking/utls"
)

// Profile represents a complete browser fingerprint profile
type Profile struct {
	Name     string
	Version  string
	Platform string
	Mobile   bool

	// Screen dimensions
	ScreenWidth  int
	ScreenHeight int

	// HTTP Headers
	UserAgent      string
	Accept         string
	AcceptLanguage string
	AcceptEncoding string

	// Client Hints (Chrome)
	SecChUa         string
	SecChUaMobile   string
	SecChUaPlatform string

	// Sec-Fetch headers
	SecFetchDest string
	SecFetchMode string
	SecFetchSite string
	SecFetchUser string

	// Other headers
	UpgradeInsecureRequests string

	// TLS Fingerprint
	TLSFingerprint utls.ClientHelloID
}

// GetChrome120Mac returns a Chrome 120 on macOS profile
func GetChrome120Mac() *Profile {
	return &Profile{
		Name:                    "chrome",
		Version:                 "120",
		Platform:                "macos",
		Mobile:                  false,
		UserAgent:               "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		Accept:                  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		AcceptLanguage:          "en-US,en;q=0.5",
		AcceptEncoding:          "gzip, deflate, br",
		SecChUa:                 "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"",
		SecChUaMobile:           "?0",
		SecChUaPlatform:         "\"macOS\"",
		SecFetchDest:            "document",
		SecFetchMode:            "navigate",
		SecFetchSite:            "none",
		SecFetchUser:            "?1",
		UpgradeInsecureRequests: "1",
		TLSFingerprint:          utls.HelloChrome_120,
	}
}

// GetChrome120Win returns a Chrome 120 on Windows profile
func GetChrome120Win() *Profile {
	return &Profile{
		Name:                    "chrome",
		Version:                 "120",
		Platform:                "windows",
		Mobile:                  false,
		UserAgent:               "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		Accept:                  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		AcceptLanguage:          "en-US,en;q=0.5",
		AcceptEncoding:          "gzip, deflate, br",
		SecChUa:                 "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"",
		SecChUaMobile:           "?0",
		SecChUaPlatform:         "\"Windows\"",
		SecFetchDest:            "document",
		SecFetchMode:            "navigate",
		SecFetchSite:            "none",
		SecFetchUser:            "?1",
		UpgradeInsecureRequests: "1",
		TLSFingerprint:          utls.HelloChrome_120,
	}
}

// GetChrome120Android returns a Chrome 120 on Android profile
func GetChrome120Android() *Profile {
	return &Profile{
		Name:                    "chrome",
		Version:                 "120",
		Platform:                "android",
		Mobile:                  true,
		UserAgent:               "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.210 Mobile Safari/537.36",
		Accept:                  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		AcceptLanguage:          "en-US,en;q=0.5",
		AcceptEncoding:          "gzip, deflate, br",
		SecChUa:                 "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"",
		SecChUaMobile:           "?1",
		SecChUaPlatform:         "\"Android\"",
		SecFetchDest:            "document",
		SecFetchMode:            "navigate",
		SecFetchSite:            "none",
		SecFetchUser:            "?1",
		UpgradeInsecureRequests: "1",
		TLSFingerprint:          utls.HelloChrome_120,
	}
}

// GetFirefox120Mac returns a Firefox 120 on macOS profile
// Real Firefox doesn't send Chrome Client Hints - keep it authentic
func GetFirefox120Mac() *Profile {
	return &Profile{
		Name:                    "firefox",
		Version:                 "120",
		Platform:                "macos",
		Mobile:                  false,
		UserAgent:               "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
		Accept:                  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		AcceptLanguage:          "en-US,en;q=0.5",
		AcceptEncoding:          "gzip, deflate, br",
		SecChUa:                 "", // Firefox doesn't send these
		SecChUaMobile:           "",
		SecChUaPlatform:         "",
		SecFetchDest:            "", // Firefox doesn't send Sec-Fetch
		SecFetchMode:            "",
		SecFetchSite:            "",
		SecFetchUser:            "",
		UpgradeInsecureRequests: "1",
		TLSFingerprint:          utls.HelloFirefox_120,
	}
}

// GetFirefox120Win returns a Firefox 120 on Windows profile
// Real Firefox doesn't send Chrome Client Hints - keep it authentic
func GetFirefox120Win() *Profile {
	return &Profile{
		Name:                    "firefox",
		Version:                 "120",
		Platform:                "windows",
		Mobile:                  false,
		UserAgent:               "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
		Accept:                  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		AcceptLanguage:          "en-US,en;q=0.5",
		AcceptEncoding:          "gzip, deflate, br",
		SecChUa:                 "", // Firefox doesn't send these
		SecChUaMobile:           "",
		SecChUaPlatform:         "",
		SecFetchDest:            "", // Firefox doesn't send Sec-Fetch
		SecFetchMode:            "",
		SecFetchSite:            "",
		SecFetchUser:            "",
		UpgradeInsecureRequests: "1",
		TLSFingerprint:          utls.HelloFirefox_120,
	}
}

// GetSafari16Mac returns a Safari 16 on macOS profile
// Real Safari doesn't send Chrome Client Hints - keep it authentic
func GetSafari16Mac() *Profile {
	return &Profile{
		Name:                    "safari",
		Version:                 "16.0",
		Platform:                "macos",
		Mobile:                  false,
		UserAgent:               "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
		Accept:                  "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		AcceptLanguage:          "en-US,en;q=0.5",
		AcceptEncoding:          "gzip, deflate, br",
		SecChUa:                 "", // Safari doesn't send these
		SecChUaMobile:           "",
		SecChUaPlatform:         "",
		UpgradeInsecureRequests: "1",
		TLSFingerprint:          utls.HelloSafari_16_0,
	}
}

// GetSafariMobileiOS returns a Safari on iOS profile
func GetSafariMobileiOS() *Profile {
	return &Profile{
		Name:           "safari",
		Version:        "16.0",
		Platform:       "ios",
		Mobile:         true,
		UserAgent:      "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
		Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		AcceptLanguage: "en-US,en;q=0.5",
		AcceptEncoding: "gzip, deflate, br",
		TLSFingerprint: utls.HelloSafari_16_0,
	}
}

// GetEdge120Win returns an Edge 120 on Windows profile
func GetEdge120Win() *Profile {
	return &Profile{
		Name:                    "edge",
		Version:                 "120",
		Platform:                "windows",
		Mobile:                  false,
		UserAgent:               "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		Accept:                  "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		AcceptLanguage:          "en-US,en;q=0.5",
		AcceptEncoding:          "gzip, deflate, br",
		SecChUa:                 "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Microsoft Edge\";v=\"120\"",
		SecChUaMobile:           "?0",
		SecChUaPlatform:         "\"Windows\"",
		SecFetchDest:            "document",
		SecFetchMode:            "navigate",
		SecFetchSite:            "none",
		SecFetchUser:            "?1",
		UpgradeInsecureRequests: "1",
		TLSFingerprint:          utls.HelloChrome_120, // Edge uses Chrome fingerprint
	}
}

// ToHeaders converts a profile to header map
func (p *Profile) ToHeaders() map[string]string {
	headers := make(map[string]string)

	if p.UserAgent != "" {
		headers["User-Agent"] = p.UserAgent
	}
	if p.Accept != "" {
		headers["Accept"] = p.Accept
	}
	if p.AcceptLanguage != "" {
		headers["Accept-Language"] = p.AcceptLanguage
	}
	if p.AcceptEncoding != "" {
		headers["Accept-Encoding"] = p.AcceptEncoding
	}
	if p.SecChUa != "" {
		headers["Sec-Ch-Ua"] = p.SecChUa
	}
	if p.SecChUaMobile != "" {
		headers["Sec-Ch-Ua-Mobile"] = p.SecChUaMobile
	}
	if p.SecChUaPlatform != "" {
		headers["Sec-Ch-Ua-Platform"] = p.SecChUaPlatform
	}
	if p.SecFetchDest != "" {
		headers["Sec-Fetch-Dest"] = p.SecFetchDest
	}
	if p.SecFetchMode != "" {
		headers["Sec-Fetch-Mode"] = p.SecFetchMode
	}
	if p.SecFetchSite != "" {
		headers["Sec-Fetch-Site"] = p.SecFetchSite
	}
	if p.SecFetchUser != "" {
		headers["Sec-Fetch-User"] = p.SecFetchUser
	}
	if p.UpgradeInsecureRequests != "" {
		headers["Upgrade-Insecure-Requests"] = p.UpgradeInsecureRequests
	}

	return headers
}

// GetByName returns a profile by name (e.g., "chrome-120-macos", "firefox-120-windows")
func GetByName(name string) *Profile {
	switch name {
	case "chrome-120-macos":
		return GetChrome120Mac()
	case "chrome-120-windows":
		return GetChrome120Win()
	case "chrome-120-android":
		return GetChrome120Android()
	case "firefox-120-macos":
		return GetFirefox120Mac()
	case "firefox-120-windows":
		return GetFirefox120Win()
	case "safari-16-macos":
		return GetSafari16Mac()
	case "safari-ios":
		return GetSafariMobileiOS()
	case "edge-120-windows":
		return GetEdge120Win()
	default:
		return GetChrome120Mac() // Default to Chrome
	}
}

// AvailableProfiles returns list of available profile names
func AvailableProfiles() []string {
	return []string{
		"chrome-120-macos",
		"chrome-120-windows",
		"chrome-120-android",
		"firefox-120-macos",
		"firefox-120-windows",
		"safari-16-macos",
		"safari-ios",
		"edge-120-windows",
	}
}

// Note: rand.Seed is deprecated since Go 1.20.
// The global random generator is automatically seeded.

// RandomProfile returns a random profile
func RandomProfile() *Profile {
	names := AvailableProfiles()
	return GetByName(names[rand.Intn(len(names))])
}

// RandomProfileForPlatform returns a random profile for a specific platform
func RandomProfileForPlatform(platform string) *Profile {
	var candidates []string

	switch platform {
	case "windows":
		candidates = []string{"chrome-120-windows", "firefox-120-windows", "edge-120-windows"}
	case "macos":
		candidates = []string{"chrome-120-macos", "safari-16-macos", "firefox-120-macos"}
	case "android":
		candidates = []string{"chrome-120-android"}
	case "ios":
		candidates = []string{"safari-ios"}
	default:
		return RandomProfile()
	}

	return GetByName(candidates[rand.Intn(len(candidates))])
}

// Mutate returns a mutated version of the profile with random variations
func (p *Profile) Mutate() *Profile {
	mutated := *p

	// Mutate minor version
	switch p.Name {
	case "chrome":
		versions := []string{"118", "119", "120", "121", "122"}
		ver := versions[rand.Intn(len(versions))]
		mutated.Version = ver
		mutated.UserAgent = p.mutateChromeVersion(ver)
		mutated.SecChUa = p.mutateSecChUa(ver)
	case "firefox":
		versions := []string{"118", "119", "120", "121"}
		ver := versions[rand.Intn(len(versions))]
		mutated.Version = ver
		mutated.UserAgent = p.mutateFirefoxVersion(ver)
	case "safari":
		versions := []string{"15.6", "16.0", "16.5", "16.6"}
		ver := versions[rand.Intn(len(versions))]
		mutated.Version = ver
		mutated.UserAgent = p.mutateSafariVersion(ver)
	}

	// Mutate screen size slightly
	if rand.Float32() > 0.5 {
		mutated.mutateScreenSize()
	}

	return &mutated
}

func (p *Profile) mutateChromeVersion(v string) string {
	platforms := []string{
		"Macintosh; Intel Mac OS X 10_15_7",
		"Windows NT 10.0; Win64; x64",
		"Linux; x86_64",
	}
	platform := platforms[rand.Intn(len(platforms))]

	if platform == "Macintosh; Intel Mac OS X 10_15_7" {
		return p.UserAgent
	}

	return `Mozilla/5.0 (` + platform + `) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/` + v + `.0.0.0 Safari/537.36`
}

func (p *Profile) mutateFirefoxVersion(v string) string {
	platforms := []string{
		"Macintosh; Intel Mac OS X 10.15; rv:" + v + ")",
		"Windows NT 10.0; Win64; x64; rv:" + v + ")",
		"Linux; x86_64; rv:" + v + ")",
	}
	platform := platforms[rand.Intn(len(platforms))]

	return "Mozilla/5.0 (" + platform + " Gecko/20100101 Firefox/" + v + ".0"
}

func (p *Profile) mutateSafariVersion(v string) string {
	return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/" + v + " Safari/605.1.15"
}

func (p *Profile) mutateSecChUa(v string) string {
	return `"Not_A Brand";v="8", "Chromium";v="` + v + `", "Google Chrome";v="` + v + `"`
}

func (p *Profile) mutateScreenSize() {
	sizes := []struct{ w, h int }{
		{1920, 1080},
		{1366, 768},
		{1536, 864},
		{1440, 900},
		{1280, 720},
	}
	size := sizes[rand.Intn(len(sizes))]
	p.ScreenWidth = size.w
	p.ScreenHeight = size.h
}

// Rotator manages profile rotation
type Rotator struct {
	profiles []*Profile
	current  int
}

// NewRotator creates a new profile rotator
func NewRotator(profiles []*Profile) *Rotator {
	if len(profiles) == 0 {
		// Use all available profiles
		names := AvailableProfiles()

		profiles = make([]*Profile, len(names))
		for i, name := range names {
			profiles[i] = GetByName(name)
		}
	}

	return &Rotator{
		profiles: profiles,
	}
}

// Next returns the next profile
func (r *Rotator) Next() *Profile {
	p := r.profiles[r.current]
	r.current = (r.current + 1) % len(r.profiles)
	return p
}

// Random returns a random profile
func (r *Rotator) Random() *Profile {
	return r.profiles[rand.Intn(len(r.profiles))]
}

// Mutated returns a mutated version of a random profile
func (r *Rotator) Mutated() *Profile {
	base := r.Random()
	if rand.Float32() > 0.3 { // 70% chance of mutation
		return base.Mutate()
	}
	return base
}
