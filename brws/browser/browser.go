// Package browser provides browser detection and classification utilities.
package browser

import (
	"strings"
)

// Type represents a browser type.
type Type int

const (
	// BrowserUnknown represents an unknown browser
	BrowserUnknown Type = iota
	// BrowserChrome represents Google Chrome
	BrowserChrome
	// BrowserFirefox represents Mozilla Firefox
	BrowserFirefox
	// BrowserSafari represents Apple Safari
	BrowserSafari
	// BrowserEdge represents Microsoft Edge
	BrowserEdge
	// BrowserOpera represents Opera
	BrowserOpera
	// BrowserBrave represents Brave browser
	BrowserBrave
)

// String returns the string representation of the browser type.
func (t Type) String() string {
	switch t {
	case BrowserUnknown:
		return "Unknown"
	case BrowserChrome:
		return "Chrome"
	case BrowserFirefox:
		return "Firefox"
	case BrowserSafari:
		return "Safari"
	case BrowserEdge:
		return "Edge"
	case BrowserOpera:
		return "Opera"
	case BrowserBrave:
		return "Brave"
	default:
		return "Unknown"
	}
}

// DetectFromUA detects the browser type from a User-Agent string.
func DetectFromUA(ua string) Type {
	ua = strings.ToLower(ua)

	// Check for Edge first (also contains Chrome/Safari in UA)
	if strings.Contains(ua, "edg") || strings.Contains(ua, "edge") {
		return BrowserEdge
	}

	// Check for Brave (also contains Chrome in UA)
	if strings.Contains(ua, "brave") {
		return BrowserBrave
	}

	// Check for Opera (also contains Chrome/Safari in UA)
	if strings.Contains(ua, "opr") || strings.Contains(ua, "opera") {
		return BrowserOpera
	}

	// Check for Firefox
	if strings.Contains(ua, "firefox") || strings.Contains(ua, "fxios") {
		return BrowserFirefox
	}

	// Check for Safari (check before Chrome as Safari also has "Safari" in UA)
	if strings.Contains(ua, "safari") && !strings.Contains(ua, "chrome") && !strings.Contains(ua, "chromium") {
		return BrowserSafari
	}

	// Check for Chrome/Chromium
	if strings.Contains(ua, "chrome") || strings.Contains(ua, "chromium") || strings.Contains(ua, "crios") {
		return BrowserChrome
	}

	return BrowserUnknown
}

// IsChrome returns true if the browser is Chrome or Chromium-based.
func (t Type) IsChrome() bool {
	return t == BrowserChrome || t == BrowserEdge || t == BrowserOpera || t == BrowserBrave
}

// IsWebKit returns true if the browser uses WebKit engine.
func (t Type) IsWebKit() bool {
	return t == BrowserSafari || t == BrowserChrome || t == BrowserEdge || t == BrowserOpera || t == BrowserBrave
}

// IsGecko returns true if the browser uses Gecko engine.
func (t Type) IsGecko() bool {
	return t == BrowserFirefox
}

// MatchesTLS checks if the browser type is consistent with a JA4 fingerprint.
func (t Type) MatchesTLS(ja4 string) bool {
	if ja4 == "" {
		return true
	}

	ja4 = strings.ToLower(ja4)

	switch t {
	case BrowserUnknown:
		return true
	case BrowserChrome, BrowserEdge, BrowserOpera, BrowserBrave:
		// Chrome-based browsers typically use specific TLS patterns
		return strings.Contains(ja4, "t13d") || strings.Contains(ja4, "q13d")
	case BrowserFirefox:
		// Firefox uses different patterns
		return strings.Contains(ja4, "t13d") || strings.Contains(ja4, "q13d") || strings.Contains(ja4, "t12d")
	case BrowserSafari:
		// Safari has distinct patterns
		return strings.Contains(ja4, "t13d") || strings.Contains(ja4, "q13d")
	default:
		return true
	}
}

// MatchesPlatform checks if the browser-platform combination is valid.
func (t Type) MatchesPlatform(platform string) bool {
	platform = strings.ToLower(platform)

	switch t {
	case BrowserUnknown:
		return true
	case BrowserSafari:
		// Safari is primarily on Apple platforms
		return strings.Contains(platform, "mac") ||
			strings.Contains(platform, "iphone") ||
			strings.Contains(platform, "ipad") ||
			strings.Contains(platform, "ios")
	case BrowserFirefox, BrowserChrome, BrowserEdge, BrowserOpera, BrowserBrave:
		// These browsers are available on all platforms
		return true
	default:
		return true
	}
}

// Info holds browser information extracted from a User-Agent string.
type Info struct {
	Type          Type
	Version       string
	Platform      string
	Mobile        bool
	Engine        string
	EngineVersion string
}

// Parse parses a User-Agent string and returns detailed browser information.
func Parse(ua string) *Info {
	info := &Info{
		Type:     DetectFromUA(ua),
		Platform: extractPlatform(ua),
		Mobile:   strings.Contains(strings.ToLower(ua), "mobile"),
	}

	// Extract version
	info.Version = extractVersion(ua, info.Type)
	info.Engine, info.EngineVersion = extractEngine(ua)

	return info
}

// extractPlatform extracts the platform from User-Agent.
func extractPlatform(ua string) string {
	ua = strings.ToLower(ua)

	switch {
	case strings.Contains(ua, "windows"):
		return "Windows"
	case strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os"):
		return "macOS"
	case strings.Contains(ua, "linux"):
		return "Linux"
	case strings.Contains(ua, "android"):
		return "Android"
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") || strings.Contains(ua, "ios"):
		return "iOS"
	default:
		return "Unknown"
	}
}

// extractVersion extracts the browser version from User-Agent.
func extractVersion(ua string, browserType Type) string {
	ua = strings.ToLower(ua)

	switch browserType {
	case BrowserUnknown:
		return ""
	case BrowserChrome:
		// Chrome/XX.X.XX.X or CriOS/XX.X.XX.X (iOS)
		if idx := strings.Index(ua, "chrome/"); idx != -1 {
			return extractVersionNumber(ua[idx+7:])
		}

		if idx := strings.Index(ua, "crios/"); idx != -1 {
			return extractVersionNumber(ua[idx+6:])
		}
	case BrowserFirefox:
		// Firefox/XX.X or FxiOS/XX.X (iOS)
		if idx := strings.Index(ua, "firefox/"); idx != -1 {
			return extractVersionNumber(ua[idx+8:])
		}

		if idx := strings.Index(ua, "fxios/"); idx != -1 {
			return extractVersionNumber(ua[idx+6:])
		}
	case BrowserSafari:
		// Version/XX.X
		if idx := strings.Index(ua, "version/"); idx != -1 {
			return extractVersionNumber(ua[idx+8:])
		}
	case BrowserEdge:
		// Edg/XX.X.XX.X or Edge/XX.X.XX.X
		if idx := strings.Index(ua, "edg/"); idx != -1 {
			return extractVersionNumber(ua[idx+4:])
		}

		if idx := strings.Index(ua, "edge/"); idx != -1 {
			return extractVersionNumber(ua[idx+5:])
		}
	case BrowserOpera:
		// OPR/XX.X.XX.X or Opera/XX.X.XX.X
		if idx := strings.Index(ua, "opr/"); idx != -1 {
			return extractVersionNumber(ua[idx+4:])
		}

		if idx := strings.Index(ua, "opera/"); idx != -1 {
			return extractVersionNumber(ua[idx+6:])
		}
	case BrowserBrave:
		// Brave doesn't have a specific version in UA, uses Chrome version
		if idx := strings.Index(ua, "chrome/"); idx != -1 {
			return extractVersionNumber(ua[idx+7:])
		}
	}

	return ""
}

// extractVersionNumber extracts the version number from a string.
func extractVersionNumber(s string) string {
	var version string

	for _, c := range s {
		if (c >= '0' && c <= '9') || c == '.' {
			version += string(c)
		} else {
			break
		}
	}

	return version
}

// extractEngine extracts the rendering engine and version from User-Agent.
func extractEngine(ua string) (engine, version string) {
	ua = strings.ToLower(ua)

	switch {
	case strings.Contains(ua, "gecko"):
		engine = "Gecko"

		if idx := strings.Index(ua, "gecko/"); idx != -1 {
			version = extractVersionNumber(ua[idx+6:])
		}
	case strings.Contains(ua, "webkit"):
		engine = "WebKit"

		if idx := strings.Index(ua, "webkit/"); idx != -1 {
			version = extractVersionNumber(ua[idx+7:])
		}
	case strings.Contains(ua, "blink"):
		engine = "Blink"
	}

	return engine, version
}
