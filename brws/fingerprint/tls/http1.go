package tlsfprint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

type HTTP1Fingerprint struct {
	Headers            map[string]string
	HeaderOrder        []string
	UserAgent          string
	Accept             string
	AcceptLanguage     string
	AcceptEncoding     string
	ContentType        string
	Connection         string
	CacheControl       string
	SecChUa            string
	SecChUaMobile      string
	SecChUaPlatform    string
	SecChUaFullVersion string
	SecFetchDest       string
	SecFetchMode       string
	SecFetchSite       string
	SecFetchUser       string
	UpgradeInsecure    string
	JA3H1              string
}

func CalculateHTTP1Fingerprint(headers map[string]string) string {
	var parts []string

	order := []string{
		":method", ":path", ":scheme", ":authority",
		"host", "user-agent", "accept", "accept-language", "accept-encoding",
		"content-type", "connection", "cache-control",
		"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-ch-ua-full-version",
		"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
		"upgrade-insecure-requests",
	}

	for _, h := range order {
		if v, ok := headers[h]; ok {
			parts = append(parts, fmt.Sprintf("%s:%s", h, v))
		}
	}

	return strings.Join(parts, ";")
}

func CalculateJA3H1(headers map[string]string) string {
	var headerParts []string

	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, strings.ToLower(k))
	}
	sort.Strings(keys)

	for _, k := range keys {
		headerParts = append(headerParts, fmt.Sprintf("%s:%s", k, headers[k]))
	}

	combined := strings.Join(headerParts, ",")
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:])[:32]
}

type HTTP1Signature struct {
	Name            string
	Version         string
	Platform        string
	UserAgent       string
	Accept          string
	AcceptLanguage  string
	AcceptEncoding  string
	Headers         map[string]string
	HeaderOrder     []string
	SecChUa         string
	SecChUaMobile   string
	SecChUaPlatform string
	SecFetchDest    string
	SecFetchMode    string
	SecFetchSite    string
	JA3H1           string
}

var HTTP1Signatures = map[string]*HTTP1Signature{
	"chrome-120-windows": {
		Name:           "Chrome 120 Windows",
		Version:        "120.0.6099.129",
		Platform:       "Windows",
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
		AcceptLanguage: "en-US,en;q=0.9",
		AcceptEncoding: "gzip, deflate, br",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"Windows"`,
			"sec-fetch-dest":            "document",
			"sec-fetch-mode":            "navigate",
			"sec-fetch-site":            "none",
			"sec-fetch-user":            "?1",
			"upgrade-insecure-requests": "1",
		},
		HeaderOrder: []string{
			":method", ":path", ":scheme", ":authority",
			"accept", "accept-encoding", "accept-language",
			"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
			"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
			"upgrade-insecure-requests", "user-agent",
		},
	},
	"chrome-120-macos": {
		Name:           "Chrome 120 macOS",
		Version:        "120.0.6099.129",
		Platform:       "macOS",
		UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
		AcceptLanguage: "en-US,en;q=0.9",
		AcceptEncoding: "gzip, deflate, br",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"macOS"`,
			"sec-fetch-dest":            "document",
			"sec-fetch-mode":            "navigate",
			"sec-fetch-site":            "none",
			"sec-fetch-user":            "?1",
			"upgrade-insecure-requests": "1",
		},
		HeaderOrder: []string{
			":method", ":path", ":scheme", ":authority",
			"accept", "accept-encoding", "accept-language",
			"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
			"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
			"upgrade-insecure-requests", "user-agent",
		},
	},
	"chrome-120-android": {
		Name:           "Chrome 120 Android",
		Version:        "120.0.6099.210",
		Platform:       "Android",
		UserAgent:      "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
		Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
		AcceptLanguage: "en-US,en;q=0.9",
		AcceptEncoding: "gzip, deflate, br",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
			"sec-ch-ua-mobile":          "?1",
			"sec-ch-ua-platform":        `"Android"`,
			"sec-fetch-dest":            "document",
			"sec-fetch-mode":            "navigate",
			"sec-fetch-site":            "none",
			"sec-fetch-user":            "?1",
			"upgrade-insecure-requests": "1",
		},
		HeaderOrder: []string{
			":method", ":path", ":scheme", ":authority",
			"accept", "accept-encoding", "accept-language",
			"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
			"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
			"upgrade-insecure-requests", "user-agent",
		},
	},
	"firefox-120-windows": {
		Name:           "Firefox 120 Windows",
		Version:        "120.0",
		Platform:       "Windows",
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
		Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		AcceptLanguage: "en-US,en;q=0.5",
		AcceptEncoding: "gzip, deflate, br",
		Headers: map[string]string{
			"sec-fetch-dest":            "document",
			"sec-fetch-mode":            "navigate",
			"sec-fetch-site":            "none",
			"sec-fetch-user":            "?1",
			"upgrade-insecure-requests": "1",
		},
		HeaderOrder: []string{
			":method", ":path", ":scheme", ":authority",
			"host", "user-agent", "accept", "accept-language", "accept-encoding",
			"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
			"upgrade-insecure-requests",
		},
	},
	"firefox-120-macos": {
		Name:           "Firefox 120 macOS",
		Version:        "120.0",
		Platform:       "macOS",
		UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
		Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		AcceptLanguage: "en-US,en;q=0.5",
		AcceptEncoding: "gzip, deflate, br",
		Headers: map[string]string{
			"sec-fetch-dest":            "document",
			"sec-fetch-mode":            "navigate",
			"sec-fetch-site":            "none",
			"sec-fetch-user":            "?1",
			"upgrade-insecure-requests": "1",
		},
		HeaderOrder: []string{
			":method", ":path", ":scheme", ":authority",
			"host", "user-agent", "accept", "accept-language", "accept-encoding",
			"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
			"upgrade-insecure-requests",
		},
	},
	"safari-17-macos": {
		Name:           "Safari 17 macOS",
		Version:        "17.1",
		Platform:       "macOS",
		UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
		Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		AcceptLanguage: "en-US,en;q=0.9",
		AcceptEncoding: "gzip, deflate, br",
		Headers: map[string]string{
			"sec-fetch-dest": "document",
			"sec-fetch-mode": "navigate",
			"sec-fetch-site": "same-origin",
		},
		HeaderOrder: []string{
			":method", ":path", ":scheme", ":authority",
			"accept", "accept-language", "accept-encoding",
			"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "user-agent",
		},
	},
	"edge-120-windows": {
		Name:           "Edge 120 Windows",
		Version:        "120.0.2210.120",
		Platform:       "Windows",
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
		AcceptLanguage: "en-US,en;q=0.9",
		AcceptEncoding: "gzip, deflate, br",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not_A Brand";v="8", "Chromium";v="120", "Microsoft Edge";v="120"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"Windows"`,
			"sec-fetch-dest":            "document",
			"sec-fetch-mode":            "navigate",
			"sec-fetch-site":            "none",
			"sec-fetch-user":            "?1",
			"upgrade-insecure-requests": "1",
		},
		HeaderOrder: []string{
			":method", ":path", ":scheme", ":authority",
			"accept", "accept-encoding", "accept-language",
			"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
			"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
			"upgrade-insecure-requests", "user-agent",
		},
	},
}

func DetectBrowserFromHTTP1(headers map[string]string) string {
	ua := headers["user-agent"]
	if ua == "" {
		ua = headers["User-Agent"]
	}
	if ua == "" {
		return "unknown"
	}

	switch {
	case strings.Contains(ua, "Chrome") && !strings.Contains(ua, "Edg"):
		if strings.Contains(ua, "Android") || strings.Contains(ua, "Mobile") {
			return "chrome-mobile"
		}
		return "chrome"
	case strings.Contains(ua, "Edg"):
		return "edge"
	case strings.Contains(ua, "Firefox"):
		return "firefox"
	case strings.Contains(ua, "Safari") && !strings.Contains(ua, "Chrome"):
		if strings.Contains(ua, "Mobile") {
			return "safari-mobile"
		}
		return "safari"
	}

	return "unknown"
}

func MatchHTTP1Signature(headers map[string]string) *HTTP1Signature {
	ua := strings.ToLower(headers["user-agent"])
	if ua == "" {
		ua = strings.ToLower(headers["User-Agent"])
	}

	for _, sig := range HTTP1Signatures {
		sigUA := strings.ToLower(sig.UserAgent)

		if strings.Contains(ua, "edg") && strings.Contains(sigUA, "edg") {
			return sig
		}
		if strings.Contains(ua, "chrome") && !strings.Contains(ua, "edg") && strings.Contains(sigUA, "chrome") {
			if strings.Contains(ua, "android") && strings.Contains(sig.Platform, "Android") {
				return sig
			}
			if strings.Contains(ua, "mac os x") && strings.Contains(sig.Platform, "macOS") {
				return sig
			}
			if !strings.Contains(ua, "android") && !strings.Contains(ua, "mobile") && strings.Contains(sig.Platform, "Windows") {
				return sig
			}
		}
		if strings.Contains(ua, "firefox") && strings.Contains(sigUA, "firefox") {
			if strings.Contains(ua, "windows") && strings.Contains(sig.Platform, "Windows") {
				return sig
			}
			if strings.Contains(ua, "mac os x") && strings.Contains(sig.Platform, "macOS") {
				return sig
			}
		}
		if strings.Contains(ua, "safari") && strings.Contains(sigUA, "safari") && !strings.Contains(ua, "chrome") {
			if strings.Contains(ua, "mobile") {
				return nil
			}
			if strings.Contains(sig.Platform, "macOS") {
				return sig
			}
		}
	}

	return nil
}

type HTTP1Analyzer struct {
	observations []HTTP1Observation
}

type HTTP1Observation struct {
	Timestamp       int64
	Headers         map[string]string
	HeaderOrder     []string
	UserAgent       string
	Accept          string
	AcceptLanguage  string
	AcceptEncoding  string
	JA3H1           string
	DetectedBrowser string
	SignatureMatch  *HTTP1Signature
}

func NewHTTP1Analyzer() *HTTP1Analyzer {
	return &HTTP1Analyzer{
		observations: make([]HTTP1Observation, 0),
	}
}

func (a *HTTP1Analyzer) Record(headers map[string]string) HTTP1Observation {
	ua := headers["user-agent"]
	if ua == "" {
		ua = headers["User-Agent"]
	}
	accept := headers["accept"]
	if accept == "" {
		accept = headers["Accept"]
	}
	acceptLang := headers["accept-language"]
	if acceptLang == "" {
		acceptLang = headers["Accept-Language"]
	}
	acceptEnc := headers["accept-encoding"]
	if acceptEnc == "" {
		acceptEnc = headers["Accept-Encoding"]
	}

	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	obs := HTTP1Observation{
		Headers:         headers,
		HeaderOrder:     keys,
		UserAgent:       ua,
		Accept:          accept,
		AcceptLanguage:  acceptLang,
		AcceptEncoding:  acceptEnc,
		JA3H1:           CalculateJA3H1(headers),
		DetectedBrowser: DetectBrowserFromHTTP1(headers),
		SignatureMatch:  MatchHTTP1Signature(headers),
	}
	a.observations = append(a.observations, obs)
	return obs
}

func (a *HTTP1Analyzer) GetObservations() []HTTP1Observation {
	return a.observations
}

func (a *HTTP1Analyzer) GetUniqueFingerprints() map[string]bool {
	unique := make(map[string]bool)
	for _, obs := range a.observations {
		unique[obs.JA3H1] = true
	}
	return unique
}

func (a *HTTP1Analyzer) GetBrowserDistribution() map[string]int {
	dist := make(map[string]int)
	for _, obs := range a.observations {
		dist[obs.DetectedBrowser]++
	}
	return dist
}

func (a *HTTP1Analyzer) GetSignatureMatchDistribution() map[string]int {
	dist := make(map[string]int)
	for _, obs := range a.observations {
		if obs.SignatureMatch != nil {
			dist[obs.SignatureMatch.Name]++
		} else {
			dist["unknown"]++
		}
	}
	return dist
}

var (
	chromeUAPattern  = regexp.MustCompile(`(?i)Mozilla/5\.0.*Chrome/\d+`)
	firefoxUAPattern = regexp.MustCompile(`(?i)Mozilla/5\.0.*Firefox/\d+`)
	safariUAPattern  = regexp.MustCompile(`(?i)Mozilla/5\.0.*Safari/\d+`)
	edgeUAPattern    = regexp.MustCompile(`(?i)Mozilla/5\.0.*Edg/\d+`)
)

func ValidateUserAgent(ua string) bool {
	if ua == "" {
		return false
	}
	return chromeUAPattern.MatchString(ua) ||
		firefoxUAPattern.MatchString(ua) ||
		safariUAPattern.MatchString(ua) ||
		edgeUAPattern.MatchString(ua)
}

func ExtractBrowserInfo(ua string) (browser, version, platform string) {
	if ua == "" {
		return "unknown", "", ""
	}

	switch {
	case strings.Contains(ua, "Edg/"):
		parts := strings.Split(ua, "Edg/")
		if len(parts) > 1 {
			version = strings.Split(parts[1], " ")[0]
		}
		return "edge", version, extractPlatform(ua)
	case strings.Contains(ua, "Chrome/"):
		parts := strings.Split(ua, "Chrome/")
		if len(parts) > 1 {
			version = strings.Split(parts[1], " ")[0]
		}
		if strings.Contains(ua, "Mobile") || strings.Contains(ua, "Android") {
			return "chrome-mobile", version, extractPlatform(ua)
		}
		return "chrome", version, extractPlatform(ua)
	case strings.Contains(ua, "Firefox/"):
		parts := strings.Split(ua, "Firefox/")
		if len(parts) > 1 {
			version = strings.Split(parts[1], " ")[0]
		}
		return "firefox", version, extractPlatform(ua)
	case strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad"):
		return "safari-mobile", "", "iOS"
	case strings.Contains(ua, "Version/") && strings.Contains(ua, "Safari/"):
		parts := strings.Split(ua, "Version/")
		if len(parts) > 1 {
			version = strings.Split(parts[1], " ")[0]
		}
		if strings.Contains(ua, "Mobile") {
			return "safari-mobile", version, "iOS"
		}
		return "safari", version, extractPlatform(ua)
	}

	return "unknown", "", ""
}

func extractPlatform(ua string) string {
	switch {
	case strings.Contains(ua, "Windows"):
		return "Windows"
	case strings.Contains(ua, "Mac OS X"):
		return "macOS"
	case strings.Contains(ua, "Android"):
		return "Android"
	case strings.Contains(ua, "Linux"):
		return "Linux"
	case strings.Contains(ua, "iPhone"):
		return "iOS"
	case strings.Contains(ua, "iPad"):
		return "iOS"
	}
	return "unknown"
}

type HTTPHeaderGenerator struct {
	signature *HTTP1Signature
	randomize bool
	seed      int64
}

func NewHTTPHeaderGenerator(sig *HTTP1Signature, randomize bool, seed int64) *HTTPHeaderGenerator {
	return &HTTPHeaderGenerator{
		signature: sig,
		randomize: randomize,
		seed:      seed,
	}
}

func (g *HTTPHeaderGenerator) Generate(headers map[string]string) map[string]string {
	result := make(map[string]string)

	if g.signature != nil {
		for k, v := range g.signature.Headers {
			result[k] = v
		}
	}

	for k, v := range headers {
		result[k] = v
	}

	if g.signature != nil && g.signature.UserAgent != "" {
		result["user-agent"] = g.signature.UserAgent
	}

	return result
}

func (g *HTTPHeaderGenerator) PermuteHeaderOrder(headers map[string]string) []string {
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}

	if !g.randomize || len(keys) <= 1 {
		return keys
	}

	for i := len(keys) - 1; i > 0; i-- {
		j := int64(i+1) * g.seed % int64(i+1)
		keys[i], keys[j] = keys[j], keys[i]
	}

	return keys
}
