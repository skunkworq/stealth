package instrumentation

import (
	"strings"
)

// WAFShield represents the detected Web Application Firewall type
type WAFShield string

const (
	WAFCloudflare WAFShield = "cloudflare"
	WAFDataDome   WAFShield = "datadome"
	WAFImperva    WAFShield = "imperva"
	WAFAkamai     WAFShield = "akamai"
	WAFUnknown    WAFShield = ""
)

// DetectChallenge evaluates HTTP headers and body payload to identify anti-bot vendor shields
func DetectChallenge(statusCode int, headers map[string]string, body []byte) WAFShield {
	// 1. Cloudflare Detection
	// Typically returns 403 or 503 during challenge, exposing `cf-ray` and specific server headers
	if headers["cf-ray"] != "" || headers["server"] == "cloudflare" {
		if statusCode == 403 || statusCode == 503 || containsBytes(body, []byte("cf-browser-verification")) {
			return WAFCloudflare
		}
	}

	// 2. DataDome Detection
	// Usually returns 403 or 401 with `x-datadome` headers or injected tracking scripts
	if headers["x-datadome"] != "" || headers["x-datadome-clientid"] != "" {
		return WAFDataDome
	}
	if containsBytes(body, []byte("datadome.js")) || containsBytes(body, []byte("x-datadome-clientid")) {
		return WAFDataDome
	}

	// 3. Imperva (Incapsula) Detection
	// Injects `visid_incap` or returns an explicit Incapsula block page
	if strings.Contains(headers["X-CDN"], "Incapsula") {
		return WAFImperva
	}
	if containsBytes(body, []byte("_Incapsula_Resource")) || containsBytes(body, []byte("visid_incap")) {
		return WAFImperva
	}

	// 4. Akamai Bot Manager
	// Sets very long `_abck` or `bm_sz` challenge cookies
	if containsCookies(headers, "_abck") || containsCookies(headers, "bm_sz") {
		return WAFAkamai
	}

	// Generic Block signatures
	if statusCode == 403 {
		if containsBytes(body, []byte("Access Denied")) || containsBytes(body, []byte("captcha")) {
			// Unclassified generic bot challenge
			return WAFUnknown
		}
	}

	return WAFUnknown
}

// containsBytes strictly searches for a byte sequence without converting massive payloads to strings
func containsBytes(body, search []byte) bool {
	if len(body) == 0 || len(search) == 0 {
		return false
	}

	// Convert slice to string for standard lib contains (fast enough for typical block pages)
	return strings.Contains(string(body), string(search))
}

func containsCookies(headers map[string]string, target string) bool {
	// Check `set-cookie` if captured exactly, or iterating generally
	for key, value := range headers {
		if strings.ToLower(key) == "set-cookie" && strings.Contains(value, target) {
			return true
		}
		// If proxies roll them into flat Cookies
		if strings.ToLower(key) == "cookie" && strings.Contains(value, target) {
			return true
		}
	}
	return false
}
