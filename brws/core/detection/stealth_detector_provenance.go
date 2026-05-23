package detection

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func isSameOriginTelemetryFetch(req *http.Request) bool {
	if req == nil {
		return false
	}

	mode := req.Header.Get("Sec-Fetch-Mode")
	return req.Header.Get("Sec-Fetch-Dest") == "empty" &&
		(mode == "cors" || mode == "same-origin") &&
		req.Header.Get("Sec-Fetch-Site") == "same-origin"
}

func isNoneContextTelemetryFetch(req *http.Request) bool {
	if req == nil {
		return false
	}

	mode := req.Header.Get("Sec-Fetch-Mode")
	return req.Header.Get("Sec-Fetch-Dest") == "empty" &&
		(mode == "cors" || mode == "same-origin") &&
		req.Header.Get("Sec-Fetch-Site") == "none"
}

func isNoCORSTelemetryFetch(req *http.Request) bool {
	if req == nil {
		return false
	}

	return req.Header.Get("Sec-Fetch-Dest") == "empty" &&
		req.Header.Get("Sec-Fetch-Mode") == "no-cors"
}

func isDocumentNavigation(req *http.Request) bool {
	if req == nil {
		return false
	}

	return req.Header.Get("Sec-Fetch-Dest") == "document" &&
		req.Header.Get("Sec-Fetch-Mode") == "navigate"
}

func isDocumentNavigationSubmission(req *http.Request) bool {
	if req == nil {
		return false
	}

	return req.Method == http.MethodPost &&
		isDocumentNavigation(req) &&
		req.Header.Get("Sec-Fetch-User") == "?1"
}

func isSameSiteTelemetryFetch(req *http.Request) bool {
	if req == nil {
		return false
	}

	mode := req.Header.Get("Sec-Fetch-Mode")
	return req.Header.Get("Sec-Fetch-Dest") == "empty" &&
		(mode == "cors" || mode == "same-origin") &&
		req.Header.Get("Sec-Fetch-Site") == "same-site"
}

func isCrossSiteTelemetryFetch(req *http.Request) bool {
	if req == nil {
		return false
	}

	mode := req.Header.Get("Sec-Fetch-Mode")
	return req.Header.Get("Sec-Fetch-Dest") == "empty" &&
		(mode == "cors" || mode == "same-origin") &&
		req.Header.Get("Sec-Fetch-Site") == "cross-site"
}

func isRefererSameAsRequestURL(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}

	referer := req.Referer()
	if referer == "" {
		return false
	}

	refURL, err := url.Parse(referer)
	if err != nil {
		return false
	}

	return urlsEqualSansFragment(refURL, req.URL)
}

func isOriginSameAsRequestURL(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}

	origin := req.Header.Get("Origin")
	if origin == "" {
		return false
	}

	originURL, err := url.Parse(origin)
	if err != nil {
		return false
	}

	return strings.EqualFold(originURL.Scheme, req.URL.Scheme) &&
		strings.EqualFold(originURL.Host, req.URL.Host)
}

// isSiblingSubdomainOrigin returns true when the Origin header shares the same
// base domain as the request URL but is NOT the same host (i.e., it's a
// sibling or child subdomain). Synthetic beacons often construct sibling
// origins like "app.example.com" when targeting "api.example.com".
func isSiblingSubdomainOrigin(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}
	origin := req.Header.Get("Origin")
	if origin == "" {
		return false
	}
	originURL, err := url.Parse(origin)
	if err != nil {
		return false
	}
	originHost := strings.ToLower(strings.Split(originURL.Host, ":")[0])
	reqHost := strings.ToLower(strings.Split(req.URL.Host, ":")[0])
	if originHost == reqHost {
		return false // same host, not sibling
	}
	// Check shared base domain (last two labels).
	originParts := strings.Split(originHost, ".")
	reqParts := strings.Split(reqHost, ".")
	if len(originParts) < 2 || len(reqParts) < 2 {
		return false
	}
	originBase := originParts[len(originParts)-2] + "." + originParts[len(originParts)-1]
	reqBase := reqParts[len(reqParts)-2] + "." + reqParts[len(reqParts)-1]
	return originBase == reqBase
}

func isNoCORSSafelistedContentType(contentType string) bool {
	baseContentType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if baseContentType == "" {
		return true
	}

	switch baseContentType {
	case "application/x-www-form-urlencoded", "multipart/form-data", "text/plain":
		return true
	default:
		return false
	}
}

func urlsEqualSansFragment(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}

	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Host, b.Host) &&
		strings.TrimRight(a.EscapedPath(), "/") == strings.TrimRight(b.EscapedPath(), "/") &&
		a.RawQuery == b.RawQuery
}

func snapshotRequestBody(req *http.Request) ([]byte, error) {
	if req == nil || req.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	return body, nil
}

func normalizedURLPath(u *url.URL) string {
	if u == nil {
		return ""
	}
	if u.Path != "" {
		return strings.ToLower(u.Path)
	}
	return "/"
}

func normalizedURLHost(u *url.URL) string {
	if u == nil {
		return ""
	}

	return strings.ToLower(strings.Split(u.Host, ":")[0])
}

func looksLikeTelemetryEndpointPath(u *url.URL) bool {
	path := normalizedURLPath(u)
	if path == "" {
		return false
	}

	telemetryMarkers := []string{
		"/api/telemetry",
		"/api/ml/",
		"/collect",
		"/beacon",
		"/metrics",
		"/track",
		"/events",
		"/trap",
	}

	for _, marker := range telemetryMarkers {
		if strings.Contains(path, marker) {
			return true
		}
	}

	return false
}

func looksLikeAPIHostname(u *url.URL) bool {
	host := normalizedURLHost(u)
	if host == "" {
		return false
	}

	prefixes := []string{
		"api.",
		"metrics.",
		"telemetry.",
		"events.",
		"collect.",
		"track.",
		"beacon.",
	}

	for _, prefix := range prefixes {
		if strings.HasPrefix(host, prefix) {
			return true
		}
	}

	return false
}

// looksLikeEncodedPayload checks whether a query string contains base64 or
// percent-encoded blobs that suggest fingerprint data smuggling. It looks for:
//   - Long base64-like runs (>64 chars of [A-Za-z0-9+/=])
//   - Dense percent-encoding (>30% of characters are %XX sequences)
func looksLikeEncodedPayload(query string) bool {
	// Check for base64-like runs: contiguous [A-Za-z0-9+/=] longer than 64 chars
	run := 0
	for _, c := range query {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' {
			run++
			if run > 64 {
				return true
			}
		} else {
			run = 0
		}
	}

	// Check for dense percent-encoding
	pctCount := strings.Count(query, "%")
	if len(query) > 32 && float64(pctCount*3)/float64(len(query)) > 0.30 {
		return true
	}

	return false
}

func ghostHeadersInDeclaredOrder(req *http.Request, candidates []string) []string {
	if req == nil {
		return nil
	}

	declared := declaredHeaderOrder(req)
	if len(declared) == 0 {
		return nil
	}

	ghosts := make([]string, 0)
	for _, candidate := range candidates {
		lowerCandidate := strings.ToLower(candidate)
		declaredPresent := false
		for _, header := range declared {
			if strings.TrimSpace(header) == lowerCandidate {
				declaredPresent = true
				break
			}
		}
		if declaredPresent && req.Header.Get(candidate) == "" {
			ghosts = append(ghosts, lowerCandidate)
		}
	}

	return ghosts
}

func declaredHeaderOrder(req *http.Request) []string {
	if req == nil {
		return nil
	}

	order := req.Header.Get("X-Stealth-Header-Order")
	if order == "" {
		return nil
	}

	parts := strings.Split(strings.ToLower(order), ",")
	normalized := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		normalized = append(normalized, trimmed)
	}

	return normalized
}

func headerOrderIndex(order []string, header string) int {
	lowerHeader := strings.ToLower(header)
	for i, current := range order {
		if current == lowerHeader {
			return i
		}
	}

	return -1
}

// bodyContainsRuntimePayload checks whether the body contains genuine browser
// runtime data, not just superficial keyword references. For JSON bodies, it
// requires runtime keywords to appear as standalone JSON object keys (e.g.
// "navigator": {...}) rather than as prefixes in compound measurement labels
// (e.g. "navigator_entropy": {"value": 5.23}). This prevents keyword-stuffing
// attacks where a synthetic beacon includes runtime words without actual data.
func bodyContainsRuntimePayload(body string) bool {
	if body == "" {
		return false
	}

	runtimeKeywords := []string{
		"navigator", "webgl", "canvas", "timing", "behavior", "audio",
		"webrtc", "plugins", "screen", "fonts",
	}

	// Try JSON-aware check first: parse the body and look for runtime keywords
	// as exact JSON keys at any level of the object hierarchy.
	body = strings.TrimSpace(body)
	if len(body) > 0 && body[0] == '{' {
		var parsed map[string]json.RawMessage
		if json.Unmarshal([]byte(body), &parsed) == nil {
			if jsonContainsRuntimeKeys(parsed, runtimeKeywords, 0) {
				return true
			}
			// If we successfully parsed JSON but found no standalone runtime
			// keys, the body is keyword-stuffing — return false.
			return false
		}
	}

	// Non-JSON body: fall back to substring matching.
	lower := strings.ToLower(body)
	for _, keyword := range runtimeKeywords {
		if strings.Contains(lower, keyword) {
			return true
		}
	}

	return false
}

// jsonContainsRuntimeKeys recursively searches a JSON object for keys that
// exactly match runtime keywords. Compound keys like "navigator_entropy" do
// NOT match "navigator" — only exact key matches count.
func jsonContainsRuntimeKeys(obj map[string]json.RawMessage, keywords []string, depth int) bool {
	if depth > 3 {
		return false // limit recursion
	}
	for key, val := range obj {
		lowerKey := strings.ToLower(key)
		for _, kw := range keywords {
			if lowerKey == kw {
				return true
			}
		}
		// Recurse into nested objects
		var nested map[string]json.RawMessage
		if json.Unmarshal(val, &nested) == nil {
			if jsonContainsRuntimeKeys(nested, keywords, depth+1) {
				return true
			}
		}
	}
	return false
}
