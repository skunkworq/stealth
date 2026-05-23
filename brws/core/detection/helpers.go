package detection

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/skunkworq/stealth/brws/core/constants"
)

// generateRequestID creates a unique request identifier based on the current timestamp.
func generateRequestID() string {
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}

// hasJSFingerprintHeaders returns true if the request contains at least one
// X-* fingerprint header that proves the client has a JS execution context.
// Used to gate missing-data penalties: if a client sends some JS-sourced
// fingerprint data but omits others (e.g. behavioral, timing), that's suspicious.
// Pure HTTP clients (like curl-impersonate) that send zero X-* headers won't
// trigger these penalties.
func hasJSFingerprintHeaders(req *http.Request) bool {
	jsHeaders := []string{
		constants.HeaderNavigatorData,
		constants.HeaderWebGLData,
		constants.HeaderPluginData,
		constants.HeaderScreenData,
		constants.HeaderFontData,
		constants.HeaderWebRTCData,
	}
	for _, h := range jsHeaders {
		if req.Header.Get(h) != "" {
			return true
		}
	}
	return false
}

// indicatorChecks extracts the Check string from each VectorIndicator.
// Used by all analyzer methods that delegate to a typed analyzer and need to
// map result.Indicators → []string for DetectionVector.Indicators.
func indicatorChecks(inds []VectorIndicator) []string {
	out := make([]string, 0, len(inds))
	for _, ind := range inds {
		out = append(out, ind.Check)
	}
	return out
}

// missingHeaderVector returns a DetectionVector for a JS-context header that
// is absent when other JS-sourced headers are present, proving the client
// has a JS execution context but deliberately omitted this data.
func missingHeaderVector(name, category, indicatorKey string, score, weight float64, description string) *DetectionVector {
	return &DetectionVector{
		Name:        name,
		Category:    category,
		Score:       score,
		Weight:      weight,
		Detected:    true,
		Description: description,
		Indicators:  []string{indicatorKey},
	}
}

func getClientIP(req *http.Request) string {
	// Check for forwarded headers
	if forwarded := req.Header.Get("X-Forwarded-For"); forwarded != "" {
		return strings.Split(forwarded, ",")[0]
	}
	if realIP := req.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}
	// Fall back to remote addr
	if idx := strings.LastIndex(req.RemoteAddr, ":"); idx > 0 {
		return req.RemoteAddr[:idx]
	}
	return req.RemoteAddr
}

func extractPlatform(ua string) string {
	if strings.Contains(ua, "Windows") {
		return "Windows"
	}
	if strings.Contains(ua, "Mac") {
		return "macOS"
	}
	if strings.Contains(ua, "Linux") {
		return "Linux"
	}
	if strings.Contains(ua, "Android") {
		return "Android"
	}
	if strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad") {
		return "iOS"
	}
	return "Unknown"
}

func extractBrowserVersion(ua string) string {
	re := regexp.MustCompile(`Chrome/(\d+)`)
	matches := re.FindStringSubmatch(ua)
	if len(matches) > 1 {
		return matches[1]
	}
	re = regexp.MustCompile(`Firefox/(\d+)`)
	matches = re.FindStringSubmatch(ua)
	if len(matches) > 1 {
		return matches[1]
	}
	re = regexp.MustCompile(`Safari/(\d+)`)
	matches = re.FindStringSubmatch(ua)
	if len(matches) > 1 {
		return matches[1]
	}
	return "Unknown"
}

// advancedChecksToVector converts AdvancedCheckResult slices into a DetectionVector.
func advancedChecksToVector(checks []AdvancedCheckResult, name, category string, weight float64) *DetectionVector {
	if len(checks) == 0 {
		return nil
	}

	vec := &DetectionVector{
		Name:        name,
		Category:    category,
		Weight:      weight,
		Description: fmt.Sprintf("Advanced %s analysis", category),
		Indicators:  make([]string, 0),
	}

	for _, c := range checks {
		if c.Score > 0 {
			vec.Score += c.Score
			vec.Indicators = append(vec.Indicators, fmt.Sprintf("%s: %s", c.CheckName, c.Details))
		}
	}

	// Average across checks to keep in [0,1]
	if len(checks) > 0 {
		vec.Score /= float64(len(checks))
	}
	if vec.Score > 1.0 {
		vec.Score = 1.0
	}

	vec.Detected = vec.Score > 0.3
	return vec
}

// categoryFromString converts a category string back to VectorCategory.
func categoryFromString(s string) VectorCategory {
	switch s {
	case "tls":
		return VectorTLS
	case "http":
		return VectorHTTP
	case "navigator":
		return VectorNavigator
	case "canvas":
		return VectorCanvas
	case "timing":
		return VectorTiming
	case "behavioral":
		return VectorBehavioral
	case "webgl":
		return VectorWebGL
	default:
		return VectorHTTP
	}
}
