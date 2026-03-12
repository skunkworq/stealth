package adversarial

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// CloudflareChallengeType identifies the type of Cloudflare challenge.
type CloudflareChallengeType string

const (
	// ChallengeNone indicates no Cloudflare challenge was detected.
	ChallengeNone CloudflareChallengeType = "none"
	// ChallengeJS indicates a 503 JS evaluation challenge.
	ChallengeJS CloudflareChallengeType = "js_challenge"
	// ChallengeManaged indicates an interactive managed challenge.
	ChallengeManaged CloudflareChallengeType = "managed_challenge"
	// ChallengeTurnstile indicates a Cloudflare Turnstile widget challenge.
	ChallengeTurnstile CloudflareChallengeType = "turnstile"
	// ChallengeBlocked indicates a hard block (403) from Cloudflare.
	ChallengeBlocked CloudflareChallengeType = "blocked"
)

// CloudflareChallenge represents a detected Cloudflare challenge.
type CloudflareChallenge struct {
	Type       CloudflareChallengeType `json:"type"`
	StatusCode int                     `json:"status_code"`
	RayID      string                  `json:"ray_id"`
	SiteKey    string                  `json:"site_key,omitempty"`
	Widget     *TurnstileWidgetConfig  `json:"widget,omitempty"`
	URL        string                  `json:"url"`
	DetectedAt time.Time               `json:"detected_at"`
	PoWParams  *PoWChallenge           `json:"pow_params,omitempty"`
}

// CloudflareSolution represents a solved challenge.
type CloudflareSolution struct {
	ClearanceCookie *http.Cookie       `json:"clearance_cookie,omitempty"`
	TurnstileToken  string             `json:"turnstile_token,omitempty"`
	LabToken        *LabTurnstileToken `json:"lab_turnstile_token,omitempty"`
	WidgetTelemetry *WidgetTelemetry   `json:"widget_telemetry,omitempty"`
	SolvedAt        time.Time          `json:"solved_at"`
	SolveTimeMs     int64              `json:"solve_time_ms"`
	Method          string             `json:"method"`
}

// CloudflareSolver is the interface for solving Cloudflare challenges.
type CloudflareSolver interface {
	SolveChallenge(challenge *CloudflareChallenge) (*CloudflareSolution, error)
}

// turnstileSiteKeyRe extracts the Turnstile sitekey from HTML body content.
var turnstileSiteKeyRe = regexp.MustCompile(`(?:data-sitekey|sitekey)\s*[=:]\s*["']([0-9a-zA-Z_-]+)["']`)

// DetectChallenge inspects an HTTP response's status code, headers, and body
// to determine if Cloudflare is presenting a challenge page.
func DetectChallenge(statusCode int, headers http.Header, body []byte) *CloudflareChallenge {
	if !IsCloudflarePage(headers) {
		return nil
	}

	challenge := &CloudflareChallenge{
		StatusCode: statusCode,
		RayID:      headers.Get("Cf-Ray"),
		DetectedAt: time.Now(),
	}

	bodyStr := string(body)

	// 503 + JS challenge markers
	if statusCode == http.StatusServiceUnavailable {
		if strings.Contains(bodyStr, "jschl_vc") ||
			strings.Contains(bodyStr, "_cf_chl_opt") ||
			strings.Contains(bodyStr, "cf-browser-verification") {
			challenge.Type = ChallengeJS
			challenge.SiteKey = extractTurnstileSiteKey(bodyStr)
			challenge.PoWParams = extractPoWParams(bodyStr)

			// Upgrade to managed if body contains managed challenge class/id markers
			// (not URL paths like "/cdn-cgi/challenge-platform")
			if strings.Contains(bodyStr, `class="managed_challenge"`) ||
				strings.Contains(bodyStr, `"managed_challenge"`) ||
				strings.Contains(bodyStr, "cf-challenge-running") {
				challenge.Type = ChallengeManaged
			}
			return challenge
		}
	}

	// 403 responses require further classification
	if statusCode == http.StatusForbidden {
		// Check for Turnstile widget
		if strings.Contains(bodyStr, "cf-turnstile") ||
			strings.Contains(bodyStr, "challenges.cloudflare.com/turnstile") ||
			strings.Contains(bodyStr, "/turnstile/v0/api.js") {
			challenge.Type = ChallengeTurnstile
			challenge.Widget = ParseTurnstileWidgetConfigFromHTML(bodyStr)
			challenge.SiteKey = extractTurnstileSiteKey(bodyStr)
			return challenge
		}

		// Check for managed challenge
		if strings.Contains(bodyStr, "managed_challenge") ||
			strings.Contains(bodyStr, "challenge-platform") ||
			strings.Contains(bodyStr, "cf-challenge-running") {
			challenge.Type = ChallengeManaged
			challenge.SiteKey = extractTurnstileSiteKey(bodyStr)
			return challenge
		}

		// 403 from Cloudflare with no challenge markers is a hard block
		challenge.Type = ChallengeBlocked
		return challenge
	}

	return nil
}

// extractTurnstileSiteKey attempts to extract a Turnstile sitekey from HTML content.
func extractTurnstileSiteKey(body string) string {
	if widget := ParseTurnstileWidgetConfigFromHTML(body); widget != nil && widget.SiteKey != "" {
		return widget.SiteKey
	}
	matches := turnstileSiteKeyRe.FindStringSubmatch(body)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

// ExtractClearanceCookie searches for the cf_clearance cookie in the response.
func ExtractClearanceCookie(resp *http.Response) *http.Cookie {
	if resp == nil {
		return nil
	}
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "cf_clearance" {
			return cookie
		}
	}
	return nil
}

// IsCloudflarePage checks whether the response headers indicate it originates
// from a Cloudflare-fronted server.
func IsCloudflarePage(headers http.Header) bool {
	server := strings.ToLower(headers.Get("Server"))
	if strings.Contains(server, "cloudflare") {
		return true
	}
	if headers.Get("Cf-Ray") != "" {
		return true
	}
	return false
}

// cfChlOptRe extracts the _cf_chl_opt JSON from the challenge page body.
var cfChlOptRe = regexp.MustCompile(`var\s+_cf_chl_opt\s*=\s*(\{[^;]+\})`)

// extractPoWParams parses PoW parameters from the _cf_chl_opt JSON in the page body.
func extractPoWParams(body string) *PoWChallenge {
	matches := cfChlOptRe.FindStringSubmatch(body)
	if len(matches) < 2 {
		return nil
	}

	var opts struct {
		PoW struct {
			Prefix     string `json:"prefix"`
			Difficulty int    `json:"difficulty"`
			Algorithm  string `json:"algorithm"`
		} `json:"pow"`
	}

	if err := json.Unmarshal([]byte(matches[1]), &opts); err != nil {
		return nil
	}

	if opts.PoW.Prefix == "" {
		return nil
	}

	return &PoWChallenge{
		Prefix:     opts.PoW.Prefix,
		Difficulty: opts.PoW.Difficulty,
		Algorithm:  opts.PoW.Algorithm,
	}
}

// String formats the CloudflareChallenge for logging.
func (c *CloudflareChallenge) String() string {
	if c == nil {
		return "CloudflareChallenge{none}"
	}
	siteKeyInfo := ""
	if c.SiteKey != "" {
		siteKeyInfo = fmt.Sprintf(" sitekey=%s", c.SiteKey)
	}
	return fmt.Sprintf("CloudflareChallenge{type=%s status=%d ray=%s%s url=%s detected=%s}",
		c.Type, c.StatusCode, c.RayID, siteKeyInfo, c.URL, c.DetectedAt.Format(time.RFC3339))
}
