package detection

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// CloudflareDetector analyzes signals that Cloudflare uses for bot detection.
type CloudflareDetector struct{}

// CloudflareSignal represents a detected Cloudflare-specific signal.
type CloudflareSignal struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"` // "low", "medium", "high"
	Score       float64 `json:"score"`    // 0.0 - 1.0
}

// NewCloudflareDetector creates a new CloudflareDetector instance.
func NewCloudflareDetector() *CloudflareDetector {
	return &CloudflareDetector{}
}

// AnalyzeRequest inspects an outgoing HTTP request for signals that Cloudflare
// would use to classify the client as a bot.
func (d *CloudflareDetector) AnalyzeRequest(req *http.Request) []CloudflareSignal {
	var signals []CloudflareSignal

	// Check for cf_clearance cookie age -- a solve time under 2 seconds is suspicious
	signals = append(signals, d.checkClearanceAge(req)...)

	// Check for rapid solve indicator in custom header
	signals = append(signals, d.checkRapidSolve(req)...)

	// Check for missing Cloudflare cookies
	signals = append(signals, d.checkMissingCFCookies(req)...)

	// Check for suspicious TLS indicators via proxy headers
	signals = append(signals, d.checkSuspiciousTLS(req)...)

	// Check for header ordering anomalies
	signals = append(signals, d.checkHeaderOrder(req)...)

	return signals
}

// checkClearanceAge detects whether the cf_clearance cookie was set too recently,
// which may indicate automated challenge solving.
func (d *CloudflareDetector) checkClearanceAge(req *http.Request) []CloudflareSignal {
	var signals []CloudflareSignal

	cookie, err := req.Cookie("cf_clearance")
	if err != nil || cookie == nil {
		return signals
	}

	// If the cookie has an expiry set and it was created very recently (< 2s ago),
	// this is a signal of automated solving.
	if !cookie.Expires.IsZero() {
		// cf_clearance typically has a long expiry; we estimate creation time.
		// Standard Cloudflare clearance cookies last ~30 minutes.
		estimatedCreation := cookie.Expires.Add(-30 * time.Minute)
		age := time.Since(estimatedCreation)
		if age < 2*time.Second && age >= 0 {
			signals = append(signals, CloudflareSignal{
				Name:        "cf_clearance_age",
				Description: "cf_clearance cookie age is suspiciously young (< 2s), indicating automated solve",
				Severity:    "high",
				Score:       0.7,
			})
		}
	}

	return signals
}

// checkRapidSolve detects whether the challenge was solved in under 500ms,
// which is faster than humanly possible for interactive challenges.
func (d *CloudflareDetector) checkRapidSolve(req *http.Request) []CloudflareSignal {
	var signals []CloudflareSignal

	// Look for solve timing in a custom header (used by solver integration)
	solveTime := req.Header.Get("X-Cf-Solve-Time-Ms")
	if solveTime != "" {
		var ms int64
		if _, err := fmt.Sscanf(solveTime, "%d", &ms); err == nil && ms < 500 {
			signals = append(signals, CloudflareSignal{
				Name:        "rapid_solve",
				Description: "Challenge solved in under 500ms, indicating automated solver",
				Severity:    "high",
				Score:       0.8,
			})
		}
	}

	return signals
}

// checkMissingCFCookies flags requests that are missing expected Cloudflare
// bot management cookies.
func (d *CloudflareDetector) checkMissingCFCookies(req *http.Request) []CloudflareSignal {
	var signals []CloudflareSignal

	hasCFBM := false
	hasClearance := false

	for _, cookie := range req.Cookies() {
		switch cookie.Name {
		case "__cf_bm":
			hasCFBM = true
		case "cf_clearance":
			hasClearance = true
		}
	}

	if !hasCFBM && !hasClearance {
		signals = append(signals, CloudflareSignal{
			Name:        "missing_cf_cookies",
			Description: "No __cf_bm or cf_clearance cookies present; first visit or cookie-stripped bot",
			Severity:    "medium",
			Score:       0.4,
		})
	}

	return signals
}

// checkSuspiciousTLS examines headers for indicators of TLS interception or proxy
// usage that Cloudflare can detect through its bot management system.
func (d *CloudflareDetector) checkSuspiciousTLS(req *http.Request) []CloudflareSignal {
	var signals []CloudflareSignal

	// Check for proxy indicators
	proxyHeaders := []string{
		"X-Forwarded-For",
		"X-Real-Ip",
		"Via",
		"Forwarded",
	}

	proxyCount := 0
	for _, h := range proxyHeaders {
		if req.Header.Get(h) != "" {
			proxyCount++
		}
	}

	if proxyCount >= 2 {
		signals = append(signals, CloudflareSignal{
			Name:        "suspicious_tls",
			Description: "Multiple proxy headers detected, suggesting TLS termination proxy or MITM",
			Severity:    "medium",
			Score:       0.5,
		})
	}

	// Check for TLS version mismatch indicators
	// Some proxy tools expose their TLS version in headers
	tlsVersion := req.Header.Get("X-Tls-Version")
	if tlsVersion != "" && !strings.Contains(tlsVersion, "1.3") && !strings.Contains(tlsVersion, "1.2") {
		signals = append(signals, CloudflareSignal{
			Name:        "suspicious_tls",
			Description: "Non-standard TLS version detected via proxy header",
			Severity:    "high",
			Score:       0.6,
		})
	}

	return signals
}

// checkHeaderOrder verifies whether the request headers follow the typical
// ordering pattern of real browsers. Bots often send headers in alphabetical
// or non-standard order.
func (d *CloudflareDetector) checkHeaderOrder(req *http.Request) []CloudflareSignal {
	var signals []CloudflareSignal

	// Check for missing Accept-Language (real browsers always send it)
	if req.Header.Get("Accept-Language") == "" {
		signals = append(signals, CloudflareSignal{
			Name:        "header_order",
			Description: "Missing Accept-Language header, unusual for real browsers",
			Severity:    "medium",
			Score:       0.4,
		})
	}

	// Check for missing Accept header
	if req.Header.Get("Accept") == "" {
		signals = append(signals, CloudflareSignal{
			Name:        "header_order",
			Description: "Missing Accept header, unusual for real browsers",
			Severity:    "medium",
			Score:       0.3,
		})
	}

	// Check for suspicious header patterns: bot libraries often include
	// Connection: keep-alive explicitly while browsers leave it implicit in HTTP/2
	connection := req.Header.Get("Connection")
	if connection != "" && req.ProtoMajor >= 2 {
		signals = append(signals, CloudflareSignal{
			Name:        "header_order",
			Description: "Explicit Connection header in HTTP/2 request, typical of bot libraries",
			Severity:    "low",
			Score:       0.3,
		})
	}

	return signals
}

// AnalyzeResponse inspects an HTTP response for Cloudflare-specific signals
// that indicate the bot management system is actively engaging with the client.
func (d *CloudflareDetector) AnalyzeResponse(resp *http.Response) []CloudflareSignal {
	var signals []CloudflareSignal

	if resp == nil {
		return signals
	}

	// Detect rate limiting from Cloudflare
	if resp.StatusCode == http.StatusTooManyRequests {
		server := strings.ToLower(resp.Header.Get("Server"))
		if strings.Contains(server, "cloudflare") || resp.Header.Get("Cf-Ray") != "" {
			signals = append(signals, CloudflareSignal{
				Name:        "rate_limited",
				Description: "Received 429 Too Many Requests from Cloudflare, indicating rate limiting",
				Severity:    "high",
				Score:       0.8,
			})
		}
	}

	// Detect challenge loop: if the response contains a challenge page when
	// we already have a cf-ray, this may indicate repeated challenge issuance
	currentRay := resp.Header.Get("Cf-Ray")
	if currentRay != "" {
		// Check for challenge in response after we already solved one
		if resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusForbidden {
			server := strings.ToLower(resp.Header.Get("Server"))
			if strings.Contains(server, "cloudflare") {
				signals = append(signals, CloudflareSignal{
					Name:        "challenge_loop",
					Description: "Challenge response received, possible challenge loop or session invalidation",
					Severity:    "high",
					Score:       0.7,
				})
			}
		}
	}

	// Detect captcha escalation: 403 after a 503 JS challenge suggests
	// Cloudflare is escalating from JS challenge to managed/interactive challenge
	if resp.StatusCode == http.StatusForbidden {
		server := strings.ToLower(resp.Header.Get("Server"))
		if strings.Contains(server, "cloudflare") {
			// Check for escalation markers
			retryAfter := resp.Header.Get("Retry-After")
			if retryAfter != "" {
				signals = append(signals, CloudflareSignal{
					Name:        "captcha_escalation",
					Description: "Cloudflare returned 403 with Retry-After, suggesting challenge escalation",
					Severity:    "high",
					Score:       0.9,
				})
			}
		}
	}

	return signals
}

// ScoreRequest aggregates all request signals into a single 0.0-1.0 bot
// probability score. A higher score indicates higher likelihood of being
// identified as a bot by Cloudflare.
func (d *CloudflareDetector) ScoreRequest(req *http.Request) float64 {
	signals := d.AnalyzeRequest(req)
	if len(signals) == 0 {
		return 0.0
	}

	// Use weighted combination: take the maximum single signal score and
	// add a fraction of remaining signals to account for compounding evidence.
	var maxScore float64
	var totalScore float64

	for _, s := range signals {
		totalScore += s.Score
		if s.Score > maxScore {
			maxScore = s.Score
		}
	}

	// Composite score: max signal contributes 60%, average of rest contributes 40%
	remainingCount := float64(len(signals) - 1)
	remainingTotal := totalScore - maxScore

	score := maxScore * 0.6
	if remainingCount > 0 {
		score += (remainingTotal / remainingCount) * 0.4
	}

	return minFloat(1.0, score)
}
