// Package challenge provides detection and handling of anti-bot challenges
// such as reCAPTCHA, hCaptcha, Cloudflare, and Turnstile.
package challenge

import (
	"strings"

	"github.com/skunkworq/stealth/brws/core/detection"
)

// DetectionReport is the canonical report type from core/detection, re-exported for callers.
type DetectionReport = detection.DetectionReport

// DetectionResult is the per-request detection result from core/detection, re-exported for callers.
type DetectionResult = detection.DetectionResult

// ScreenData is the canonical screen data type from core/detection, re-exported for callers.
type ScreenData = detection.ScreenData

// StealthDetection re-exports the core detection result type.
type StealthDetection = detection.StealthDetection

// StealthDetector re-exports the core detector type.
type StealthDetector = detection.StealthDetector

// AdaptiveScorer re-exports the core adaptive scorer type.
type AdaptiveScorer = detection.AdaptiveScorer

// AdaptiveScorerConfig re-exports the core adaptive scorer config type.
type AdaptiveScorerConfig = detection.AdaptiveScorerConfig

// Analyzer re-exports the core fingerprint analyzer type.
type Analyzer = detection.Analyzer

// CloudflareDetector re-exports the core cloudflare detector type.
type CloudflareDetector = detection.CloudflareDetector

// HTTPFingerprintInfo re-exports the core HTTP fingerprint info type.
type HTTPFingerprintInfo = detection.HTTPFingerprintInfo

// IsomorphicAnalyzer re-exports the core isomorphic analyzer type.
type IsomorphicAnalyzer = detection.IsomorphicAnalyzer

// WebGLData re-exports the core WebGL data type.
type WebGLData = detection.WebGLData

// WebGLAnalyzer re-exports the core WebGL analyzer type.
type WebGLAnalyzer = detection.WebGLAnalyzer

// FontData re-exports the core font data type.
type FontData = detection.FontData

// FontAnalyzer re-exports the core font analyzer type.
type FontAnalyzer = detection.FontAnalyzer

// ScreenAnalyzer re-exports the core screen analyzer type.
type ScreenAnalyzer = detection.ScreenAnalyzer

// PluginData re-exports the core plugin data type.
type PluginData = detection.PluginData

// PluginAnalyzer re-exports the core plugin analyzer type.
type PluginAnalyzer = detection.PluginAnalyzer

// TimingAnalyzer re-exports the core timing analyzer type.
type TimingAnalyzer = detection.TimingAnalyzer

// RequestTimingSequence re-exports the core request timing sequence type.
type RequestTimingSequence = detection.RequestTimingSequence

// AdvancedDetection re-exports the core advanced detection type.
type AdvancedDetection = detection.AdvancedDetection

var NewStealthDetector = detection.NewStealthDetector
var NewAdaptiveScorer = detection.NewAdaptiveScorer
var NewAnalyzer = detection.NewAnalyzer
var NewCloudflareDetector = detection.NewCloudflareDetector
var NewIsomorphicAnalyzer = detection.NewIsomorphicAnalyzer
var NewWebGLAnalyzer = detection.NewWebGLAnalyzer
var NewFontAnalyzer = detection.NewFontAnalyzer
var NewScreenAnalyzer = detection.NewScreenAnalyzer
var NewPluginAnalyzer = detection.NewPluginAnalyzer
var NewTimingAnalyzer = detection.NewTimingAnalyzer
var NewRequestTimingSequenceFromMap = detection.NewRequestTimingSequenceFromMap
var NewAdvancedDetection = detection.NewAdvancedDetection

// ChallengeType represents the type of challenge detected.
//
//nolint:revive // Type name stuttering is intentional for clarity
type ChallengeType string

const (
	// ChallengeRecaptchaV2 represents reCAPTCHA v2 challenge type
	ChallengeRecaptchaV2 ChallengeType = "recaptcha-v2"
	// ChallengeRecaptchaV3 represents reCAPTCHA v3 challenge type
	ChallengeRecaptchaV3 ChallengeType = "recaptcha-v3"

	// ChallengeHCaptcha represents hCaptcha challenge type
	ChallengeHCaptcha ChallengeType = "hcaptcha"

	// ChallengeCloudflare represents Cloudflare challenge type
	ChallengeCloudflare ChallengeType = "cloudflare"
	// ChallengeTurnstile represents Turnstile challenge type
	ChallengeTurnstile ChallengeType = "turnstile"
	// ChallengeChallengeBot represents bot challenge type.
	ChallengeChallengeBot ChallengeType = "challenge-bot"

	// ChallengeDataDome represents a DataDome challenge type
	ChallengeDataDome ChallengeType = "datadome"

	// ChallengeGeneric represents a generic challenge type
	ChallengeGeneric ChallengeType = "generic"
)

// Challenge represents a detected challenge
type Challenge struct {
	Type     ChallengeType
	SiteKey  string
	URL      string
	Response string
}

// Detector detects anti-bot challenges in HTTP responses
type Detector struct{}

// NewDetector creates a new challenge detector
func NewDetector() *Detector {
	return &Detector{}
}

// Detect analyzes response body and headers for challenge indicators
func (d *Detector) Detect(body []byte, headers map[string][]string) *Challenge {
	bodyStr := strings.ToLower(string(body))

	// Check for Cloudflare
	if server := getHeader(headers, "server"); strings.Contains(server, "cloudflare") {
		if strings.Contains(bodyStr, "cf-challenge") ||
			strings.Contains(bodyStr, "challenge-platform") ||
			strings.Contains(bodyStr, "captcha") {
			return &Challenge{
				Type: ChallengeCloudflare,
				URL:  extractURL(bodyStr),
			}
		}

		// Check for Turnstile
		if strings.Contains(bodyStr, "cf-turnstile") ||
			strings.Contains(bodyStr, "turnstile") {
			siteKey := extractSiteKey(bodyStr, "cf-turnstile")
			return &Challenge{
				Type:    ChallengeTurnstile,
				SiteKey: siteKey,
				URL:     extractURL(bodyStr),
			}
		}
	}

	// Check for reCAPTCHA
	if strings.Contains(bodyStr, "g-recaptcha") ||
		strings.Contains(bodyStr, "data-sitekey") {

		siteKey := extractSiteKey(bodyStr, "data-sitekey")

		// Determine v2 vs v3
		if strings.Contains(bodyStr, "g-recaptcha-response") {
			return &Challenge{
				Type:    ChallengeRecaptchaV2,
				SiteKey: siteKey,
				URL:     extractURL(bodyStr),
			}
		}

		return &Challenge{
			Type:    ChallengeRecaptchaV3,
			SiteKey: siteKey,
			URL:     extractURL(bodyStr),
		}
	}

	// Check for hCaptcha
	if strings.Contains(bodyStr, "h-captcha") ||
		strings.Contains(bodyStr, "data-hcaptcha-sitekey") {

		siteKey := extractSiteKey(bodyStr, "data-hcaptcha-sitekey")
		return &Challenge{
			Type:    ChallengeHCaptcha,
			SiteKey: siteKey,
			URL:     extractURL(bodyStr),
		}
	}

	// Check for generic challenge indicators
	challengeIndicators := []string{
		"access denied",
		"blocked",
		"please verify you are human",
		"suspicious activity",
	}

	for _, indicator := range challengeIndicators {
		if strings.Contains(bodyStr, indicator) {
			return &Challenge{
				Type: ChallengeGeneric,
				URL:  extractURL(bodyStr),
			}
		}
	}

	return nil
}

func getHeader(headers map[string][]string, key string) string {
	key = strings.ToLower(key)
	for k, v := range headers {
		if strings.ToLower(k) == key && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// IsBlocked checks if the response indicates a block/challenge
func (d *Detector) IsBlocked(body []byte, statusCode int) bool {
	// Check status code
	if statusCode == 403 || statusCode == 429 || statusCode == 503 {
		return true
	}

	// Check body for block indicators
	bodyStr := strings.ToLower(string(body))
	blockIndicators := []string{
		"blocked",
		"access denied",
		"forbidden",
		"rate limit",
		"too many requests",
		"incapsula",
		"cloudflare",
		"captcha",
		"verify you are human",
		"suspicious activity",
	}

	for _, indicator := range blockIndicators {
		if strings.Contains(bodyStr, indicator) {
			return true
		}
	}

	return false
}

func extractSiteKey(body, _ string) string {
	// Simple extraction - looks for patterns like data-sitekey="xxx"
	patterns := []string{
		"data-sitekey=\"",
		"data-sitekey='",
		"sitekey=\"",
		"sitekey='",
	}

	for _, p := range patterns {
		idx := strings.Index(body, p)
		if idx == -1 {
			continue
		}

		start := idx + len(p)
		end := strings.IndexAny(body[start:], "\"' ")
		if end == -1 {
			end = len(body)
		}

		if end > start {
			return body[start : start+end]
		}
	}

	return ""
}

func extractURL(body string) string {
	// Try to extract URL from various patterns
	patterns := []string{
		"action=\"",
		"action='",
		"url=\"",
		"url='",
	}

	for _, p := range patterns {
		idx := strings.Index(body, p)
		if idx == -1 {
			continue
		}

		start := idx + len(p)
		end := strings.IndexAny(body[start:], "\"' ")
		if end == -1 {
			end = len(body)
		}

		if end > start {
			return body[start : start+end]
		}
	}

	return ""
}
