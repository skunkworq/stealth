package challenge

import (
	"strings"
)

// ClassifierResultType classifies the type of challenge found in a response.
type ClassifierResultType string

const (
	// CloudflareTurnstile indicates a Cloudflare Turnstile challenge.
	CloudflareTurnstile ClassifierResultType = "cloudflare-turnstile"
	// CloudflareJS indicates a Cloudflare JavaScript challenge.
	CloudflareJS ClassifierResultType = "cloudflare-js"
	// ReCAPTCHAv2 indicates a Google reCAPTCHA v2 challenge.
	ReCAPTCHAv2 ClassifierResultType = "recaptcha-v2"
	// ReCAPTCHAv3 indicates a Google reCAPTCHA v3 challenge.
	ReCAPTCHAv3 ClassifierResultType = "recaptcha-v3"
	// HCaptcha indicates an hCaptcha challenge.
	HCaptcha ClassifierResultType = "hcaptcha"
	// DataDome indicates a DataDome challenge.
	DataDome ClassifierResultType = "datadome"
	// Generic indicates a generic or unknown challenge.
	Generic ClassifierResultType = "generic"
	// None indicates no challenge was detected.
	None ClassifierResultType = "none"
)

// ClassifierResult holds the outcome of challenge classification.
type ClassifierResult struct {
	Type       ClassifierResultType
	Confidence float64
}

// Classifier identifies anti-bot challenges in raw response bodies.
type Classifier struct {
	detector *Detector
}

// NewClassifier creates a new challenge classifier.
func NewClassifier() *Classifier {
	return &Classifier{
		detector: NewDetector(),
	}
}

// Classify analyzes raw response bytes and returns the detected challenge type
// with an estimated confidence score.
func (c *Classifier) Classify(body []byte) *ClassifierResult {
	// The detector expects headers; provide an empty map for body-only analysis.
	ch := c.detector.Detect(body, map[string][]string{})
	if ch == nil {
		return &ClassifierResult{
			Type:       None,
			Confidence: 1.0,
		}
	}

	// Map internal ChallengeType to classifier result type.
	resultType := mapChallengeType(ch.Type)

	// Estimate confidence based on indicator strength.
	confidence := estimateConfidence(body, ch.Type)

	return &ClassifierResult{
		Type:       resultType,
		Confidence: confidence,
	}
}

func mapChallengeType(t ChallengeType) ClassifierResultType {
	switch t {
	case ChallengeCloudflare:
		return CloudflareJS
	case ChallengeTurnstile:
		return CloudflareTurnstile
	case ChallengeRecaptchaV2:
		return ReCAPTCHAv2
	case ChallengeRecaptchaV3:
		return ReCAPTCHAv3
	case ChallengeHCaptcha:
		return HCaptcha
	case ChallengeDataDome:
		return DataDome
	default:
		return Generic
	}
}

func estimateConfidence(body []byte, t ChallengeType) float64 {
	bodyStr := strings.ToLower(string(body))
	var indicators int

	switch t {
	case ChallengeCloudflare:
		indicators = countIndicators(bodyStr, []string{
			"cf-challenge", "challenge-platform", "cloudflare", "captcha",
		})
	case ChallengeTurnstile:
		indicators = countIndicators(bodyStr, []string{
			"cf-turnstile", "turnstile",
		})
	case ChallengeRecaptchaV2, ChallengeRecaptchaV3:
		indicators = countIndicators(bodyStr, []string{
			"g-recaptcha", "recaptcha", "data-sitekey",
		})
	case ChallengeHCaptcha:
		indicators = countIndicators(bodyStr, []string{
			"h-captcha", "hcaptcha", "data-hcaptcha-sitekey",
		})
	case ChallengeDataDome:
		indicators = countIndicators(bodyStr, []string{
			"datadome", "dd-captcha",
		})
	default:
		indicators = countIndicators(bodyStr, []string{
			"access denied", "blocked", "verify you are human", "suspicious activity",
		})
	}

	// Confidence scales with the number of distinct indicators found.
	confidence := 0.5 + float64(indicators)*0.15
	if confidence > 1.0 {
		confidence = 1.0
	}
	return confidence
}

func countIndicators(text string, indicators []string) int {
	count := 0
	for _, ind := range indicators {
		if strings.Contains(text, ind) {
			count++
		}
	}
	return count
}
