package stealth

import (
	"strings"

	"github.com/skunkworq/stealth/brws/browser/engine"
	"github.com/skunkworq/stealth/brws/ml"
)

// BuildStateVector constructs an 18-dimensional vector from detection indicators,
// matching the layout in datagen.ToFeatureVector and the Python training scripts.
//
// Indices 0-10:  Detection vectors (binary flags from anomaly strings)
// Indices 11-13: CAPTCHA state (presented, solved, difficulty)
// Indices 14-17: Behavioral metrics (velocity, typing, straightness, solve_time)
func BuildStateVector(anomalies []string, captcha *CaptchaState, behavioral *BehavioralState) []float64 {
	vec := make([]float64, 18)

	// Parse anomaly strings into detection dimensions
	for _, a := range anomalies {
		aLower := strings.ToLower(a)
		if strings.Contains(aLower, "webdriver") {
			vec[0] = 1.0
		}
		if strings.Contains(aLower, "canvas") || strings.Contains(aLower, "webgl") {
			vec[1] = 1.0
		}
		if strings.Contains(aLower, "client_hints") || strings.Contains(aLower, "inconsistent_ch") {
			vec[2] = 1.0
		}
		if strings.Contains(aLower, "mismatch") && !strings.Contains(aLower, "timezone") {
			vec[3] = 1.0
		}
		if strings.Contains(aLower, "hardware") || strings.Contains(aLower, "memory") {
			vec[4] = 1.0
		}
		if strings.Contains(aLower, "network") {
			vec[5] = 1.0
		}
		if strings.Contains(aLower, "plugins") {
			vec[6] = 1.0
		}
		if strings.Contains(aLower, "geometry") {
			vec[7] = 1.0
		}
		if strings.Contains(aLower, "video") {
			vec[8] = 1.0
		}
		if strings.Contains(aLower, "permissions") {
			vec[9] = 1.0
		}
		if strings.Contains(aLower, "timezone") {
			vec[10] = 1.0
		}
	}

	// CAPTCHA dimensions [11-13]
	if captcha != nil {
		if captcha.Presented {
			vec[11] = 1.0
		}
		if captcha.Solved {
			vec[12] = 1.0
		}
		vec[13] = captcha.Difficulty
	}

	// Behavioral dimensions [14-17]
	if behavioral != nil {
		vec[14] = Clamp(behavioral.MouseVelocity/2000.0, 0, 1)
		vec[15] = Clamp(behavioral.TypingSpeed/500.0, 0, 1)
		vec[16] = behavioral.Straightness
		if behavioral.SolveTimeMs > 0 {
			vec[17] = Clamp(float64(behavioral.SolveTimeMs)/30000.0, 0, 1)
		}
	}

	return vec
}

// CaptchaState holds CAPTCHA-related state for building the state vector.
type CaptchaState struct {
	Presented  bool
	Solved     bool
	Difficulty float64
}

// BehavioralState holds behavioral metrics for building the state vector.
type BehavioralState struct {
	MouseVelocity float64
	TypingSpeed   float64
	Straightness  float64
	SolveTimeMs   int64
}

// ApplyAction maps a DQN action index (0-17) to a StealthConfig mutation.
// Actions 0-11 toggle boolean fields on StealthConfig via ToggleFeature.
// Actions 12-17 are behavioral/challenge flags consumed by other subsystems.
// Returns whether the action was applied and the field name.
func ApplyAction(cfg engine.StealthConfig, actionIndex int) (applied bool, fieldName string) {
	name, ok := ml.ActionMap[actionIndex]
	if !ok {
		return false, "unknown"
	}

	if actionIndex >= 12 {
		// CaptchaSolver, HumanizeInteraction, DelayedNavigation,
		// WebRTCDisable, CanvasNoiseStrength, HeadlessPatches
		// These are signaling actions consumed by challenge/behavior subsystems.
		return true, name
	}

	if cfg == nil {
		return false, name
	}

	applied, _ = cfg.ToggleFeature(name)
	return applied, name
}

// WithPolicy is a functional option to load a trained DQN model for RL-driven
// stealth config adaptation during navigation.
func WithPolicy(modelPath string) Option {
	return func(c *Config) {
		c.PolicyModelPath = modelPath
	}
}

// ExtractAnomalies parses WAF/detection error strings into anomaly indicators.
func ExtractAnomalies(err error) []string {
	if err == nil {
		return nil
	}
	msg := err.Error()
	anomalies := make([]string, 0)

	checks := map[string]string{
		"webdriver":    "webdriver_exposed",
		"canvas":       "canvas_detected",
		"client_hints": "client_hints_issues",
		"WAF":          "waf_challenge",
		"blocked":      "blocked",
		"captcha":      "captcha_challenge",
	}

	for keyword, anomaly := range checks {
		if strings.Contains(strings.ToLower(msg), strings.ToLower(keyword)) {
			anomalies = append(anomalies, anomaly)
		}
	}

	return anomalies
}

// extractAnomaliesFromResponse parses a response for WAF/challenge markers
// and returns anomaly indicators for RL state vectors.
func extractAnomaliesFromResponse(resp *engine.Response) []string {
	if resp == nil {
		return nil
	}
	anomalies := make([]string, 0)

	// Check status codes
	if resp.Status == 403 || resp.Status == 503 {
		anomalies = append(anomalies, "waf_challenge")
	}

	// Check headers for WAF markers
	for k, vals := range resp.Headers {
		kl := strings.ToLower(k)
		for _, v := range vals {
			vl := strings.ToLower(v)
			switch {
			case strings.Contains(kl, "cf-ray"):
				anomalies = append(anomalies, "waf_challenge")
			case strings.Contains(kl, "x-datadome"):
				anomalies = append(anomalies, "waf_challenge")
			case strings.Contains(vl, "cloudflare"):
				anomalies = append(anomalies, "waf_challenge")
			}
		}
	}

	// Check body for challenge markers
	body := strings.ToLower(string(resp.Body))
	checks := map[string]string{
		"cf-browser-verification": "waf_challenge",
		"datadome.js":             "waf_challenge",
		"_Incapsula_Resource":     "waf_challenge",
		"visid_incap":             "waf_challenge",
		"captcha":                 "captcha_challenge",
		"access denied":           "blocked",
	}
	for marker, anomaly := range checks {
		if strings.Contains(body, marker) {
			anomalies = append(anomalies, anomaly)
		}
	}

	return anomalies
}

func Clamp(v, min, max float64) float64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
