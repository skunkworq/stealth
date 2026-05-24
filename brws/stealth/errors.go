package stealth

import "errors"

// Sentinel errors for common stealth failure modes.
// Use errors.Is to check for these in callers.
var (
	// ErrWAFBlocked is returned when a WAF or bot-detection system has blocked
	// the request and all retry/evasion strategies have been exhausted.
	ErrWAFBlocked = errors.New("WAF blocked")

	// ErrCaptchaRequired is returned when the response requires solving a
	// CAPTCHA and no solver is configured or all solve attempts failed.
	ErrCaptchaRequired = errors.New("captcha required")

	// ErrEscalationExhausted is returned when all proxy/engine escalation
	// tiers have been tried and the request is still blocked.
	ErrEscalationExhausted = errors.New("escalation exhausted")
)
