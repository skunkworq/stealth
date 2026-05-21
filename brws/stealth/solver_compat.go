package stealth

import (
	solver "github.com/skunkworq/stealth/brws/stealth/solver"
)

// Re-export Turnstile constants so callers in package stealth still compile.
const (
	CloudflareTurnstileTestSiteKey = solver.CloudflareTurnstileTestSiteKey
	CloudflareTurnstileTestSecret  = solver.CloudflareTurnstileTestSecret
	CloudflareTurnstileDummyToken  = solver.CloudflareTurnstileDummyToken
)

// Type aliases — callers that reference stealth.CaptchaSolver etc. continue to work.
type (
	CaptchaSolver              = solver.CaptchaSolver
	CaptchaResponse            = solver.CaptchaResponse
	SolveResult                = solver.SolveResult
	HumanEventOpts             = solver.HumanEventOpts
	ReCaptchaV2Result          = solver.ReCaptchaV2Result
	ReCaptchaV3Result          = solver.ReCaptchaV3Result
	CloudflareSolverClient     = solver.CloudflareSolverClient
	CloudflareSolveResult      = solver.CloudflareSolveResult
	TurnstileFlowOptions       = solver.TurnstileFlowOptions
	TurnstileInteractionPlan   = solver.TurnstileInteractionPlan
	TurnstileVerifier          = solver.TurnstileVerifier
	LabTurnstileVerifier       = solver.LabTurnstileVerifier
	CloudflareTestModeVerifier = solver.CloudflareTestModeVerifier
	CFInitResp                 = solver.CFInitResp
)

func NewCaptchaSolver() *CaptchaSolver               { return solver.NewCaptchaSolver() }
func NewCloudflareSolverClient() *CloudflareSolverClient { return solver.NewCloudflareSolverClient() }
func TimezoneToOffset(tz string) int                 { return solver.TimezoneToOffset(tz) }

func deriveBaseURL(targetURL string) string { return solver.DeriveBaseURL(targetURL) }
