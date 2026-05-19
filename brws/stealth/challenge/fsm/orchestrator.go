package fsm

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/skunkworq/stealth/brws/stealth/challenge"
	"github.com/skunkworq/stealth/brws/browser/engine"
	"github.com/skunkworq/stealth/brws/core/instrumentation"
)

// ChallengeOrchestrator is the top-level coordinator for challenge detection and
// solving. It chains a UnifiedDetector with a SolverRegistry to handle any
// challenge type through a single entry point.
type ChallengeOrchestrator struct {
	registry *SolverRegistry
	detector *UnifiedDetector
	metrics  *SolveMetrics
	config   *SolverConfig
	logger   *instrumentation.Logger
}

// NewChallengeOrchestrator creates a new orchestrator.
func NewChallengeOrchestrator(
	registry *SolverRegistry,
	config *SolverConfig,
	logger *instrumentation.Logger,
) *ChallengeOrchestrator {
	return &ChallengeOrchestrator{
		registry: registry,
		detector: NewUnifiedDetector(),
		metrics:  NewSolveMetrics(),
		config:   config,
		logger:   logger,
	}
}

// HandleResponse is the single entry point for challenge handling.
// It detects challenges, finds a solver, drives it, records metrics,
// and returns the solved response (or the original if no challenge found).
func (co *ChallengeOrchestrator) HandleResponse(
	ctx context.Context,
	targetURL string,
	resp *engine.Response,
	eng engine.Engine,
	timeout time.Duration,
) (*engine.Response, error) {
	// Unified detection
	ch := co.detector.Detect(resp)
	if ch == nil {
		return resp, nil
	}

	co.logger.Info("challenge detected by orchestrator",
		"type", string(ch.Type),
		"url", targetURL,
	)

	// Find solver
	solver := co.registry.FindSolver(ch)
	if solver == nil {
		co.logger.Warn("no solver registered for challenge type",
			"type", string(ch.Type),
		)
		return resp, nil
	}

	// Build context
	cfg := co.config
	if cfg == nil {
		cfg = DefaultSolverConfig()
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = timeout
	}

	cctx := &ChallengeContext{
		Ctx:       ctx,
		TargetURL: targetURL,
		Response:  resp,
		Challenge: ch,
		Engine:    eng,
		Config:    cfg,
		Logger:    co.logger,
	}

	// Drive solver
	start := time.Now()
	result, err := solver.Solve(cctx)
	duration := time.Since(start)

	// Record metrics
	success := err == nil && result != nil && result.Solved
	co.metrics.Record(solver.Provider(), success, duration)

	if err != nil {
		co.logger.Warn("challenge solve failed",
			"provider", solver.Provider(),
			"type", string(ch.Type),
			"duration_ms", duration.Milliseconds(),
			"error", err,
		)
		return resp, nil
	}

	if result.Solved {
		co.logger.Info("challenge solved",
			"provider", solver.Provider(),
			"type", string(ch.Type),
			"duration_ms", duration.Milliseconds(),
		)
		if result.Response != nil {
			return result.Response, nil
		}
	}

	return resp, nil
}

// HandleResponseWithTraceEvents is like HandleResponse but injects pre-generated
// trace events into the challenge context for replay-based solving.
func (co *ChallengeOrchestrator) HandleResponseWithTraceEvents(
	ctx context.Context,
	targetURL string,
	resp *engine.Response,
	eng engine.Engine,
	timeout time.Duration,
	traceEvents []challenge.CaptchaEvent,
) (*engine.Response, error) {
	ch := co.detector.Detect(resp)
	if ch == nil {
		return resp, nil
	}

	co.logger.Info("challenge detected (trace-enhanced)",
		"type", string(ch.Type),
		"url", targetURL,
		"trace_events", len(traceEvents),
	)

	solver := co.registry.FindSolver(ch)
	if solver == nil {
		co.logger.Warn("no solver for challenge type", "type", string(ch.Type))
		return resp, nil
	}

	cfg := co.config
	if cfg == nil {
		cfg = DefaultSolverConfig()
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = timeout
	}

	cctx := &ChallengeContext{
		Ctx:         ctx,
		TargetURL:   targetURL,
		Response:    resp,
		Challenge:   ch,
		Engine:      eng,
		Config:      cfg,
		Logger:      co.logger,
		TraceEvents: traceEvents,
	}

	start := time.Now()
	result, err := solver.Solve(cctx)
	duration := time.Since(start)

	success := err == nil && result != nil && result.Solved
	co.metrics.Record(solver.Provider(), success, duration)

	if err != nil {
		co.logger.Warn("trace-enhanced solve failed",
			"provider", solver.Provider(), "duration_ms", duration.Milliseconds(), "error", err)
		return resp, err
	}

	if result.Solved {
		co.logger.Info("challenge solved (trace-enhanced)",
			"provider", solver.Provider(), "duration_ms", duration.Milliseconds())
		if result.Response != nil {
			return result.Response, nil
		}
	}

	return resp, nil
}

// Metrics returns the solve metrics tracker.
func (co *ChallengeOrchestrator) Metrics() *SolveMetrics {
	return co.metrics
}

// Registry returns the solver registry.
func (co *ChallengeOrchestrator) Registry() *SolverRegistry {
	return co.registry
}

// UnifiedDetector chains multiple detection strategies in priority order:
// DataDome headers → Cloudflare detection → generic CAPTCHA detection.
type UnifiedDetector struct {
	challengeDetector *challenge.Detector
}

// NewUnifiedDetector creates a new unified detector.
func NewUnifiedDetector() *UnifiedDetector {
	return &UnifiedDetector{
		challengeDetector: challenge.NewDetector(),
	}
}

// Detect inspects a response and returns the detected challenge, or nil.
// Detection priority: DataDome → Cloudflare → generic CAPTCHA.
func (ud *UnifiedDetector) Detect(resp *engine.Response) *challenge.Challenge {
	if resp == nil {
		return nil
	}

	// 1. DataDome detection (headers + body markers)
	if DetectDataDome(resp.Headers, resp.Body) {
		return &challenge.Challenge{
			Type: challenge.ChallengeDataDome,
			URL:  resp.FinalURL,
		}
	}

	// 2. Cloudflare detection (via challenge.DetectChallenge)
	httpHeaders := make(http.Header)
	for k, vals := range resp.Headers {
		for _, v := range vals {
			httpHeaders.Add(k, v)
		}
	}
	cfChallenge := challenge.DetectChallenge(resp.Status, httpHeaders, resp.Body)
	if cfChallenge != nil {
		challengeType := cfChallengeTypeToGeneric(cfChallenge.Type)
		return &challenge.Challenge{
			Type:    challengeType,
			SiteKey: cfChallenge.SiteKey,
			URL:     cfChallenge.URL,
		}
	}

	// 3. Check for captcha headers (X-Captcha-Required)
	if HasCaptchaHeader(resp.Headers) {
		bodyStr := strings.ToLower(string(resp.Body))
		if strings.Contains(bodyStr, "recaptcha") || hasCaptchaTypeHeader(resp.Headers, "recaptcha-v2") {
			return &challenge.Challenge{
				Type: challenge.ChallengeRecaptchaV2,
				URL:  resp.FinalURL,
			}
		}
		return &challenge.Challenge{
			Type: challenge.ChallengeGeneric,
			URL:  resp.FinalURL,
		}
	}

	// 4. Generic challenge detection (body + headers analysis)
	return ud.challengeDetector.Detect(resp.Body, resp.Headers)
}

// cfChallengeTypeToGeneric maps adversarial CF challenge types to generic challenge types.
func cfChallengeTypeToGeneric(cfType challenge.CloudflareChallengeType) challenge.ChallengeType {
	switch cfType {
	case challenge.ChallengeJS, challenge.ChallengeManaged:
		return challenge.ChallengeCloudflare
	case challenge.ChallengeTurnstile:
		return challenge.ChallengeTurnstile
	case challenge.ChallengeBlocked:
		return challenge.ChallengeCloudflare
	default:
		return challenge.ChallengeCloudflare
	}
}

// HasCaptchaHeader checks for X-Captcha-Required: 1 header.
func HasCaptchaHeader(headers map[string][]string) bool {
	for _, v := range headers["X-Captcha-Required"] {
		if v == "1" {
			return true
		}
	}
	return false
}

// hasCaptchaTypeHeader checks for a specific X-Captcha-Type value.
func hasCaptchaTypeHeader(headers map[string][]string, captchaType string) bool {
	for _, v := range headers["X-Captcha-Type"] {
		if v == captchaType {
			return true
		}
	}
	return false
}
