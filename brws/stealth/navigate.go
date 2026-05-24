package stealth

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/skunkworq/stealth/brws/browser/engine"
	"github.com/skunkworq/stealth/brws/core/instrumentation"
	"github.com/skunkworq/stealth/brws/core/resilience"
	"github.com/skunkworq/stealth/brws/stealth/behavior"
	"github.com/skunkworq/stealth/brws/stealth/challenge"
	challengefsm "github.com/skunkworq/stealth/brws/stealth/challenge/fsm"
	"github.com/skunkworq/stealth/brws/stealth/solver"
)

// Navigate performs a GET request to the specified URL.
//
// Concurrency: Navigate is not safe to call concurrently from multiple
// goroutines on the same Adaptive instance without external synchronization.
// The evasionFSM is lazily initialized on the first call and mutated by
// subsequent calls; sharing an Adaptive across goroutines requires the caller
// to serialize Navigate calls (e.g., via a mutex or a single-goroutine owner).
func (c *Adaptive) Navigate(ctx context.Context, url string) (*Response, error) {
	return c.navigate(ctx, url, nil)
}

// NavigateOnTab performs a GET request on an existing browser tab.
// The stealth engine runs its setup (scripts, headers, permissions) directly
// on the provided tabCtx, then navigates it. This eliminates the wasteful
// double-navigation pattern when the stealth client and agent share a tab.
func (c *Adaptive) NavigateOnTab(ctx context.Context, tabCtx context.Context, url string) (*Response, error) {
	return c.navigate(ctx, url, tabCtx)
}

// navigate is the shared implementation for Navigate and NavigateOnTab.
// When tabCtx is nil, it uses engine.Do() (creates a temp tab).
// When tabCtx is non-nil, it uses engine.DoOnTab() (operates on existing tab).
func (c *Adaptive) navigate(ctx context.Context, url string, tabCtx context.Context) (*Response, error) {
	ctx, span := c.tracer.StartSpan(ctx, "navigate", instrumentation.SpanKindRequest)

	span.SetAttribute("url", url)
	defer span.End()

	c.logger.Info("navigating", "url", url)

	// Lazy FSM init — select URL-aware strategies on first request.
	// Guarded by fsmMu so concurrent Navigate calls don't race on the nil check.
	c.fsmMu.Lock()
	if c.evasionFSMEnabled && c.evasionFSM == nil {
		c.evasionFSM = behavior.NewAdaptiveEvasionFSMForURL(url)
		c.logger.Info("evasion FSM initialized with URL-aware strategies", "url", url)
	}
	c.fsmMu.Unlock()

	_ = c.hooks.Execute(ctx, instrumentation.HookNames.OnRequestStart)
	c.fsm.ResetState(instrumentation.RequestStates.Idle)
	_ = c.fsm.Transition(ctx, instrumentation.RequestEvents.Start)

	var challengeSolved bool

	// Use waterfall engine when available, otherwise raw engine
	activeEngine := c.ActiveEngine()

	// Determine request function: DoOnTab when tabCtx provided, otherwise Do
	var doRequest requestFunc
	if tabCtx != nil {
		te, ok := activeEngine.(engine.TabEngine)
		if !ok {
			return nil, fmt.Errorf("engine %q does not support DoOnTab", activeEngine.Name())
		}
		doRequest = func(ctx context.Context, req *engine.Request) (*engine.Response, error) {
			return te.DoOnTab(ctx, tabCtx, req)
		}
	} else {
		doRequest = activeEngine.Do
	}

	resp, err := c.retryForWAF(ctx, url, doRequest)
	resp, err = c.retryForEvasion(ctx, url, doRequest, resp, err)
	resp, err = c.escalateAndRetry(ctx, url, doRequest, resp, err)

	resp, challengeSolved = c.handleChallenges(ctx, url, span, resp, challengeSolved)

	if resp == nil {
		if err != nil {
			return nil, fmt.Errorf("navigation failed: %w", err)
		}
		return nil, fmt.Errorf("navigation failed: no response received")
	}

	span.SetAttribute("status", resp.Status)
	span.SetAttribute("body_size", len(resp.Body))
	_ = c.fsm.Transition(ctx, instrumentation.RequestEvents.Complete)
	_ = c.hooks.Execute(ctx, instrumentation.HookNames.OnRequestEnd)

	c.logger.Info("navigation complete", "url", url, "status", resp.Status, "size", len(resp.Body))

	stealthResp := &Response{Response: *resp, ChallengeSolved: challengeSolved}

	// Wrap sentinel errors so callers can use errors.Is rather than status checks.
	// Only fire when a solver/FSM was active (i.e., a solve was attempted); if no
	// solver is configured the captcha response passes through unmodified.
	if c.evasionFSM != nil && c.isCaptchaResponse(resp) && !challengeSolved {
		return stealthResp, fmt.Errorf("%w (status %d)", ErrCaptchaRequired, resp.Status)
	}
	if c.escalation != nil && c.escalation.Enabled && isBanSignal(c.escalation, resp.Status) {
		if c.evasionFSM != nil && c.evasionFSM.ShouldEscalate() {
			return stealthResp, fmt.Errorf("%w (status %d)", ErrEscalationExhausted, resp.Status)
		}
		return stealthResp, fmt.Errorf("%w (status %d)", ErrWAFBlocked, resp.Status)
	}

	return stealthResp, nil
}

// requestFunc is the function signature for making an engine request.
type requestFunc = func(context.Context, *engine.Request) (*engine.Response, error)

// retryForWAF performs the initial WAF-aware fetch with up to 3 backoff retries.
// On each WAF detection it adapts the stealth config before retrying.
func (c *Adaptive) retryForWAF(ctx context.Context, url string, doRequest requestFunc) (*engine.Response, error) {
	var resp *engine.Response
	var err error
	if retryErr := resilience.RetryContext(ctx, &resilience.Config{
		MaxAttempts:       3,
		InitialBackoff:    2 * time.Second,
		MaxBackoff:        8 * time.Second,
		BackoffMultiplier: 2.0,
		Jitter:            0.2,
	}, func(ctx context.Context) error {
		resp, err = doRequest(ctx, &engine.Request{URL: url, Timeout: c.options.Timeout})
		if err != nil {
			c.logger.Error("navigation failed", "url", url, "error", err)
			if ctx.Err() != nil {
				return resilience.WithPermanentError(err)
			}
			return err
		}
		if isWAFResponse(resp) {
			c.logger.Warn("WAF challenge detected, adapting and retrying", "status", resp.Status)
			_ = c.fsm.Transition(ctx, instrumentation.RequestEvents.Retry)
			if c.policyLoader != nil && c.config.Stealth != nil {
				var captchaState *CaptchaState
				if c.isCaptchaResponse(resp) {
					captchaState = &CaptchaState{Presented: true}
				}
				stateVec := BuildStateVector(extractAnomaliesFromResponse(resp), captchaState, nil)
				actionIdx, qValue := c.policyLoader.SelectAction(stateVec)
				applied, field := ApplyAction(c.config.Stealth, actionIdx)
				c.logger.Info("RL policy action", "action", field, "q_value", qValue, "applied", applied)
			} else if c.config.Stealth != nil {
				c.config.Stealth.ToggleFeature("CanvasNoise")
				c.config.Stealth.ToggleFeature("WebGLSpoof")
				c.config.Stealth.ToggleFeature("ClientHints")
			}
			return fmt.Errorf("WAF challenge detected (status %d)", resp.Status)
		}
		return nil
	}); retryErr != nil && err == nil {
		err = retryErr
	}
	return resp, err
}

// retryForEvasion runs the evasion FSM rotation loop after an initial ban signal.
// It rotates strategies and retries until the ban clears or escalation is warranted.
func (c *Adaptive) retryForEvasion(ctx context.Context, url string, doRequest requestFunc, resp *engine.Response, err error) (*engine.Response, error) {
	if c.evasionFSM == nil || resp == nil {
		return resp, err
	}
	detected := isBanSignal(c.escalation, resp.Status)
	score := 0.0
	if detected {
		score = 1.0
	}
	c.evasionFSM.RecordResult(score, detected)
	if detected {
		c.evasionFSM.RecordBanSignal(resp.Status)
		prevStrategy := c.evasionFSM.CurrentStrategy().Name()
		for fsmRetry := 0; fsmRetry < len(c.evasionFSM.Strategies()) && !c.evasionFSM.ShouldEscalate(); fsmRetry++ {
			nextStrategy := c.evasionFSM.CurrentStrategy().Name()
			if fsmRetry > 0 && nextStrategy == prevStrategy {
				break
			}
			prevStrategy = nextStrategy
			c.logger.Info("evasion FSM retry", "strategy", nextStrategy, "attempt", fsmRetry+1)
			resp, err = doRequest(ctx, engineRequestWithStrategy(c.evasionFSM.CurrentStrategy(), url, c.options.Timeout))
			if err != nil {
				break
			}
			retryDetected := isBanSignal(c.escalation, resp.Status)
			retryScore := 0.0
			if retryDetected {
				retryScore = 1.0
			}
			c.evasionFSM.RecordResult(retryScore, retryDetected)
			if retryDetected {
				c.evasionFSM.RecordBanSignal(resp.Status)
			} else {
				break
			}
		}
	}
	if c.evasionFSM.ShouldEscalate() && c.waterfall != nil {
		reason := c.evasionFSM.EscalationReason()
		tierName := escalationTierFor(c.escalation, resp.Status)
		c.waterfall.PromoteTier(tierName)
		c.logger.Info("evasion FSM escalation", "reason", reason, "promoting", tierName)
	}
	return resp, err
}

// escalateAndRetry promotes the proxy/engine tier and re-fetches on persistent ban signals.
func (c *Adaptive) escalateAndRetry(ctx context.Context, url string, doRequest requestFunc, resp *engine.Response, err error) (*engine.Response, error) {
	if resp == nil || c.escalation == nil || !c.escalation.Enabled || !isBanSignal(c.escalation, resp.Status) {
		return resp, err
	}
	for escAttempt := 0; escAttempt < c.escalation.MaxEscalationRetries; escAttempt++ {
		if !c.escalate(ctx, resp, url, nil) {
			break
		}
		c.logger.Info("escalation retry", "attempt", escAttempt+1, "status", resp.Status)
		resp, err = doRequest(ctx, &engine.Request{URL: url, Timeout: c.options.Timeout})
		if err != nil || !isBanSignal(c.escalation, resp.Status) {
			break
		}
	}
	return resp, err
}

// handleChallenges runs the CAPTCHA FSM and orchestrator challenge-handling
// pipeline after the initial fetch+retry loop. It returns the (possibly
// updated) response and whether a challenge was solved.
func (c *Adaptive) handleChallenges(ctx context.Context, url string, span *instrumentation.Span, resp *engine.Response, challengeSolved bool) (*engine.Response, bool) {
	if c.evasionFSM != nil && resp != nil && c.isCaptchaResponse(resp) {
		c.logger.Info("captcha detected in response", "url", url, "status", resp.Status)
		var solvedResp *engine.Response
		solved, shouldEscalate := c.evasionFSM.ProcessCaptcha(func() bool {
			var err error
			solvedResp, err = c.attemptCaptchaSolve(ctx, url, resp)
			if err != nil {
				c.logger.Warn("captcha solve failed", "url", url, "error", err)
			}
			return err == nil && solvedResp != nil
		})
		if solved {
			resp = solvedResp
			challengeSolved = true
			span.AddEvent("captcha_solved_via_fsm", nil)
			c.logger.Info("captcha solved via FSM", "url", url)
		} else if shouldEscalate && c.waterfall != nil {
			reason := c.evasionFSM.EscalationReason()
			tierName := escalationTierFor(c.escalation, resp.Status)
			c.waterfall.PromoteTier(tierName)
			c.logger.Info("captcha solve exhausted, escalating", "reason", reason, "promoting", tierName)
		}
	}

	if c.orchestrator != nil && c.config.Challenge.AutoSolve && !c.isCleanResponse(resp) {
		_ = c.fsm.Transition(ctx, instrumentation.RequestEvents.ChallengeDetected)
		solvedResp, _ := c.orchestrator.HandleResponse(ctx, url, resp, c.engine, c.options.Timeout)
		if solvedResp != nil {
			resp = solvedResp
			challengeSolved = true
			span.AddEvent("challenge_solved", nil)
		}
	}

	return resp, challengeSolved
}

// NavigateWithReferrer performs a navigation with an explicit referrer.
// When the underlying engine is a Chromium StealthEngine with StealthPlus
// enabled, this sets both the HTTP Referer header and document.referrer.
func (c *Adaptive) NavigateWithReferrer(ctx context.Context, url string, referrer string) (*Response, error) {
	c.logger.Info("navigating with referrer", "url", url, "referrer", referrer)

	activeEngine := c.ActiveEngine()
	resp, err := activeEngine.Do(ctx, &engine.Request{
		URL:      url,
		Referrer: referrer,
		Timeout:  c.options.Timeout,
	})
	if err != nil {
		return nil, err
	}

	return &Response{Response: *resp}, nil
}

// NavigateWithSearchProfile navigates to url using a pre-built search engine
// referrer profile.  Supported profiles: "google", "bing", "duckduckgo", "random".
// When the engine implements ProfileNavigator, the full referrer profile is
// applied via the engine; otherwise the referrer is passed as a header.
func (c *Adaptive) NavigateWithSearchProfile(ctx context.Context, url string, profile string) (*Response, error) {
	c.logger.Info("navigating with search profile", "url", url, "profile", profile)

	// Extract domain for profile construction
	domain := url
	if idx := strings.Index(domain, "://"); idx != -1 {
		domain = domain[idx+3:]
	}
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}

	var referrer string
	switch strings.ToLower(profile) {
	case "google":
		referrer = buildGoogleReferrer(domain)
	case "bing":
		referrer = buildBingReferrer(domain)
	case "duckduckgo", "ddg":
		referrer = buildDuckDuckGoReferrer(domain)
	case "random":
		referrer = pickRandomSearchReferrer(domain)
	default:
		return nil, fmt.Errorf("unknown search profile: %s (use google, bing, duckduckgo, random)", profile)
	}

	return c.NavigateWithReferrer(ctx, url, referrer)
}

// isCaptchaResponse returns true if the response contains a captcha/challenge.
func (c *Adaptive) isCaptchaResponse(resp *engine.Response) bool {
	if resp == nil {
		return false
	}
	// Use orchestrator's unified detector if available
	if c.orchestrator != nil {
		ud := challengefsm.NewUnifiedDetector()
		if ch := ud.Detect(resp); ch != nil {
			return true
		}
	}
	// Fallback: check headers and body
	return challengefsm.HasCaptchaHeader(resp.Headers)
}

// isCleanResponse returns true if the response doesn't contain a challenge.
func (c *Adaptive) isCleanResponse(resp *engine.Response) bool {
	if resp == nil {
		return false
	}
	return resp.Status >= 200 && resp.Status < 400 && !c.isCaptchaResponse(resp)
}

// isWAFResponse returns true if the response contains WAF/challenge markers.
// This replaces the engine-level WAF detection that was removed from
// stealth_engine.go; challenge detection now lives entirely in the client.
func isWAFResponse(resp *engine.Response) bool {
	if resp == nil {
		return false
	}
	waf := instrumentation.DetectChallenge(resp.Status, engine.FlattenHeadersLower(resp.Headers), resp.Body)
	return waf != instrumentation.WAFUnknown
}

// attemptCaptchaSolve tries to solve a detected captcha, using trace-replayed
// events when available, falling back to synthetic event generation.
func (c *Adaptive) attemptCaptchaSolve(ctx context.Context, targetURL string, resp *engine.Response) (*engine.Response, error) {
	if c.orchestrator == nil {
		return nil, fmt.Errorf("no challenge orchestrator configured")
	}

	// Generate trace-based events if trace library has recordings
	var traceEvents []challenge.CaptchaEvent
	if c.traceLibrary != nil && c.traceLibrary.Count() > 0 {
		rng := rand.New(rand.NewSource(time.Now().UnixNano()))
		// Try to find a matching trace for the challenge type
		ud := challengefsm.NewUnifiedDetector()
		if ch := ud.Detect(resp); ch != nil {
			challengeType := string(ch.Type)
			events, err := c.traceLibrary.GenerateFromTrace(challengeType, "", rng.Float64)
			if err == nil {
				traceEvents = events
				c.logger.Info("using trace-replayed events for captcha solve",
					"type", challengeType, "events", len(traceEvents))
			}
		}
	}

	// Use orchestrator with trace events injected
	solvedResp, err := c.orchestrator.HandleResponseWithTraceEvents(
		ctx, targetURL, resp, c.engine, c.options.Timeout, traceEvents,
	)
	if err != nil {
		return nil, err
	}
	if solvedResp != nil && solvedResp != resp {
		return solvedResp, nil
	}
	return nil, fmt.Errorf("captcha solve did not produce a clean response")
}

// detectCFChallenge checks if the response is a Cloudflare challenge page.
func (c *Adaptive) detectCFChallenge(resp *engine.Response) *challenge.CloudflareChallenge {
	httpHeaders := make(http.Header)
	for k, vals := range resp.Headers {
		for _, v := range vals {
			httpHeaders.Add(k, v)
		}
	}
	return challenge.DetectChallenge(resp.Status, httpHeaders, resp.Body)
}

// solveCFChallenge attempts to solve a detected CF challenge and retry the request.
func (c *Adaptive) solveCFChallenge(ctx context.Context, targetURL string, resp *engine.Response, ch *challenge.CloudflareChallenge) (*engine.Response, error) {
	switch ch.Type {
	case challenge.ChallengeJS, challenge.ChallengeManaged:
		// Extract PoW params from the challenge page body
		if ch.PoWParams == nil {
			return nil, fmt.Errorf("no PoW params in challenge page")
		}

		// Solve the PoW
		solution, err := c.cfSolver.SolvePoW(ch.PoWParams.Prefix, ch.PoWParams.Difficulty)
		if err != nil {
			return nil, fmt.Errorf("PoW solve failed: %w", err)
		}

		// For managed challenges, also generate fingerprint + behavioral events
		var fp *challenge.FingerprintPayload
		var events []challenge.CaptchaEvent
		if ch.Type == challenge.ChallengeManaged {
			fp = c.cfSolver.GenerateFingerprint()
			events = c.cfSolver.EventGen().GenerateHumanEvents(5000)
		}

		// Human-like delay before submitting
		//nolint:gosec
		time.Sleep(time.Duration(1500+rand.Intn(3000)) * time.Millisecond)

		// Submit solution to the challenge API endpoint
		baseURL := solver.DeriveBaseURL(targetURL)
		clearanceCookie, err := c.cfSolver.SubmitSolution(baseURL, ch, solution, fp, events)
		if err != nil {
			return nil, err
		}

		// Retry the original request with the clearance cookie
		retryReq := &engine.Request{
			URL:     targetURL,
			Timeout: c.options.Timeout,
			ExtraHeaders: map[string]string{
				"Cookie": fmt.Sprintf("cf_clearance=%s", clearanceCookie.Value),
			},
		}
		return c.engine.Do(ctx, retryReq)

	case challenge.ChallengeBlocked:
		return nil, fmt.Errorf("hard blocked by Cloudflare (403, no challenge to solve)")

	default:
		return nil, fmt.Errorf("unsupported CF challenge type: %s", ch.Type)
	}
}

// ============================================================================
// Search profile referrer builders (engine-agnostic)
// ============================================================================

func buildGoogleReferrer(domain string) string {
	queries := []string{
		fmt.Sprintf("https://www.google.com/search?q=%s&source=hp&ei=abc", domain),
		fmt.Sprintf("https://www.google.com/search?q=%s+reviews&oq=%s+reviews", domain, domain),
		fmt.Sprintf("https://www.google.com/search?q=site%%3A%s", domain),
		fmt.Sprintf("https://www.google.com/search?q=%s+login&source=lmns", domain),
	}
	return queries[rand.Intn(len(queries))]
}

func buildBingReferrer(domain string) string {
	queries := []string{
		fmt.Sprintf("https://www.bing.com/search?q=%s&form=QBLH", domain),
		fmt.Sprintf("https://www.bing.com/search?q=%s+official&qs=n", domain),
		fmt.Sprintf("https://www.bing.com/search?q=site%%3A%s&form=QBRE", domain),
	}
	return queries[rand.Intn(len(queries))]
}

func buildDuckDuckGoReferrer(domain string) string {
	queries := []string{
		fmt.Sprintf("https://duckduckgo.com/?q=%s&ia=web", domain),
		fmt.Sprintf("https://duckduckgo.com/?q=%s+reviews&ia=web", domain),
		fmt.Sprintf("https://duckduckgo.com/?q=site%%3A%s&ia=web", domain),
	}
	return queries[rand.Intn(len(queries))]
}

func pickRandomSearchReferrer(domain string) string {
	builders := []func(string) string{
		buildGoogleReferrer,
		buildBingReferrer,
		buildDuckDuckGoReferrer,
	}
	return builders[rand.Intn(len(builders))](domain)
}

// engineRequestWithStrategy applies an evasion strategy's header/method/body mutations
// to an engine.Request. Strategies operate on *http.Request; this bridges the gap by
// running Apply on a synthetic request and extracting the results into ExtraHeaders.
// For browser engines (Chromium) these headers may be overridden by the engine itself;
// for the native HTTP engine they are injected verbatim.
func engineRequestWithStrategy(strategy behavior.EvasionStrategy, url string, timeout time.Duration) *engine.Request {
	synthetic, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return &engine.Request{URL: url, Timeout: timeout}
	}

	strategy.Apply(synthetic, nil, url)

	req := &engine.Request{
		URL:          url,
		Timeout:      timeout,
		Method:       synthetic.Method,
		ExtraHeaders: make(map[string]string, len(synthetic.Header)),
	}
	for k, vs := range synthetic.Header {
		if len(vs) > 0 {
			req.ExtraHeaders[k] = vs[0]
		}
	}
	if synthetic.Body != nil {
		if body, readErr := io.ReadAll(synthetic.Body); readErr == nil {
			req.Body = body
		}
	}
	return req
}
