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

	// Lazy FSM init — select URL-aware strategies on first request
	if c.evasionFSMEnabled && c.evasionFSM == nil {
		c.evasionFSM = behavior.NewAdaptiveEvasionFSMForURL(url)
		c.logger.Info("evasion FSM initialized with URL-aware strategies", "url", url)
	}

	_ = c.hooks.Execute(ctx, instrumentation.HookNames.OnRequestStart)
	c.fsm.ResetState(instrumentation.RequestStates.Idle)
	_ = c.fsm.Transition(ctx, instrumentation.RequestEvents.Start)

	var resp *engine.Response
	var err error
	var challengeSolved bool

	// Use waterfall engine when available, otherwise raw engine
	activeEngine := c.ActiveEngine()

	// Determine request function: DoOnTab when tabCtx provided, otherwise Do
	var doRequest func(context.Context, *engine.Request) (*engine.Response, error)
	if tabCtx != nil {
		if te, ok := activeEngine.(engine.TabEngine); ok {
			doRequest = func(ctx context.Context, req *engine.Request) (*engine.Response, error) {
				return te.DoOnTab(ctx, tabCtx, req)
			}
		} else {
			return nil, fmt.Errorf("engine %q does not support DoOnTab", activeEngine.Name())
		}
	} else {
		doRequest = activeEngine.Do
	}

	if retryErr := resilience.RetryContext(ctx, &resilience.Config{
		MaxAttempts:       3,
		InitialBackoff:    2 * time.Second,
		MaxBackoff:        8 * time.Second,
		BackoffMultiplier: 2.0,
		Jitter:            0.2,
	}, func(ctx context.Context) error {
		resp, err = doRequest(ctx, &engine.Request{
			URL:     url,
			Timeout: c.options.Timeout,
		})
		if err != nil {
			span.SetAttribute("error", err.Error())
			c.logger.Error("navigation failed", "url", url, "error", err)
			if ctx.Err() != nil {
				return resilience.WithPermanentError(err)
			}
			return err
		}

		// Check for WAF/challenge markers in the response body/headers.
		// The engine now returns raw responses; challenge detection lives here.
		if isWAFResponse(resp) {
			c.logger.Warn("WAF challenge detected in response. Adapting stealth config and retrying",
				"status", resp.Status)

			// FSM State Transition
			_ = c.fsm.Transition(ctx, instrumentation.RequestEvents.Retry)

			// RL-driven stealth adaptation or hardcoded fallback
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

	// EVASION FSM: on ban signal, rotate strategy and retry before escalating
	if c.evasionFSM != nil && resp != nil {
		detected := isBanSignal(c.escalation, resp.Status)
		score := 0.0
		if detected {
			score = 1.0
		}
		c.evasionFSM.RecordResult(score, detected)
		if detected {
			c.evasionFSM.RecordBanSignal(resp.Status)

			// Retry with rotated strategy before escalating to browser mode.
			// Each iteration applies the FSM's current strategy to the engine request
			// so header mutations (Sec-Fetch-*, Accept, method) actually take effect.
			prevStrategy := c.evasionFSM.CurrentStrategy().Name()
			for fsmRetry := 0; fsmRetry < len(c.evasionFSM.Strategies()) && !c.evasionFSM.ShouldEscalate(); fsmRetry++ {
				nextStrategy := c.evasionFSM.CurrentStrategy().Name()
				if fsmRetry > 0 && nextStrategy == prevStrategy {
					break // FSM didn't advance — stop retrying
				}
				prevStrategy = nextStrategy
				c.logger.Info("evasion FSM retry", "strategy", nextStrategy, "attempt", fsmRetry+1)

				resp, err = doRequest(ctx, engineRequestWithStrategy(
					c.evasionFSM.CurrentStrategy(), url, c.options.Timeout,
				))
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
					break // Strategy evaded — stop retrying
				}
			}
		}
		if c.evasionFSM.ShouldEscalate() && c.waterfall != nil {
			reason := c.evasionFSM.EscalationReason()
			tierName := escalationTierFor(c.escalation, resp.Status)
			c.waterfall.PromoteTier(tierName)
			c.logger.Info("evasion FSM escalation", "reason", reason, "promoting", tierName)
		}
	}

	// ANTI-BOT ESCALATION: on ban-signal status codes, escalate and retry
	if resp != nil && c.escalation != nil && c.escalation.Enabled && isBanSignal(c.escalation, resp.Status) {
		for escAttempt := 0; escAttempt < c.escalation.MaxEscalationRetries; escAttempt++ {
			shouldRetry := c.escalate(ctx, resp, url, nil)
			if !shouldRetry {
				break
			}
			c.logger.Info("escalation retry", "attempt", escAttempt+1, "status", resp.Status)

			resp, err = doRequest(ctx, &engine.Request{
				URL:     url,
				Timeout: c.options.Timeout,
			})
			if err != nil || !isBanSignal(c.escalation, resp.Status) {
				break
			}
		}
	}

	// CAPTCHA SOLVING: detect captcha in response, attempt solve with trace replay before escalating
	if c.evasionFSM != nil && resp != nil && c.isCaptchaResponse(resp) {
		c.evasionFSM.RecordCaptchaDetected()
		c.logger.Info("captcha detected in response", "url", url, "status", resp.Status)

		if c.evasionFSM.ShouldAttemptCaptcha() {
			solvedResp, solveErr := c.attemptCaptchaSolve(ctx, url, resp)
			if solveErr == nil && solvedResp != nil {
				c.evasionFSM.RecordCaptchaSolveResult(true)
				resp = solvedResp
				challengeSolved = true
				span.AddEvent("captcha_solved_via_fsm", nil)
				c.logger.Info("captcha solved via FSM", "url", url)
			} else {
				c.evasionFSM.RecordCaptchaSolveResult(false)
				c.logger.Warn("captcha solve failed", "url", url, "error", solveErr)

				// Check if we should escalate to browser after captcha failure
				if c.evasionFSM.ShouldEscalate() && c.waterfall != nil {
					reason := c.evasionFSM.EscalationReason()
					tierName := escalationTierFor(c.escalation, resp.Status)
					c.waterfall.PromoteTier(tierName)
					c.logger.Info("captcha solve exhausted, escalating", "reason", reason, "promoting", tierName)
				}
			}
		} else {
			c.logger.Info("captcha solve exhausted, skipping to orchestrator")
		}
	}

	// CHALLENGE HANDLING: delegate to orchestrator for anything the FSM didn't solve
	if c.orchestrator != nil && c.config.Challenge.AutoSolve && !c.isCleanResponse(resp) {
		_ = c.fsm.Transition(ctx, instrumentation.RequestEvents.ChallengeDetected)
		solvedResp, _ := c.orchestrator.HandleResponse(ctx, url, resp, c.engine, c.options.Timeout)
		if solvedResp != nil {
			resp = solvedResp
			challengeSolved = true
			span.AddEvent("challenge_solved", nil)
		}
	} else if c.config.Challenge.AutoDetect && resp != nil && !c.isCleanResponse(resp) {
		// Fallback to generic challenge detection (no orchestrator)
		detector := challenge.NewDetector()
		if ch := detector.Detect(resp.Body, resp.Headers); ch != nil {
			span.AddEvent("challenge_detected", map[string]interface{}{"type": string(ch.Type)})
			c.logger.Info("challenge detected", "type", ch.Type)
		}
	}

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

	return &Response{
		Response:        *resp,
		ChallengeSolved: challengeSolved,
	}, nil
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
	flatHeaders := make(map[string]string, len(resp.Headers))
	for k, v := range resp.Headers {
		if len(v) > 0 {
			flatHeaders[strings.ToLower(k)] = v[0]
		}
	}
	waf := instrumentation.DetectChallenge(resp.Status, flatHeaders, resp.Body)
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
