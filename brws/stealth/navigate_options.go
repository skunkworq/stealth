package stealth

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
	"github.com/skunkworq/stealth/brws/challenge"
	"github.com/skunkworq/stealth/brws/engine"
	"github.com/skunkworq/stealth/brws/instrumentation"
	"github.com/skunkworq/stealth/brws/stealth/challengefsm"
)

// NavigateOptions configures advanced navigation behaviour. It exposes the
// underlying engine.Request wait/script knobs without forcing callers to
// reach into the engine package directly.
type NavigateOptions struct {
	// WaitForSelector waits for the given CSS selector to be visible before
	// capturing HTML. Honoured by JS-capable engines (chromium).
	WaitForSelector string
	// WaitForLoad waits for document.readyState == complete (i.e. body ready)
	// before capturing HTML. Default behaviour of Navigate already implies
	// this on chromium; set explicitly for clarity.
	WaitForLoad bool
	// AdditionalSleep sleeps after the wait condition and before capturing
	// HTML. Use this for SPAs that hydrate after onload.
	AdditionalSleep time.Duration
	// ScriptToExecute is optional JS to run before capture.
	ScriptToExecute string
	// Cookies are installed into the browser cookie jar before the
	// navigation request fires. Honoured by JS-capable engines (chromium).
	// Useful for replaying a previously-captured session (e.g. after a
	// human solved a captcha in a one-off manual harvest).
	Cookies []engine.HTTPCookie
}

// NavigateWithOptions is like Navigate but exposes the underlying engine
// request options (wait-for-selector, additional sleep, etc.). It mirrors
// Navigate's retry / captcha / escalation flow.
func (c *Client) NavigateWithOptions(ctx context.Context, url string, opts NavigateOptions) (*Response, error) {
	ctx, span := c.tracer.StartSpan(ctx, "navigate", instrumentation.SpanKindRequest)

	span.SetAttribute("url", url)
	defer span.End()

	c.logger.Info("navigating with options", "url", url,
		"wait_selector", opts.WaitForSelector,
		"wait_load", opts.WaitForLoad,
		"additional_sleep", opts.AdditionalSleep.String())

	if c.evasionFSMEnabled && c.evasionFSM == nil {
		c.evasionFSM = behavior.NewAdaptiveEvasionFSMForURL(url)
		c.logger.Info("evasion FSM initialized with URL-aware strategies", "url", url)
	}

	_ = c.hooks.Execute(ctx, instrumentation.HookNames.OnRequestStart)
	c.fsm.ResetState(instrumentation.RequestStates.Idle)
	_ = c.fsm.Transition(ctx, instrumentation.RequestEvents.Start)

	buildReq := func() *engine.Request {
		return &engine.Request{
			URL:               url,
			Timeout:           c.options.Timeout,
			WaitForNavigation: opts.WaitForLoad,
			WaitForSelector:   opts.WaitForSelector,
			AdditionalSleep:   opts.AdditionalSleep,
			ScriptToExecute:   opts.ScriptToExecute,
			Cookies:           opts.Cookies,
		}
	}

	var resp *engine.Response
	var err error
	maxRetries := 3

	activeEngine := c.activeEngine()

	for attempt := 1; attempt <= maxRetries; attempt++ {
		resp, err = activeEngine.Do(ctx, buildReq())
		if err != nil {
			if strings.Contains(err.Error(), "WAF Challenge Detected") && attempt < maxRetries {
				c.logger.Warn("WAF Blocked. Adapting Stealth Config and Retrying", "attempt", attempt, "error", err)
				_ = c.fsm.Transition(ctx, instrumentation.RequestEvents.Retry)
				if c.policyLoader != nil {
					stateVec := BuildStateVector(extractAnomalies(err), nil, nil)
					actionIdx, qValue := c.policyLoader.SelectAction(stateVec)
					applied, field := ApplyAction(c.config.Stealth, actionIdx)
					c.logger.Info("RL policy action", "action", field, "q_value", qValue, "applied", applied)
				} else {
					c.config.Stealth.CanvasNoise = true
					c.config.Stealth.WebGLSpoof = true
					c.config.Stealth.ClientHints = true
				}
				time.Sleep(time.Duration(500+attempt*1500) * time.Millisecond)
				continue
			}

			span.SetAttribute("error", err.Error())
			c.logger.Error("navigation failed", "url", url, "error", err)
			return nil, err
		}
		break
	}

	if c.evasionFSM != nil && resp != nil {
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
				resp, err = activeEngine.Do(ctx, buildReq())
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
			c.waterfall.PromoteTier("chromium")
			c.logger.Info("evasion FSM escalation", "reason", reason, "promoting", "chromium")
		}
	}

	if resp != nil && c.escalation != nil && c.escalation.Enabled && isBanSignal(c.escalation, resp.Status) {
		for escAttempt := 0; escAttempt < c.escalation.MaxEscalationRetries; escAttempt++ {
			shouldRetry := c.escalate(ctx, resp, url, nil)
			if !shouldRetry {
				break
			}
			c.logger.Info("escalation retry", "attempt", escAttempt+1, "status", resp.Status)
			resp, err = c.activeEngine().Do(ctx, buildReq())
			if err != nil || !isBanSignal(c.escalation, resp.Status) {
				break
			}
		}
	}

	if c.evasionFSM != nil && resp != nil && c.isCaptchaResponse(resp) {
		c.evasionFSM.RecordCaptchaDetected()
		c.logger.Info("captcha detected in response", "url", url, "status", resp.Status)
		if c.evasionFSM.ShouldAttemptCaptcha() {
			solvedResp, solveErr := c.attemptCaptchaSolveOpts(ctx, url, resp)
			if solveErr == nil && solvedResp != nil {
				c.evasionFSM.RecordCaptchaSolveResult(true)
				resp = solvedResp
				span.AddEvent("captcha_solved_via_fsm", nil)
			} else {
				c.evasionFSM.RecordCaptchaSolveResult(false)
				c.logger.Warn("captcha solve failed", "url", url, "error", solveErr)
				if c.evasionFSM.ShouldEscalate() && c.waterfall != nil {
					reason := c.evasionFSM.EscalationReason()
					c.waterfall.PromoteTier("chromium")
					c.logger.Info("captcha solve exhausted, escalating", "reason", reason)
				}
			}
		}
	}

	if c.orchestrator != nil && c.config.Challenge.AutoSolve && !c.isCleanResponse(resp) {
		_ = c.fsm.Transition(ctx, instrumentation.RequestEvents.ChallengeDetected)
		solvedResp, _ := c.orchestrator.HandleResponse(ctx, url, resp, c.engine, c.options.Timeout)
		if solvedResp != nil {
			resp = solvedResp
			span.AddEvent("challenge_solved", nil)
		}
	} else if c.config.Challenge.AutoDetect && !c.isCleanResponse(resp) {
		detector := challenge.NewDetector()
		if ch := detector.Detect(resp.Body, resp.Headers); ch != nil {
			span.AddEvent("challenge_detected", map[string]interface{}{"type": string(ch.Type)})
			c.logger.Info("challenge detected", "type", ch.Type)
		}
	}

	span.SetAttribute("status", resp.Status)
	span.SetAttribute("body_size", len(resp.Body))
	_ = c.fsm.Transition(ctx, instrumentation.RequestEvents.Complete)
	_ = c.hooks.Execute(ctx, instrumentation.HookNames.OnRequestEnd)

	c.logger.Info("navigation complete", "url", url, "status", resp.Status, "size", len(resp.Body))

	return &Response{
		Status:   resp.Status,
		Headers:  resp.Headers,
		Body:     resp.Body,
		FinalURL: resp.FinalURL,
		Trace:    resp.Trace,
	}, nil
}

// attemptCaptchaSolveOpts mirrors attemptCaptchaSolve but is package-private
// to keep the original Navigate flow untouched.
func (c *Client) attemptCaptchaSolveOpts(ctx context.Context, targetURL string, resp *engine.Response) (*engine.Response, error) {
	if c.orchestrator == nil {
		return nil, fmt.Errorf("no challenge orchestrator configured")
	}

	var traceEvents []adversarial.CaptchaEvent
	if c.traceLibrary != nil && c.traceLibrary.Count() > 0 {
		rng := rand.New(rand.NewSource(time.Now().UnixNano()))
		ud := challengefsm.NewUnifiedDetector()
		if ch := ud.Detect(resp); ch != nil {
			challengeType := string(ch.Type)
			events, err := c.traceLibrary.GenerateFromTrace(challengeType, "", rng.Float64)
			if err == nil {
				traceEvents = events
			}
		}
	}

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

// silence unused import warning for net/http when escalation paths don't use it.
var _ = http.MethodGet
