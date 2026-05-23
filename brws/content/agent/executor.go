// Package agent — Executor Layer
//
// Executes agent-chosen actions against a live browser tab via CDP.
// The executor is intentionally separate from observation and formatting
// so that execution backends can be swapped (e.g. Playwright, puppeteer,
// or even HTTP-only fallback).
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"strconv"
	"time"

	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"

	"github.com/skunkworq/stealth/brws/browser/engine"
	"github.com/skunkworq/stealth/brws/stealth"
	"github.com/skunkworq/stealth/brws/stealth/behavior"
	"github.com/skunkworq/stealth/brws/stealth/captcha"
)

// Executor performs actions on a live browser tab.
type Executor struct {
	// EngineCtx is the chromedp allocator context used to spawn tab contexts.
	// If nil, the executor expects a pre-built chromedp context in Execute().
	EngineCtx context.Context

	// StealthClient optionally provides challenge-aware navigation.
	// When set, Navigate actions first use the stealth client to handle
	// anti-bot challenges and establish session cookies, then navigate
	// the agent's tab context (which must share the same browser instance).
	StealthClient *stealth.Adaptive

	// VisionSolver optionally provides LLM-based visual CAPTCHA solving.
	// When set, execSolveChallenge screenshots the page and asks the vision
	// LLM to produce click/type instructions — no page context is sent,
	// only the raw image. Falls through to StealthClient on failure.
	VisionSolver *captcha.VisionSolver

	// SimulateBehavior enables human-like mouse paths, per-keystroke typing
	// delays with occasional typo corrections, and incremental scroll physics
	// for all agent-driven actions. Adds latency; reduces bot-detection risk.
	SimulateBehavior bool

	// BehaviorDelay overrides the base delay passed to behavior simulators.
	// Zero uses simulator built-in defaults (50–200 ms for mouse/typing,
	// 100–300 ms lead delay for scrolls).
	BehaviorDelay time.Duration

	// DefaultLoadStrategy controls when navigate actions yield control back.
	// Zero value falls back to LoadLoad (window.onload).
	DefaultLoadStrategy engine.LoadStrategy
}

// ExecuteResult describes what happened during execution.
type ExecuteResult struct {
	ActionID        string
	Success         bool
	Error           string
	NewURL          string
	ScrollDelta     float64
	ChallengeSolved bool // true if a captcha/anti-bot challenge was solved during this action
	// NoChange is true when the action succeeded but produced no measurable page
	// change: scroll actions that moved zero pixels, or nav actions that landed
	// on the same URL. Used by the waterfall to detect stuck agents.
	NoChange bool
}

// Execute runs a single action and returns the result.
// The provided ctx must be a valid chromedp context (created via chromedp.NewContext).
func (e *Executor) Execute(ctx context.Context, action Action) (*ExecuteResult, error) {
	res := &ExecuteResult{ActionID: action.ID, Success: true}

	// Capture pre-action URL so we can detect no-change on nav actions.
	preURL, _ := e.currentURL(ctx)

	var err error
	switch action.Type {
	case ActionClick:
		err = e.execClick(ctx, action)
	case ActionTypeText:
		err = e.execType(ctx, action)
	case ActionSelect:
		err = e.execSelect(ctx, action)
	case ActionToggle:
		err = e.execToggle(ctx, action)
	case ActionScrollDown, ActionScrollUp, ActionScrollBottom, ActionScrollTop, ActionScrollTo:
		res.ScrollDelta, err = e.execScroll(ctx, action)
	case ActionNavigate:
		stealthRes, navErr := e.execNavigate(ctx, action)
		if stealthRes != nil {
			res.ChallengeSolved = stealthRes.ChallengeSolved
		}
		err = navErr
		res.NewURL, _ = e.currentURL(ctx)
	case ActionBack:
		err = e.execBack(ctx)
		res.NewURL, _ = e.currentURL(ctx)
	case ActionForward:
		err = e.execForward(ctx)
		res.NewURL, _ = e.currentURL(ctx)
	case ActionReload:
		err = chromedp.Run(ctx, chromedp.Reload())
		res.NewURL, _ = e.currentURL(ctx)
	case ActionWait:
		err = e.execWait(ctx, action)
	case ActionScreenshot:
		err = e.execScreenshot(ctx, action)
	case ActionHover:
		err = e.execHover(ctx, action)
	case ActionFocus:
		err = e.execFocus(ctx, action)
	case ActionKeyPress:
		err = e.execKeyPress(ctx, action)
	case ActionClearInput:
		err = e.execClearInput(ctx, action)
	case ActionWaitForSelector:
		err = e.execWaitForSelector(ctx, action)
	case ActionWaitForNavigation:
		res.NewURL, err = e.execWaitForNavigation(ctx, action)
	case ActionNewTab:
		err = e.execNewTab(ctx, action)
	case ActionSwitchTab:
		err = e.execSwitchTab(ctx, action)
	case ActionCloseTab:
		err = e.execCloseTab(ctx, action)
	case ActionSolveChallenge:
		res.ChallengeSolved, err = e.execSolveChallenge(ctx, action)
	case ActionNone:
		// No-op
	default:
		err = fmt.Errorf("unknown action type: %s", action.Type)
	}

	// Detect no-change: used by the agent waterfall to track stuck states.
	// Only checked on action types where we have a reliable change signal.
	if err == nil {
		switch action.Type {
		case ActionScrollDown, ActionScrollUp:
			// Relative scrolls report their delta; zero means we were already at the boundary.
			res.NoChange = res.ScrollDelta == 0
		case ActionNavigate, ActionBack, ActionForward, ActionReload:
			// Nav actions always populate res.NewURL; compare to pre-action URL.
			res.NoChange = res.NewURL != "" && res.NewURL == preURL
		}
	}

	if err != nil {
		res.Success = false
		res.Error = err.Error()
	}
	return res, err
}

// ExecutePlan runs a sequence of actions and returns all results.
func (e *Executor) ExecutePlan(ctx context.Context, actions []Action) ([]ExecuteResult, error) {
	results := make([]ExecuteResult, 0, len(actions))
	for _, act := range actions {
		res, err := e.Execute(ctx, act)
		results = append(results, *res)
		if err != nil {
			return results, err
		}
		// Small settle delay between actions
		time.Sleep(200 * time.Millisecond)
	}
	return results, nil
}

// ---------------------------------------------------------------------------
// Individual action implementations
// ---------------------------------------------------------------------------

func (e *Executor) execClick(ctx context.Context, action Action) error {
	if e.SimulateBehavior {
		return e.execClickSimulated(ctx, action)
	}
	selector := action.Parameters["selector"]
	if s, ok := selector.(string); ok && s != "" {
		return chromedp.Run(ctx, chromedp.Click(s, chromedp.NodeVisible))
	}
	// Fallback: click by coordinates if selector is missing
	if x, y := e.coordsFromAction(action); x > 0 || y > 0 {
		return chromedp.Run(ctx, chromedp.MouseClickXY(x, y))
	}
	return fmt.Errorf("click action missing selector or coordinates")
}

// execClickSimulated moves the mouse along a Bézier path to the element centre
// (JS events visible to page scripts), then performs a reliable CDP click.
func (e *Executor) execClickSimulated(ctx context.Context, action Action) error {
	s, _ := action.Parameters["selector"].(string)

	var cx, cy float64
	if s != "" {
		// Resolve viewport-relative centre of the target element.
		script := fmt.Sprintf(`
		(function() {
			var el = document.querySelector(%q);
			if (!el) return null;
			var r = el.getBoundingClientRect();
			return {x: r.left + r.width / 2, y: r.top + r.height / 2};
		})();`, s)
		var pos map[string]interface{}
		_ = chromedp.Run(ctx, chromedp.Evaluate(script, &pos))
		if pos != nil {
			cx, cy = cdpFloat(pos, "x"), cdpFloat(pos, "y")
		}
	} else {
		cx, cy = e.coordsFromAction(action)
	}

	// Dispatch JS mousemove events along a Bézier curve to the element centre.
	// These are best-effort: the async JS fires and runs in the page's event
	// loop while the CDP click below completes reliably regardless.
	if cx > 0 || cy > 0 {
		sim := behavior.NewMouseSimulator(e.BehaviorDelay)
		_ = chromedp.Run(ctx, chromedp.Evaluate(sim.MoveTo(cx, cy), nil))
	}

	if s != "" {
		return chromedp.Run(ctx, chromedp.Click(s, chromedp.NodeVisible))
	}
	return chromedp.Run(ctx, chromedp.MouseClickXY(cx, cy))
}

func (e *Executor) execType(ctx context.Context, action Action) error {
	if e.SimulateBehavior {
		return e.execTypeSimulated(ctx, action)
	}
	selector := action.Parameters["selector"]
	text := action.Parameters["text"]
	if s, ok := selector.(string); ok && s != "" {
		if t, ok := text.(string); ok {
			return chromedp.Run(ctx,
				chromedp.SendKeys(s, t, chromedp.NodeVisible),
			)
		}
		return fmt.Errorf("type action missing text parameter")
	}
	return fmt.Errorf("type action missing selector")
}

// execTypeSimulated focuses the element then types character-by-character via
// CDP with randomised inter-keystroke delays and a 5% chance of a typo
// correction (extra char then backspace). JS key-event dispatch cannot type
// into native inputs, so the simulator's CharDelay() provides the timing while
// chromedp.SendKeys does the actual key injection.
//
//nolint:gosec // G404: math/rand intentional — non-cryptographic behavioral timing
func (e *Executor) execTypeSimulated(ctx context.Context, action Action) error {
	s, ok := action.Parameters["selector"].(string)
	if !ok || s == "" {
		return fmt.Errorf("type action missing selector")
	}
	t, ok := action.Parameters["text"].(string)
	if !ok {
		return fmt.Errorf("type action missing text parameter")
	}

	if err := chromedp.Run(ctx, chromedp.Focus(s, chromedp.NodeVisible)); err != nil {
		return fmt.Errorf("focus element: %w", err)
	}

	sim := behavior.NewTypingSimulator(e.BehaviorDelay)
	runes := []rune(t)
	for i, r := range runes {
		if err := chromedp.Run(ctx, chromedp.SendKeys(s, string(r))); err != nil {
			return fmt.Errorf("type char: %w", err)
		}
		time.Sleep(sim.CharDelay())

		// 5% chance of a typo: backspace and retype the same character.
		if i < len(runes)-1 && rand.Float32() < 0.05 { //nolint:gosec
			_ = chromedp.Run(ctx, chromedp.SendKeys(s, "\b"))
			time.Sleep(sim.CharDelay() * 2)
			_ = chromedp.Run(ctx, chromedp.SendKeys(s, string(r)))
		}
	}
	return nil
}

func (e *Executor) execSelect(ctx context.Context, action Action) error {
	selector := action.Parameters["selector"]
	value := action.Parameters["value"]
	s, ok1 := selector.(string)
	v, ok2 := value.(string)
	if !ok1 || s == "" {
		return fmt.Errorf("select action missing selector")
	}
	if !ok2 || v == "" {
		return fmt.Errorf("select action missing value")
	}
	script := fmt.Sprintf(`
	(function() {
		var el = document.querySelector(%q);
		if (!el) return false;
		el.value = %q;
		el.dispatchEvent(new Event('change', {bubbles: true}));
		return true;
	})();`, s, v)
	var result bool
	if err := chromedp.Run(ctx, chromedp.Evaluate(script, &result)); err != nil {
		return err
	}
	if !result {
		return fmt.Errorf("select: element not found for selector %s", s)
	}
	return nil
}

func (e *Executor) execToggle(ctx context.Context, action Action) error {
	selector := action.Parameters["selector"]
	if s, ok := selector.(string); ok && s != "" {
		return chromedp.Run(ctx, chromedp.Click(s, chromedp.NodeVisible))
	}
	return fmt.Errorf("toggle action missing selector")
}

func (e *Executor) execScroll(ctx context.Context, action Action) (float64, error) {
	var script string
	var delta float64

	switch action.Type {
	case ActionScrollDown:
		amt := e.scrollAmount(action, 0.5)
		delta = amt
		if e.SimulateBehavior {
			sim := behavior.NewScrollSimulator(e.BehaviorDelay)
			return delta, chromedp.Run(ctx, chromedp.Evaluate(sim.ScrollDown(amt), nil))
		}
		script = fmt.Sprintf(`window.scrollBy(0, %f)`, amt)
	case ActionScrollUp:
		amt := e.scrollAmount(action, 0.5)
		delta = -amt
		if e.SimulateBehavior {
			sim := behavior.NewScrollSimulator(e.BehaviorDelay)
			return delta, chromedp.Run(ctx, chromedp.Evaluate(sim.ScrollUp(amt), nil))
		}
		script = fmt.Sprintf(`window.scrollBy(0, -%f)`, amt)
	case ActionScrollBottom:
		script = `window.scrollTo(0, document.body.scrollHeight)`
	case ActionScrollTop:
		script = `window.scrollTo(0, 0)`
	case ActionScrollTo:
		if sel, ok := action.Parameters["selector"].(string); ok && sel != "" {
			script = fmt.Sprintf(`
			(function() {
				var el = document.querySelector(%q);
				if (el) el.scrollIntoView({behavior: 'smooth', block: 'center'});
			})();`, sel)
		} else if y, ok := action.Parameters["y"].(float64); ok {
			script = fmt.Sprintf(`window.scrollTo(0, %f)`, y)
		} else {
			return 0, fmt.Errorf("scroll_to missing target")
		}
	}

	return delta, chromedp.Run(ctx, chromedp.Evaluate(script, nil))
}

func (e *Executor) execNavigate(ctx context.Context, action Action) (*ExecuteResult, error) {
	urlStr, ok := action.Parameters["url"].(string)
	if !ok || urlStr == "" {
		return nil, fmt.Errorf("navigate action missing url parameter")
	}

	// If a stealth client is configured, navigate directly on the agent's tab
	// with stealth setup applied in-place. This eliminates the wasteful
	// double-navigation pattern (temp tab solve + agent tab re-navigate).
	if e.StealthClient != nil {
		resp, err := e.StealthClient.NavigateOnTab(ctx, ctx, urlStr)
		if err != nil {
			return nil, fmt.Errorf("stealth navigate failed: %w", err)
		}
		return &ExecuteResult{
			ActionID:        "navigate-stealth",
			Success:         true,
			NewURL:          resp.FinalURL,
			ChallengeSolved: resp.ChallengeSolved,
		}, nil
	}

	return nil, chromedp.Run(ctx, navigateAction(urlStr, e.DefaultLoadStrategy))
}

// navigateAction returns a chromedp Action that navigates to url and yields
// when the requested load condition is satisfied.
func navigateAction(url string, strategy engine.LoadStrategy) chromedp.Action {
	switch strategy {
	case engine.LoadCommit:
		return chromedp.ActionFunc(func(ctx context.Context) error {
			_, _, _, _, err := page.Navigate(url).Do(ctx)
			return err
		})
	case engine.LoadDOMContentLoaded:
		return chromedp.ActionFunc(func(ctx context.Context) error {
			done := make(chan struct{}, 1)
			chromedp.ListenTarget(ctx, func(ev interface{}) {
				if _, ok := ev.(*page.EventDomContentEventFired); ok {
					select {
					case done <- struct{}{}:
					default:
					}
				}
			})
			if _, _, _, _, err := page.Navigate(url).Do(ctx); err != nil {
				return err
			}
			select {
			case <-done:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	case engine.LoadNetworkIdle:
		return chromedp.ActionFunc(func(ctx context.Context) error {
			if err := page.SetLifecycleEventsEnabled(true).Do(ctx); err != nil {
				return err
			}
			done := make(chan struct{}, 1)
			chromedp.ListenTarget(ctx, func(ev interface{}) {
				if lc, ok := ev.(*page.EventLifecycleEvent); ok && lc.Name == "networkIdle" {
					select {
					case done <- struct{}{}:
					default:
					}
				}
			})
			if _, _, _, _, err := page.Navigate(url).Do(ctx); err != nil {
				return err
			}
			select {
			case <-done:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	default: // LoadLoad and zero value
		return chromedp.Navigate(url)
	}
}

func (e *Executor) execBack(ctx context.Context) error {
	return chromedp.Run(ctx, chromedp.NavigateBack())
}

func (e *Executor) execForward(ctx context.Context) error {
	return chromedp.Run(ctx, chromedp.NavigateForward())
}

func (e *Executor) execWait(ctx context.Context, action Action) error {
	ms := 1000
	if v, ok := action.Parameters["ms"]; ok {
		switch val := v.(type) {
		case float64:
			ms = int(val)
		case int:
			ms = val
		case string:
			if parsed, err := strconv.Atoi(val); err == nil {
				ms = parsed
			}
		}
	}
	if v, ok := action.Parameters["duration"]; ok {
		if s, ok := v.(string); ok {
			if d, err := time.ParseDuration(s); err == nil {
				ms = int(d.Milliseconds())
			}
		}
	}
	return chromedp.Run(ctx, chromedp.Sleep(time.Duration(ms)*time.Millisecond))
}

func (e *Executor) execScreenshot(ctx context.Context, action Action) error {
	var buf []byte
	if err := chromedp.Run(ctx, chromedp.CaptureScreenshot(&buf)); err != nil {
		return err
	}
	// Optionally save to file if path provided
	if path, ok := action.Parameters["path"].(string); ok && path != "" {
		// Screenshot is in buf; caller can save it
		_ = path
	}
	return nil
}

func (e *Executor) execHover(ctx context.Context, action Action) error {
	selector := action.Parameters["selector"]
	if s, ok := selector.(string); ok && s != "" {
		script := fmt.Sprintf(`
		(function() {
			var el = document.querySelector(%q);
			if (!el) return null;
			var r = el.getBoundingClientRect();
			return {x: r.left + r.width / 2, y: r.top + r.height / 2};
		})();`, s)
		var pos map[string]interface{}
		if err := chromedp.Run(ctx, chromedp.Evaluate(script, &pos)); err != nil {
			return err
		}
		if pos == nil {
			return fmt.Errorf("hover: element not found for selector %s", s)
		}
		x, y := cdpFloat(pos, "x"), cdpFloat(pos, "y")
		return chromedp.Run(ctx, chromedp.MouseEvent(input.MouseMoved, x, y))
	}
	return fmt.Errorf("hover action missing selector")
}

func (e *Executor) execFocus(ctx context.Context, action Action) error {
	selector := action.Parameters["selector"]
	if s, ok := selector.(string); ok && s != "" {
		return chromedp.Run(ctx, chromedp.Focus(s, chromedp.NodeVisible))
	}
	return fmt.Errorf("focus action missing selector")
}

var keyMap = map[string]string{
	"Enter":     "\r",
	"Return":    "\r",
	"Escape":    "\u001b",
	"Esc":       "\u001b",
	"Tab":       "\t",
	"Backspace": "\b",
	"Space":     " ",
}

func (e *Executor) execKeyPress(ctx context.Context, action Action) error {
	key, ok := action.Parameters["key"].(string)
	if !ok || key == "" {
		return fmt.Errorf("key_press action missing key parameter")
	}
	if mapped, ok := keyMap[key]; ok {
		key = mapped
	}
	if selector, ok := action.Parameters["selector"].(string); ok && selector != "" {
		if err := chromedp.Run(ctx, chromedp.Focus(selector, chromedp.NodeVisible)); err != nil {
			return fmt.Errorf("focus element for key_press: %w", err)
		}
		return chromedp.Run(ctx, chromedp.SendKeys(selector, key, chromedp.NodeVisible))
	}
	return chromedp.Run(ctx, chromedp.ActionFunc(func(c context.Context) error {
		return input.DispatchKeyEvent(input.KeyDown).WithText(key).Do(c)
	}))
}

func (e *Executor) execClearInput(ctx context.Context, action Action) error {
	selector := action.Parameters["selector"]
	s, ok := selector.(string)
	if !ok || s == "" {
		return fmt.Errorf("clear_input action missing selector")
	}
	script := fmt.Sprintf(`
	(function() {
		var el = document.querySelector(%q);
		if (!el) return false;
		el.value = '';
		el.dispatchEvent(new Event('input', {bubbles: true}));
		el.dispatchEvent(new Event('change', {bubbles: true}));
		return true;
	})();`, s)
	var result bool
	if err := chromedp.Run(ctx, chromedp.Evaluate(script, &result)); err != nil {
		return err
	}
	if !result {
		return fmt.Errorf("clear_input: element not found for selector %s", s)
	}
	return nil
}

func parseTimeoutMs(param interface{}, defaultMs int) int {
	if v, ok := param.(float64); ok {
		return int(v)
	}
	if v, ok := param.(int); ok {
		return v
	}
	if v, ok := param.(string); ok && v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			return parsed
		}
	}
	return defaultMs
}

func (e *Executor) execWaitForSelector(ctx context.Context, action Action) error {
	selector, ok := action.Parameters["selector"].(string)
	if !ok || selector == "" {
		return fmt.Errorf("wait_for_selector action missing selector parameter")
	}
	timeoutMs := parseTimeoutMs(action.Parameters["timeout_ms"], 5000)
	waitCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()
	if err := chromedp.Run(waitCtx, chromedp.WaitVisible(selector)); err != nil {
		if waitCtx.Err() != nil {
			return fmt.Errorf("wait_for_selector timeout after %d ms: selector %q did not appear", timeoutMs, selector)
		}
		return err
	}
	return nil
}

func (e *Executor) execWaitForNavigation(ctx context.Context, action Action) (string, error) {
	timeoutMs := parseTimeoutMs(action.Parameters["timeout_ms"], 5000)
	waitCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()

	preURL, _ := e.currentURL(waitCtx)

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-waitCtx.Done():
			return "", fmt.Errorf("wait_for_navigation timeout after %d ms", timeoutMs)
		case <-ticker.C:
			url, err := e.currentURL(waitCtx)
			if err == nil && url != "" && url != preURL {
				return url, nil
			}
		}
	}
}

func (e *Executor) execNewTab(ctx context.Context, action Action) error {
	url := "about:blank"
	if u, ok := action.Parameters["url"].(string); ok && u != "" {
		url = u
	}
	return chromedp.Run(ctx, chromedp.ActionFunc(func(c context.Context) error {
		_, err := target.CreateTarget(url).Do(c)
		return err
	}))
}

func (e *Executor) execSwitchTab(ctx context.Context, action Action) error {
	tid, ok := action.Parameters["target_id"].(string)
	if !ok || tid == "" {
		return fmt.Errorf("switch_tab missing target_id")
	}
	return chromedp.Run(ctx, target.ActivateTarget(target.ID(tid)))
}

func (e *Executor) execCloseTab(ctx context.Context, action Action) error {
	tid, ok := action.Parameters["target_id"].(string)
	if !ok || tid == "" {
		return fmt.Errorf("close_tab missing target_id")
	}
	return chromedp.Run(ctx, target.CloseTarget(target.ID(tid)))
}

// execSolveChallenge attempts to solve the current CAPTCHA challenge.
//
// Two parallel paths are tried in order:
//  1. VisionSolver — screenshots the page, asks a vision LLM (no page context)
//     to produce click/type instructions, then executes them.
//  2. StealthClient — re-navigates the current URL using the full automated
//     challenge-solving stack (FSM + CapSolver / ML solver).
//
// If VisionSolver is set it runs first; StealthClient is used as fallback or
// when VisionSolver is not configured.
func (e *Executor) execSolveChallenge(ctx context.Context, action Action) (bool, error) {
	if e.VisionSolver != nil {
		challengeType, _ := action.Parameters["challenge_type"].(string)
		solved, err := e.solveWithVision(ctx, challengeType)
		if err == nil && solved {
			return true, nil
		}
		// fall through to StealthClient on vision failure
	}

	if e.StealthClient == nil {
		return false, fmt.Errorf("no solver configured: set VisionSolver or StealthClient on Executor")
	}

	url, err := e.currentURL(ctx)
	if err != nil {
		return false, fmt.Errorf("get current url: %w", err)
	}
	resp, err := e.StealthClient.NavigateOnTab(ctx, ctx, url)
	if err != nil {
		return false, fmt.Errorf("stealth navigate for challenge solve: %w", err)
	}
	return resp.ChallengeSolved, nil
}

// solveWithVision screenshots the captcha region, builds an augmented prompt
// from the challenge type, and delegates to the VisionSolver. Instructions are
// expressed relative to the extracted image and executed on the live tab with
// an offset applied back to page coordinates.
func (e *Executor) solveWithVision(ctx context.Context, challengeType string) (bool, error) {
	ex, err := e.extractCaptchaImage(ctx)
	if err != nil {
		return false, err
	}

	prompt := buildCaptchaPrompt(challengeType, ex.DOMContext)
	instructions, err := e.VisionSolver.Solve(ctx, ex.Image, prompt)
	if err != nil {
		return false, err
	}
	if len(instructions) == 0 {
		return false, fmt.Errorf("vision solver returned no instructions")
	}

	for _, inst := range instructions {
		switch inst.Action { //nolint:exhaustive
		case "click":
			// translate image-relative coords back to page coords
			if err := chromedp.Run(ctx, chromedp.MouseClickXY(inst.X+ex.OffsetX, inst.Y+ex.OffsetY)); err != nil {
				return false, fmt.Errorf("captcha click (%.0f,%.0f): %w", inst.X+ex.OffsetX, inst.Y+ex.OffsetY, err)
			}
			time.Sleep(350 * time.Millisecond)
		case "type":
			if inst.Selector == "" {
				inst.Selector = "input[type=text],input:not([type])"
			}
			if err := chromedp.Run(ctx, chromedp.SendKeys(inst.Selector, inst.Value, chromedp.ByQuery)); err != nil {
				return false, fmt.Errorf("captcha type: %w", err)
			}
			time.Sleep(200 * time.Millisecond)
		case "submit":
			err := chromedp.Run(ctx, chromedp.Submit("form", chromedp.ByQuery))
			if err != nil {
				// fallback: press Enter
				chromedp.Run(ctx, chromedp.KeyEvent("\r")) //nolint:errcheck
			}
			time.Sleep(500 * time.Millisecond)
		}
	}

	return true, nil
}

// captchaExtraction holds everything gathered about a CAPTCHA on the page.
type captchaExtraction struct {
	// Image is the best available image of the CAPTCHA widget — either a
	// clipped screenshot of the DOM widget or a full-page fallback.
	Image   []byte
	OffsetX float64 // page-coordinate offset for translating image-relative clicks
	OffsetY float64

	// DOMContext is visible text extracted from around the CAPTCHA widget:
	// challenge labels ("Select all traffic lights"), aria labels, alt text.
	// Incorporated into the prompt so the vision LLM knows what it's asked.
	DOMContext string

	// NetworkImages holds candidate images fetched from network resources
	// whose URLs match captcha patterns (challenge tiles, puzzle pieces, etc.).
	// Currently informational — future: pass as additional image context.
	NetworkImages []string // URLs only; fetching deferred to avoid blocking
}

// extractCaptchaImage collects the best available CAPTCHA representation from
// three sources and returns a captchaExtraction:
//
//  1. DOM clip — tries known CSS selectors for CAPTCHA containers; clips the
//     screenshot to that region and records the page offset.
//  2. DOM context — scrapes visible text (labels, aria, alt) from around the
//     widget so the LLM knows what the challenge is asking.
//  3. Network images — enumerates loaded image resources via
//     performance.getEntriesByType("resource") and filters for URLs containing
//     captcha-related patterns (challenge tiles, puzzle pieces, etc.).
func (e *Executor) extractCaptchaImage(ctx context.Context) (*captchaExtraction, error) {
	ex := &captchaExtraction{}

	type rect struct{ X, Y, W, H float64 }

	// 1. DOM clip — find the CAPTCHA widget and clip the screenshot to it.
	widgetSelectors := []string{
		"iframe[src*='recaptcha']",
		"iframe[src*='hcaptcha']",
		"iframe[src*='turnstile']",
		".g-recaptcha",
		"#captcha",
		"[class*='captcha']",
		"[id*='captcha']",
	}
	for _, sel := range widgetSelectors {
		var r rect
		script := fmt.Sprintf(`(function(){
			var el = document.querySelector(%q);
			if (!el) return null;
			var b = el.getBoundingClientRect();
			return {X: b.left, Y: b.top, W: b.width, H: b.height};
		})();`, sel)
		if err := chromedp.Run(ctx, chromedp.Evaluate(script, &r)); err != nil || r.W == 0 {
			continue
		}
		clip := page.Viewport{X: r.X, Y: r.Y, Width: r.W, Height: r.H, Scale: 1}
		var clipped []byte
		if err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
			var captureErr error
			clipped, captureErr = page.CaptureScreenshot().WithClip(&clip).Do(ctx)
			return captureErr
		})); err != nil {
			continue
		}
		ex.Image = clipped
		ex.OffsetX = r.X
		ex.OffsetY = r.Y
		break
	}

	// Fallback: full-page screenshot.
	if ex.Image == nil {
		var full []byte
		if err := chromedp.Run(ctx, chromedp.CaptureScreenshot(&full)); err != nil {
			return nil, fmt.Errorf("captcha screenshot: %w", err)
		}
		ex.Image = full
	}

	// 2. DOM context — extract visible label/instruction text near the widget.
	var domCtx string
	domScript := `(function(){
		var parts = [];
		// Challenge label text (reCAPTCHA, hCaptcha instruction header).
		var labelSels = [
			'.rc-imageselect-desc-wrapper',
			'.rc-imageselect-instructions',
			'[class*="prompt"]',
			'[class*="instructions"]',
			'[class*="challenge"]',
			'[aria-label*="captcha"]',
		];
		labelSels.forEach(function(s){
			var el = document.querySelector(s);
			if (el) parts.push(el.innerText.trim());
		});
		// Alt text of visible images in captcha containers.
		document.querySelectorAll('[class*="captcha"] img, [id*="captcha"] img').forEach(function(img){
			if (img.alt) parts.push('img:' + img.alt);
		});
		return parts.filter(Boolean).join(' | ');
	})();`
	chromedp.Run(ctx, chromedp.Evaluate(domScript, &domCtx)) //nolint:errcheck
	ex.DOMContext = domCtx

	// 3. Network images — find loaded image resources with captcha-like URLs.
	var networkJSON string
	netScript := `(function(){
		var patterns = ['captcha','challenge','recaptcha','hcaptcha','turnstile','puzzle','verify'];
		var imgs = performance.getEntriesByType('resource')
			.filter(function(e){
				return e.initiatorType === 'img' || e.initiatorType === 'fetch' ||
				       /\.(png|jpg|jpeg|gif|webp|svg)(\?|$)/i.test(e.name);
			})
			.filter(function(e){
				var lc = e.name.toLowerCase();
				return patterns.some(function(p){ return lc.includes(p); });
			})
			.map(function(e){ return e.name; });
		return JSON.stringify(imgs);
	})();`
	if err := chromedp.Run(ctx, chromedp.Evaluate(netScript, &networkJSON)); err == nil && networkJSON != "" {
		var urls []string
		if json.Unmarshal([]byte(networkJSON), &urls) == nil {
			ex.NetworkImages = urls
		}
	}

	return ex, nil
}

// buildCaptchaPrompt returns SolvePromptTemplate augmented with challenge-type
// context and any DOM hints extracted from the page.
func buildCaptchaPrompt(challengeType, domContext string) string {
	base := captcha.SolvePromptTemplate

	var extra string
	switch challengeType {
	case "recaptcha", "recaptcha_v2":
		extra = "This is a reCAPTCHA v2 image grid. Click every tile that matches the category shown in the header."
	case "hcaptcha":
		extra = "This is an hCaptcha grid. Click every image that matches the instruction text."
	case "turnstile":
		extra = "This is a Cloudflare Turnstile. Click the checkbox to verify."
	case "datadome":
		extra = "This is a DataDome CAPTCHA puzzle. Drag or click to solve the puzzle."
	}

	prompt := base
	if extra != "" {
		prompt += "\n\n" + extra
	}
	if domContext != "" {
		prompt += "\n\nChallenge context from page: " + domContext
	}
	return prompt
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (e *Executor) currentURL(ctx context.Context) (string, error) {
	var url string
	err := chromedp.Run(ctx, chromedp.Location(&url))
	return url, err
}

func (e *Executor) coordsFromAction(action Action) (float64, float64) {
	x, _ := action.Parameters["x"].(float64)
	y, _ := action.Parameters["y"].(float64)
	return x, y
}

func (e *Executor) scrollAmount(action Action, defaultVPFrac float64) float64 {
	if v, ok := action.Parameters["amount"].(float64); ok && v > 0 {
		return v
	}
	if v, ok := action.Parameters["amount"].(int); ok && v > 0 {
		return float64(v)
	}
	return 800 * defaultVPFrac
}
