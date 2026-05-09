// Package agent — Executor Layer
//
// Executes agent-chosen actions against a live browser tab via CDP.
// The executor is intentionally separate from observation and formatting
// so that execution backends can be swapped (e.g. Playwright, puppeteer,
// or even HTTP-only fallback).
package agent

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"

	"github.com/skunkworq/stealth/brws/stealth"
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
	StealthClient *stealth.Client
}

// ExecuteResult describes what happened during execution.
type ExecuteResult struct {
	ActionID        string
	Success         bool
	Error           string
	NewURL          string
	ScrollDelta     float64
	ChallengeSolved bool // true if a captcha/anti-bot challenge was solved during this action
}

// Execute runs a single action and returns the result.
// The provided ctx must be a valid chromedp context (created via chromedp.NewContext).
func (e *Executor) Execute(ctx context.Context, action Action) (*ExecuteResult, error) {
	res := &ExecuteResult{ActionID: action.ID, Success: true}

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
	case ActionNewTab:
		err = e.execNewTab(ctx, action)
	case ActionSwitchTab:
		err = e.execSwitchTab(ctx, action)
	case ActionCloseTab:
		err = e.execCloseTab(ctx, action)
	case ActionNone:
		// No-op
	default:
		err = fmt.Errorf("unknown action type: %s", action.Type)
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
	selector := action.Parameters["selector"]
	if s, ok := selector.(string); ok && s != "" {
		return chromedp.Run(ctx, chromedp.Click(s, chromedp.NodeVisible))
	}
	// Fallback: click by coordinates if selector is missing
	if x, y := e.getCoords(action); x > 0 || y > 0 {
		return chromedp.Run(ctx, chromedp.MouseClickXY(x, y))
	}
	return fmt.Errorf("click action missing selector or coordinates")
}

func (e *Executor) execType(ctx context.Context, action Action) error {
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
		script = fmt.Sprintf(`window.scrollBy(0, %f)`, amt)
		delta = amt
	case ActionScrollUp:
		amt := e.scrollAmount(action, 0.5)
		script = fmt.Sprintf(`window.scrollBy(0, -%f)`, amt)
		delta = -amt
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

	// If a stealth client is configured, prime the browser session by navigating
	// through the stealth client first. This handles anti-bot challenges and
	// establishes cookies in the shared browser instance.
	if e.StealthClient != nil {
		resp, err := e.StealthClient.Navigate(ctx, urlStr)
		if err != nil {
			return nil, fmt.Errorf("stealth navigate failed: %w", err)
		}
		if resp != nil && resp.ChallengeSolved {
			// Return partial result so the caller can record challenge solving
			return &ExecuteResult{
				ActionID:        "navigate-stealth",
				Success:         true,
				NewURL:            resp.FinalURL,
				ChallengeSolved: true,
			}, nil
		}
	}

	return nil, chromedp.Run(ctx, chromedp.Navigate(urlStr))
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (e *Executor) currentURL(ctx context.Context) (string, error) {
	var url string
	err := chromedp.Run(ctx, chromedp.Location(&url))
	return url, err
}

func (e *Executor) getCoords(action Action) (float64, float64) {
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
