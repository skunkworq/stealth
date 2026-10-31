package chromium

// In-page anti-bot challenge solving, modeled on FlareSolverr's proven loop
// (flaresolverr_service.py _evil_logic): keep the browser on the interstitial,
// poll for the challenge markers to disappear, periodically drive the Turnstile
// checkbox through the keyboard (TAB to focus, SPACE to toggle — the
// accessibility path needs no element coordinates), then wait for the
// post-solve navigation before the caller captures the DOM.
//
// This replaces the legacy synthesized-submission path: modern Cloudflare
// managed challenges embed no PoW params a client can answer — the solve is
// the site's own JS running in a sufficiently clean browser plus, when the
// interactive checkbox variant is served, one synthetic keypress.

import (
	"context"
	"sync"
	"time"

	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/chromedp"
)

// challengeSolveBudget is the total time a single request will sit on an
// interstitial trying to solve it. FlareSolverr effectively budgets ~60s via
// its default request timeout; our probe callers bound harder via ctx.
const challengeSolveBudget = 45 * time.Second

// challengeClickInterval matches FS's cadence: a click_verify attempt roughly
// every wait-timeout (~5-6s) while the challenge persists.
const challengeClickInterval = 6 * time.Second

// challengePollInterval is how often the DOM is re-polled. CF reloads the
// interstitial roughly every 5s, so sub-second polling catches the transition
// promptly.
const challengePollInterval = 750 * time.Millisecond

// challengePresentExpr evaluates true while the page is still a challenge
// document — Cloudflare title markers, DDoS-Guard, or any of the challenge
// element selectors FS polls for. Single expression to keep the round-trip
// cheap inside the poll loop.
const challengePresentExpr = `(function(){
	var t = (document.title||'').toLowerCase();
	if (t === 'just a moment...' || t === 'just a moment' || t.indexOf('ddos-guard') === 0 || t === 'attention required! | cloudflare' || t.indexOf('pardon our interruption') === 0) {
		return true;
	}
	var sels = '#cf-challenge-running,.ray_id,.attack-box,#cf-please-wait,#challenge-spinner,#trk_jschal_js,#turnstile-wrapper,.lds-ring,td.info #js_info,div.vc div.text-box h2,input[name="cf-turnstile-response"],iframe#main-iframe,#challenge-element,#challenge-form';
	try { if (document.querySelector(sels)) return true; } catch(e) {}
	// Imperva/Incapsula interstitials (mirrors instrumentation.DetectChallenge's
	// body markers) — the JS challenge reloads itself once computed, so the
	// same wait loop clears it without a click.
	var h = document.documentElement ? document.documentElement.innerHTML : '';
	return h.indexOf('_Incapsula_Resource') !== -1 || h.indexOf('visid_incap') !== -1;
})()`

// cfMarkersExpr reports whether the challenge carries CF-specific artifacts
// (title or selectors). CF-managed challenges justify the full solve budget —
// the interactive variant can take 30-45s cold; Imperva/Incapsula JS
// challenges either self-clear in a few seconds when the fingerprint passes or
// never clear, so a short wait suffices and long budgets waste retries.
const cfMarkersExpr = `(function(){
	var t = (document.title||'').toLowerCase();
	if (t === 'just a moment...' || t === 'just a moment' || t === 'attention required! | cloudflare') return true;
	var sels = '#cf-challenge-running,.ray_id,.attack-box,#cf-please-wait,#challenge-spinner,#trk_jschal_js,#turnstile-wrapper,.lds-ring,input[name="cf-turnstile-response"]';
	try { return !!document.querySelector(sels); } catch(e) { return false; }
})()`

// verifyButtonExpr clicks the explicit "Verify you are human" button variant
// (older CF checkbox page) — the FS XPath fallback — returning true if one was
// found and clicked.
const verifyButtonExpr = `(function(){
	var btns = document.querySelectorAll('input[type="button"]');
	for (var i = 0; i < btns.length; i++) {
		if (/verify you are human/i.test(btns[i].value||'')) { btns[i].click(); return true; }
	}
	return false;
})()`

// challengeSolve waits for an in-page anti-bot interstitial to clear: polls the
// live DOM for FS's title/selector markers, and on each click interval drives
// the Turnstile checkbox via keyboard (TAB focuses the first focusable widget,
// SPACE toggles it) plus the explicit button variant. Returns true if the
// challenge cleared within budget — the caller then waits for the post-solve
// navigation and captures the real document.
func (s *StealthEngine) challengeSolve(ctx context.Context, budget time.Duration) bool {
	if budget <= 0 {
		budget = challengeSolveBudget
	}
	// Never eat the whole tab lifetime: reserve headroom so the caller can
	// still capture the (possibly unsolved) document and return it — a challenge
	// body beats a hard context-deadline error for upstream escalation logic.
	if d, ok := ctx.Deadline(); ok {
		if rem := time.Until(d) - 4*time.Second; rem < budget {
			budget = rem
		}
	}
	if budget <= 0 {
		return false
	}
	deadline := time.Now().Add(budget)
	clickAt := time.Now().Add(5 * time.Second) // FS pauses ~5s before the first click
	clicks := 0
	for {
		var present bool
		if err := chromedp.Evaluate(challengePresentExpr, &present).Do(ctx); err != nil {
			// Evaluation failing mid-loop usually means the document was
			// replaced (post-solve navigation) — treat as cleared.
			return true
		}
		if !present {
			return true
		}
		if time.Now().After(deadline) {
			s.logger.Debug("challenge solve budget exhausted", "clicks", clicks)
			return false
		}
		if time.Now().After(clickAt) {
			s.sendVerifyClick(ctx)
			clicks++
			// FS's early-exit: a populated cf-turnstile-response input means
			// the widget accepted the interaction — the clear is imminent.
			var tok string
			_ = chromedp.Evaluate(`(document.querySelector('input[name="cf-turnstile-response"]')||{value:''}).value||''`, &tok).Do(ctx)
			if tok != "" {
				s.logger.Info("turnstile token issued, waiting for clear", "clicks", clicks)
				select {
				case <-ctx.Done():
					return false
				case <-time.After(3 * time.Second):
					return true
				}
			}
			clickAt = time.Now().Add(challengeClickInterval)
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(challengePollInterval):
		}
	}
}

// challengeActive reports whether the current document still shows an
// anti-bot interstitial (FS's CHALLENGE_TITLES ∪ CHALLENGE_SELECTORS check).
func (s *StealthEngine) challengeActive(ctx context.Context) bool {
	var present bool
	if err := chromedp.Evaluate(challengePresentExpr, &present).Do(ctx); err != nil {
		return false
	}
	return present
}

// turnstileBoxExpr locates the Turnstile iframe (the cf-chl-widget lives in a
// cross-origin frame — unreachable by DOM query for a JS click) and returns
// its bounding box as [x,y,w,h] for a coordinate click at the checkbox spot.
const turnstileBoxExpr = `(function(){
	var f = document.querySelector('iframe[src*="challenges.cloudflare.com"],iframe[src*="turnstile"],#cf-chl-widget iframe,div[id^="cf-chl-widget"] iframe');
	if (!f) return null;
	var r = f.getBoundingClientRect();
	return [r.x, r.y, r.width, r.height];
})()`

// sendVerifyClick performs FS's click_verify: TAB/SPACE keyboard drive for
// focusable challenge widgets, a coordinate click at the checkbox position
// inside the Turnstile iframe (cross-origin — DOM clicks can't reach it), then
// the explicit "Verify you are human" button fallback.
func (s *StealthEngine) sendVerifyClick(ctx context.Context) {
	// Coordinate click into the Turnstile iframe first — when the widget is
	// present this is the reliable path (FS's move_to_element_with_offset).
	var box []float64
	if err := chromedp.Evaluate(turnstileBoxExpr, &box).Do(ctx); err == nil && len(box) == 4 && box[2] > 0 {
		s.logger.Debug("turnstile widget click", "x", box[0], "y", box[1], "w", box[2], "h", box[3])
		// Turnstile's checkbox sits ~30px from the widget's left edge,
		// vertically centered.
		x := box[0] + 30
		if box[2] < 60 {
			x = box[0] + box[2]/2
		}
		y := box[1] + box[3]/2
		press := input.DispatchMouseEventParams{
			Type: input.MousePressed,
			X:    x, Y: y,
			Button:     input.Left,
			ClickCount: 1,
		}
		_ = press.Do(ctx)
		time.Sleep(60 * time.Millisecond)
		release := input.DispatchMouseEventParams{
			Type: input.MouseReleased,
			X:    x, Y: y,
			Button:     input.Left,
			ClickCount: 1,
		}
		_ = release.Do(ctx)
		return
	}
	s.logger.Debug("no turnstile iframe box, falling back to keyboard", "box", box)

	// No Turnstile iframe — keyboard drive (FS's click_verify): TAB focuses the
	// next widget, SPACE toggles it.
	s.dispatchKey(ctx, "Tab", "Tab", 9, "")
	time.Sleep(120 * time.Millisecond)
	s.dispatchKey(ctx, "Tab", "Tab", 9, "")
	time.Sleep(300 * time.Millisecond)
	s.dispatchKey(ctx, " ", "Space", 32, " ")

	// Explicit "Verify you are human" button fallback (older CF layouts).
	var clicked bool
	_ = chromedp.Evaluate(verifyButtonExpr, &clicked).Do(ctx)
}

// dispatchKey sends a keyDown+keyUp pair via Input.dispatchKeyEvent.
func (s *StealthEngine) dispatchKey(ctx context.Context, key, code string, vkey int64, text string) {
	down := input.DispatchKeyEventParams{
		Type:                  input.KeyDown,
		Key:                   key,
		Code:                  code,
		WindowsVirtualKeyCode: vkey,
		Text:                  text,
		UnmodifiedText:        text,
	}
	_ = down.Do(ctx)
	up := input.DispatchKeyEventParams{
		Type:                  input.KeyUp,
		Key:                   key,
		Code:                  code,
		WindowsVirtualKeyCode: vkey,
	}
	_ = up.Do(ctx)
}

// waitPostSolveNav pauses briefly after the challenge clears so the
// auto-reload CF triggers post-solve can land, then waits for the network to
// go quiet again on the real document — the same settle the initial
// navigation used.
func (s *StealthEngine) waitPostSolveNav(
	ctx context.Context,
	netMu *sync.Mutex,
	inFlight *int,
	lastActivity *time.Time,
	navCount *int,
	budget, idleWindow time.Duration,
) {
	// CF reloads within ~2s of clearance; give the navigation a moment to start
	// before the settle watcher's quiet-window can fire on the old document.
	timer := time.NewTimer(1500 * time.Millisecond)
	select {
	case <-ctx.Done():
		timer.Stop()
		return
	case <-timer.C:
	}
	s.challengeSettle(ctx, netMu, inFlight, lastActivity, navCount, budget, idleWindow)
}
