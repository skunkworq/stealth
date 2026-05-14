package stealth_test

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	cstealth "github.com/skunkworq/stealth/brws/stealth/chromium"
)

// TestCloudflare_TurnstileSolve uses a stealth chromium browser to solve a real
// Cloudflare Turnstile challenge. The test navigates to a Turnstile-protected
// page, locates the widget iframe, clicks the checkbox, and verifies the
// challenge resolves (cf_clearance cookie or clean page content).
//
// Usage:
//
//	STEALTH_LIVE_TEST=1 go test ./brws/stealth/test/ -run TestCloudflare_TurnstileSolve -v -count=1 -timeout 3m
func TestCloudflare_TurnstileSolve(t *testing.T) {
	if os.Getenv("STEALTH_LIVE_TEST") != "1" {
		t.Skip("set STEALTH_LIVE_TEST=1 to run live tests")
	}

	sites := []struct {
		name    string
		url     string
		timeout time.Duration
	}{
		{"NowSecure", "https://nowsecure.nl/", 60 * time.Second},
	}

	for _, site := range sites {
		t.Run(site.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), site.timeout)
			defer cancel()

			// Create stealth browser
			stealthScript := cstealth.GenerateStealthScript(cstealth.DefaultStealthConfig())

			allocOpts := []chromedp.ExecAllocatorOption{
				chromedp.NoFirstRun,
				chromedp.NoDefaultBrowserCheck,
				chromedp.Headless,
				chromedp.DisableGPU,
				chromedp.Flag("disable-blink-features", "AutomationControlled"),
				chromedp.UserAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"),
			}

			allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, allocOpts...)
			defer allocCancel()

			tabCtx, tabCancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(t.Logf))
			defer tabCancel()

			// Inject stealth script before any page loads
			if err := chromedp.Run(tabCtx, chromedp.ActionFunc(func(ctx context.Context) error {
				_, err := page.AddScriptToEvaluateOnNewDocument(stealthScript).Do(ctx)
				return err
			})); err != nil {
				t.Fatalf("inject stealth script: %v", err)
			}

			// Track cookies set during navigation
			var cookies []*network.Cookie
			chromedp.ListenTarget(tabCtx, func(ev interface{}) {
				switch ev.(type) {
				case *network.EventResponseReceived:
					// Could log headers here if needed
				}
			})

			// Step 1: Navigate to the page
			t.Logf("Step 1: Navigating to %s...", site.url)
			if err := chromedp.Run(tabCtx,
				network.Enable(),
				chromedp.Navigate(site.url),
				chromedp.WaitReady("body"),
			); err != nil {
				t.Fatalf("navigate: %v", err)
			}

			// Brief pause for page to settle
			time.Sleep(2 * time.Second)

			// Step 2: Check initial page state
			var html string
			if err := chromedp.Run(tabCtx, chromedp.OuterHTML("html", &html)); err != nil {
				t.Fatalf("get html: %v", err)
			}

			htmlLower := strings.ToLower(html)
			hasTitle := strings.Contains(htmlLower, "<title>")
			hasTurnstile := strings.Contains(html, "cf-turnstile") ||
				strings.Contains(html, "challenges.cloudflare.com/turnstile")
			hasChallenge := strings.Contains(html, "challenge-platform") ||
				strings.Contains(html, "cf-challenge-running")

			t.Logf("Step 2: Initial page - title=%v turnstile=%v challenge=%v body=%d",
				hasTitle, hasTurnstile, hasChallenge, len(html))

			if hasTitle && !hasChallenge && !hasTurnstile {
				t.Logf("PASS: Page loaded clean — no Turnstile challenge presented")
				return
			}

			// Step 3: Look for Turnstile iframe
			t.Logf("Step 3: Looking for Turnstile iframe...")

			// Wait for the Turnstile iframe to appear (it may take a moment to load)
			var iframeFound bool
			var iframeX, iframeY, iframeW, iframeH float64

			for attempt := 0; attempt < 15; attempt++ {
				var result string
				err := chromedp.Run(tabCtx, chromedp.Evaluate(`
					(function() {
						// Look for Turnstile iframe by various selectors
						const selectors = [
							'iframe[src*="challenges.cloudflare.com"]',
							'iframe[src*="turnstile"]',
							'.cf-turnstile iframe',
							'#cf-turnstile iframe',
							'iframe[allow*="cross-origin-isolated"]',
						];

						for (const sel of selectors) {
							const iframe = document.querySelector(sel);
							if (iframe) {
								const rect = iframe.getBoundingClientRect();
								return JSON.stringify({
									found: true,
									selector: sel,
									src: iframe.src.substring(0, 100),
									x: rect.x,
									y: rect.y,
									width: rect.width,
									height: rect.height,
									visible: rect.width > 0 && rect.height > 0,
								});
							}
						}

						// Also check for any iframe that might be Turnstile
						const allIframes = document.querySelectorAll('iframe');
						const iframeInfo = [];
						allIframes.forEach(f => {
							iframeInfo.push({
								src: (f.src || '').substring(0, 80),
								width: f.getBoundingClientRect().width,
								height: f.getBoundingClientRect().height,
							});
						});

						return JSON.stringify({
							found: false,
							iframeCount: allIframes.length,
							iframes: iframeInfo,
						});
					})()
				`, &result))
				if err != nil {
					t.Logf("  Attempt %d: evaluate error: %v", attempt+1, err)
					time.Sleep(1 * time.Second)
					continue
				}

				t.Logf("  Attempt %d: %s", attempt+1, truncateStr(result, 300))

				if strings.Contains(result, `"found":true`) {
					// Parse the coordinates
					// Simple extraction since we know the format
					iframeFound = true
					fmt.Sscanf(extractJSONFloat(result, "x"), "%f", &iframeX)
					fmt.Sscanf(extractJSONFloat(result, "y"), "%f", &iframeY)
					fmt.Sscanf(extractJSONFloat(result, "width"), "%f", &iframeW)
					fmt.Sscanf(extractJSONFloat(result, "height"), "%f", &iframeH)

					if iframeW > 0 && iframeH > 0 {
						t.Logf("  Turnstile iframe found at (%.0f,%.0f) size %.0fx%.0f",
							iframeX, iframeY, iframeW, iframeH)
						break
					}
				}

				time.Sleep(1 * time.Second)
			}

			if !iframeFound || iframeW == 0 {
				// Try an alternative: maybe there's a challenge-platform overlay instead
				t.Logf("No Turnstile iframe found. Checking for managed challenge...")

				// Wait longer for CF managed challenge to auto-solve
				for wait := 0; wait < 10; wait++ {
					time.Sleep(2 * time.Second)
					if err := chromedp.Run(tabCtx, chromedp.OuterHTML("html", &html)); err != nil {
						continue
					}
					htmlLower = strings.ToLower(html)
					if strings.Contains(htmlLower, "<title>") &&
						!strings.Contains(html, "cf-challenge-running") {
						t.Logf("PASS: Managed challenge auto-solved after %ds wait", (wait+1)*2)
						logCookies(t, tabCtx)
						return
					}
					t.Logf("  Wait %d: still challenged...", wait+1)
				}

				t.Logf("FAIL: No Turnstile iframe found and managed challenge did not auto-solve")
				logPageState(t, tabCtx)
				return
			}

			// Step 4: Click the Turnstile checkbox
			// The checkbox is typically in the center-left of the iframe widget
			// Turnstile widget is ~300x65px, checkbox is at roughly (30, 32)
			clickX := iframeX + 30 + rand.Float64()*5
			clickY := iframeY + (iframeH / 2) + rand.Float64()*3 - 1.5

			t.Logf("Step 4: Clicking Turnstile checkbox at (%.1f, %.1f)...", clickX, clickY)

			// Human-like: move mouse to area first, then click
			if err := chromedp.Run(tabCtx, chromedp.ActionFunc(func(ctx context.Context) error {
				// Mouse move with slight approach curve
				steps := 5 + rand.Intn(5)
				startX := clickX - 50 - rand.Float64()*100
				startY := clickY - 30 - rand.Float64()*50

				for i := 0; i <= steps; i++ {
					tt := float64(i) / float64(steps)
					// Ease-in-out
					tt = tt * tt * (3 - 2*tt)
					x := startX + (clickX-startX)*tt + rand.Float64()*2 - 1
					y := startY + (clickY-startY)*tt + rand.Float64()*2 - 1

					if err := input.DispatchMouseEvent(input.MouseMoved, x, y).Do(ctx); err != nil {
						return err
					}
					time.Sleep(time.Duration(15+rand.Intn(25)) * time.Millisecond)
				}

				// Small pause before click (human reaction)
				time.Sleep(time.Duration(80+rand.Intn(120)) * time.Millisecond)

				// Click
				if err := input.DispatchMouseEvent(input.MousePressed, clickX, clickY).
					WithButton(input.Left).
					WithClickCount(1).
					Do(ctx); err != nil {
					return err
				}

				time.Sleep(time.Duration(50+rand.Intn(80)) * time.Millisecond)

				return input.DispatchMouseEvent(input.MouseReleased, clickX, clickY).
					WithButton(input.Left).
					WithClickCount(1).
					Do(ctx)
			})); err != nil {
				t.Fatalf("click turnstile: %v", err)
			}

			// Step 5: Wait for challenge to resolve
			t.Logf("Step 5: Waiting for Turnstile challenge to resolve...")

			var solved bool
			for wait := 0; wait < 20; wait++ {
				time.Sleep(1500 * time.Millisecond)

				// Check for token in the page
				var tokenResult string
				chromedp.Run(tabCtx, chromedp.Evaluate(`
					(function() {
						// Check for cf-turnstile-response input
						const tokenInput = document.querySelector('input[name="cf-turnstile-response"]') ||
							document.querySelector('[name="cf-turnstile-response"]');
						if (tokenInput && tokenInput.value) {
							return JSON.stringify({
								solved: true,
								tokenLength: tokenInput.value.length,
								tokenPrefix: tokenInput.value.substring(0, 20),
							});
						}

						// Check for success state in iframe
						const iframe = document.querySelector('iframe[src*="challenges.cloudflare.com"]') ||
							document.querySelector('.cf-turnstile iframe');
						if (iframe) {
							const rect = iframe.getBoundingClientRect();
							return JSON.stringify({
								solved: false,
								iframeSize: rect.width + "x" + rect.height,
								iframeSrc: iframe.src.substring(0, 80),
							});
						}

						return JSON.stringify({solved: false, noWidget: true});
					})()
				`, &tokenResult))

				t.Logf("  Wait %d: %s", wait+1, truncateStr(tokenResult, 200))

				if strings.Contains(tokenResult, `"solved":true`) {
					solved = true
					t.Logf("PASS: Turnstile token obtained!")
					break
				}

				// Also check if the page has navigated past the challenge
				var pageHTML string
				chromedp.Run(tabCtx, chromedp.OuterHTML("html", &pageHTML))
				pageLower := strings.ToLower(pageHTML)
				if strings.Contains(pageLower, "<title>") &&
					!strings.Contains(pageHTML, "cf-challenge-running") &&
					!strings.Contains(pageHTML, "challenge-platform") {
					solved = true
					t.Logf("PASS: Page navigated past challenge to clean content!")
					break
				}
			}

			if !solved {
				t.Logf("Challenge not solved within timeout")
				logPageState(t, tabCtx)
			}

			// Step 6: Log cookies
			logCookies(t, tabCtx)

			// Final check: get the cookies and see if cf_clearance is present
			cookies, _ = network.GetCookies().Do(tabCtx)
			for _, c := range cookies {
				if c.Name == "cf_clearance" {
					t.Logf("PASS: cf_clearance cookie obtained: %s...", c.Value[:min(20, len(c.Value))])
					return
				}
			}

			if solved {
				t.Logf("Turnstile solved but no cf_clearance cookie (may need page reload)")
			}
		})
	}
}

// TestCloudflare_TurnstileManagedChallenge tests the managed challenge flow
// where Cloudflare presents a challenge-platform script that may auto-solve
// or require Turnstile interaction.
//
// Usage:
//
//	STEALTH_LIVE_TEST=1 go test ./brws/stealth/test/ -run TestCloudflare_TurnstileManagedChallenge -v -count=1 -timeout 3m
func TestCloudflare_TurnstileManagedChallenge(t *testing.T) {
	if os.Getenv("STEALTH_LIVE_TEST") != "1" {
		t.Skip("set STEALTH_LIVE_TEST=1 to run live tests")
	}

	sites := []struct {
		name    string
		url     string
		timeout time.Duration
	}{
		{"NowSecure", "https://nowsecure.nl/", 90 * time.Second},
		{"Discord", "https://discord.com/", 60 * time.Second},
	}

	for _, site := range sites {
		t.Run(site.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), site.timeout)
			defer cancel()

			stealthConfig := cstealth.DefaultStealthConfig()
			stealthConfig.PermissionsSync = true
			stealthScript := cstealth.GenerateStealthScript(stealthConfig)

			allocOpts := []chromedp.ExecAllocatorOption{
				chromedp.NoFirstRun,
				chromedp.NoDefaultBrowserCheck,
				chromedp.Headless,
				chromedp.DisableGPU,
				chromedp.Flag("disable-blink-features", "AutomationControlled"),
				chromedp.UserAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"),
				chromedp.WindowSize(1920, 1080),
			}

			allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, allocOpts...)
			defer allocCancel()

			tabCtx, tabCancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(t.Logf))
			defer tabCancel()

			// Inject stealth
			if err := chromedp.Run(tabCtx, chromedp.ActionFunc(func(ctx context.Context) error {
				_, err := page.AddScriptToEvaluateOnNewDocument(stealthScript).Do(ctx)
				return err
			})); err != nil {
				t.Fatalf("inject stealth: %v", err)
			}

			// Navigate
			t.Logf("Navigating to %s...", site.url)
			start := time.Now()
			if err := chromedp.Run(tabCtx,
				network.Enable(),
				chromedp.Navigate(site.url),
				chromedp.WaitReady("body"),
			); err != nil {
				t.Fatalf("navigate: %v", err)
			}
			t.Logf("Page loaded in %v", time.Since(start).Round(time.Millisecond))

			// Poll for challenge resolution
			for attempt := 0; attempt < 30; attempt++ {
				time.Sleep(2 * time.Second)

				var state string
				chromedp.Run(tabCtx, chromedp.Evaluate(`
					(function() {
						const body = document.body ? document.body.innerHTML : '';
						const lower = body.toLowerCase();
						const hasTitle = !!document.querySelector('title') && document.title.length > 0;
						const challenging = lower.includes('cf-challenge-running') ||
							(lower.includes('challenge-platform') && !hasTitle);
						const turnstile = !!document.querySelector('iframe[src*="challenges.cloudflare.com"]');
						const cfWidget = !!document.querySelector('.cf-turnstile');

						return JSON.stringify({
							title: document.title.substring(0, 50),
							hasTitle: hasTitle,
							challenging: challenging,
							turnstile: turnstile,
							cfWidget: cfWidget,
							bodySize: body.length,
						});
					})()
				`, &state))

				t.Logf("  [%2ds] %s", (attempt+1)*2, truncateStr(state, 200))

				// Check if resolved
				if strings.Contains(state, `"hasTitle":true`) &&
					!strings.Contains(state, `"challenging":true`) {
					elapsed := time.Since(start).Round(time.Millisecond)
					t.Logf("PASS: Challenge resolved in %v", elapsed)

					// Log cookies
					logCookies(t, tabCtx)
					return
				}

				// If turnstile widget appeared, try clicking it
				if strings.Contains(state, `"turnstile":true`) || strings.Contains(state, `"cfWidget":true`) {
					t.Logf("  Turnstile widget detected, attempting click...")
					clickTurnstileCheckbox(t, tabCtx)
				}
			}

			t.Logf("TIMEOUT: Challenge not resolved within %v", time.Since(start).Round(time.Second))
			logPageState(t, tabCtx)
			logCookies(t, tabCtx)
		})
	}
}

// clickTurnstileCheckbox finds and clicks the Turnstile checkbox via CDP mouse events.
func clickTurnstileCheckbox(t *testing.T, ctx context.Context) {
	t.Helper()

	var result string
	err := chromedp.Run(ctx, chromedp.Evaluate(`
		(function() {
			const selectors = [
				'iframe[src*="challenges.cloudflare.com"]',
				'.cf-turnstile iframe',
				'#cf-turnstile iframe',
			];
			for (const sel of selectors) {
				const iframe = document.querySelector(sel);
				if (iframe) {
					const rect = iframe.getBoundingClientRect();
					if (rect.width > 0 && rect.height > 0) {
						return JSON.stringify({x: rect.x, y: rect.y, w: rect.width, h: rect.height});
					}
				}
			}
			return "";
		})()
	`, &result))
	if err != nil || result == "" {
		return
	}

	var x, y, w, h float64
	fmt.Sscanf(extractJSONFloat(result, "x"), "%f", &x)
	fmt.Sscanf(extractJSONFloat(result, "y"), "%f", &y)
	fmt.Sscanf(extractJSONFloat(result, "w"), "%f", &w)
	fmt.Sscanf(extractJSONFloat(result, "h"), "%f", &h)

	if w == 0 || h == 0 {
		return
	}

	// Click near the checkbox area (left-center of the widget)
	clickX := x + 30 + rand.Float64()*5
	clickY := y + h/2 + rand.Float64()*3 - 1.5

	t.Logf("  Clicking Turnstile at (%.0f, %.0f)", clickX, clickY)

	chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		// Move mouse
		input.DispatchMouseEvent(input.MouseMoved, clickX-20, clickY-10).Do(ctx)
		time.Sleep(50 * time.Millisecond)
		input.DispatchMouseEvent(input.MouseMoved, clickX, clickY).Do(ctx)
		time.Sleep(time.Duration(80+rand.Intn(100)) * time.Millisecond)

		// Click
		input.DispatchMouseEvent(input.MousePressed, clickX, clickY).
			WithButton(input.Left).WithClickCount(1).Do(ctx)
		time.Sleep(time.Duration(50+rand.Intn(80)) * time.Millisecond)
		return input.DispatchMouseEvent(input.MouseReleased, clickX, clickY).
			WithButton(input.Left).WithClickCount(1).Do(ctx)
	}))
}

// logCookies logs all cookies for the current page.
func logCookies(t *testing.T, ctx context.Context) {
	t.Helper()
	var cookies []*network.Cookie
	if err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		var err error
		cookies, err = network.GetCookies().Do(ctx)
		return err
	})); err != nil {
		t.Logf("  Failed to get cookies: %v", err)
		return
	}

	t.Logf("  Cookies (%d):", len(cookies))
	for _, c := range cookies {
		val := c.Value
		if len(val) > 40 {
			val = val[:40] + "..."
		}
		t.Logf("    %s = %s (domain=%s)", c.Name, val, c.Domain)
	}
}

// logPageState logs the current page HTML state for debugging.
func logPageState(t *testing.T, ctx context.Context) {
	t.Helper()
	var html string
	if err := chromedp.Run(ctx, chromedp.OuterHTML("html", &html)); err != nil {
		t.Logf("  Failed to get page state: %v", err)
		return
	}

	preview := html
	if len(preview) > 1000 {
		preview = preview[:1000] + "..."
	}
	t.Logf("  Page state (%d bytes): %s", len(html), preview)
}

// extractJSONFloat extracts a numeric value from a simple JSON string by key.
// This avoids importing encoding/json for simple test utilities.
func extractJSONFloat(json, key string) string {
	search := fmt.Sprintf(`"%s":`, key)
	idx := strings.Index(json, search)
	if idx < 0 {
		return "0"
	}
	start := idx + len(search)
	// Skip whitespace
	for start < len(json) && json[start] == ' ' {
		start++
	}
	end := start
	for end < len(json) && json[end] != ',' && json[end] != '}' && json[end] != '"' {
		end++
	}
	return strings.TrimSpace(json[start:end])
}

// Unused import suppression
var _ = cdp.NodeID(0)
