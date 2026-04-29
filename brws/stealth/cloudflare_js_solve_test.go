package stealth

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/skunkworq/stealth/brws/stealth/challenge"
	"github.com/skunkworq/stealth/brws/browser/engine"
	_ "github.com/skunkworq/stealth/brws/browser/engine/chromium"
	_ "github.com/skunkworq/stealth/brws/browser/engine/native"
)

// TestCloudflare_AnalyzeChallengePages fetches sites that serve JS challenges
// and extracts/analyzes the challenge parameters to understand what's needed
// for server-side solving.
//
// Usage:
//
//	STEALTH_LIVE_TEST=1 go test ./brws/stealth/ -run TestCloudflare_AnalyzeChallengePages -v -count=1 -timeout 2m
func TestCloudflare_AnalyzeChallengePages(t *testing.T) {
	if os.Getenv("STEALTH_LIVE_TEST") != "1" {
		t.Skip("set STEALTH_LIVE_TEST=1 to run live tests")
	}

	urls := []string{
		"https://discord.com/",
		"https://medium.com/",
		"https://nowsecure.nl/",
	}

	// Use stealth TLS to get the challenge page (not a hard block)
	eng, err := engine.New("native", engine.Options{
		Stealth:     true,
		StealthTLS:  true,
		ProfileName: "chrome-120-macos",
		Timeout:     20 * time.Second,
	})
	if err != nil {
		t.Fatalf("create engine: %v", err)
	}
	defer eng.Close()

	for _, u := range urls {
		t.Run(u, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			resp, err := eng.Do(ctx, &engine.Request{
				URL:     u,
				Timeout: 15 * time.Second,
			})
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}

			body := string(resp.Body)
			bodyLower := strings.ToLower(body)

			t.Logf("Status: %d, Body: %d bytes", resp.Status, len(resp.Body))

			// Log key headers
			for _, h := range []string{"Server", "Cf-Ray", "Cf-Mitigated", "Set-Cookie"} {
				if vals := resp.Headers[h]; len(vals) > 0 {
					for _, v := range vals {
						if h == "Set-Cookie" && len(v) > 80 {
							v = v[:80] + "..."
						}
						t.Logf("  %s: %s", h, v)
					}
				}
			}

			// Challenge detection
			httpHeaders := make(map[string][]string)
			for k, v := range resp.Headers {
				httpHeaders[k] = v
			}
			sig := challenge.ClassifyChallenge(resp.Body, httpHeaders)
			t.Logf("  Classifier: provider=%s interaction=%s confidence=%.2f",
				sig.Provider, sig.Interaction, sig.Confidence)

			// Check for _cf_chl_opt
			cfChlOptRe := regexp.MustCompile(`(?s)window\._cf_chl_opt\s*=\s*\{([^}]+)\}`)
			if matches := cfChlOptRe.FindStringSubmatch(body); len(matches) >= 2 {
				t.Logf("  _cf_chl_opt FOUND: %s", truncateStr(matches[1], 200))
			} else {
				t.Logf("  _cf_chl_opt: NOT FOUND")
			}

			// Check for challenge-platform script
			challengePlatformRe := regexp.MustCompile(`src="(/cdn-cgi/challenge-platform/[^"]+)"`)
			if matches := challengePlatformRe.FindAllStringSubmatch(body, -1); len(matches) > 0 {
				for _, m := range matches {
					t.Logf("  Challenge script: %s", m[1])
				}
			}

			// Check for Turnstile
			if strings.Contains(bodyLower, "cf-turnstile") {
				t.Logf("  Turnstile widget: FOUND")
				siteKeyRe := regexp.MustCompile(`data-sitekey="([^"]+)"`)
				if m := siteKeyRe.FindStringSubmatch(body); len(m) >= 2 {
					t.Logf("  Turnstile sitekey: %s", m[1])
				}
			}

			// Check for form action (submission URL)
			formActionRe := regexp.MustCompile(`action="([^"]+)"`)
			if matches := formActionRe.FindAllStringSubmatch(body, 5); len(matches) > 0 {
				for _, m := range matches {
					t.Logf("  Form action: %s", m[1])
				}
			}

			// Check what type of challenge this is
			markers := map[string]string{
				"challenge-platform":      "challenge-platform div/script",
				"cf-challenge":            "cf-challenge marker",
				"cf-turnstile":            "Turnstile widget",
				"jschl-answer":            "JS challenge answer field",
				"jschl_vc":                "JS challenge VC",
				"_cf_chl_opt":             "CF challenge options",
				"cf-browser-verification": "browser verification",
				"managed_challenge":       "managed challenge",
				"cf-chl-bypass":           "CF challenge bypass",
				"challenge-running":       "challenge running",
				"interstitialLoader":      "interstitial loader",
			}

			t.Logf("\n  Challenge markers:")
			for marker, desc := range markers {
				if strings.Contains(bodyLower, strings.ToLower(marker)) {
					t.Logf("    [x] %s (%s)", marker, desc)
				}
			}

			// Extract title
			titleRe := regexp.MustCompile(`<title>([^<]+)</title>`)
			if m := titleRe.FindStringSubmatch(body); len(m) >= 2 {
				t.Logf("  Page title: %s", m[1])
			}

			// Check for meta refresh redirect
			refreshRe := regexp.MustCompile(`<meta[^>]+http-equiv="refresh"[^>]+content="(\d+);[^"]*url=([^"]+)"`)
			if m := refreshRe.FindStringSubmatch(bodyLower); len(m) >= 3 {
				t.Logf("  Meta refresh: %ss -> %s", m[1], m[2])
			}

			// Summary
			hasChallengeScript := strings.Contains(body, "/cdn-cgi/challenge-platform/")
			hasTurnstile := strings.Contains(bodyLower, "cf-turnstile")
			hasPow := strings.Contains(body, "_cf_chl_opt")
			isJSOnly := hasChallengeScript && !hasTurnstile

			t.Logf("\n  Summary:")
			t.Logf("    Has challenge script: %v", hasChallengeScript)
			t.Logf("    Has Turnstile: %v", hasTurnstile)
			t.Logf("    Has PoW params: %v", hasPow)
			t.Logf("    JS-only (no Turnstile): %v", isJSOnly)
			if isJSOnly {
				t.Logf("    -> This is a JS execution challenge. Needs browser or script analysis.")
			}
			if hasTurnstile {
				t.Logf("    -> This has a Turnstile widget. Needs widget interaction or API solving.")
			}
		})
	}
}

// TestCloudflare_WaitAndRetrySolve tests the wait-and-retry approach for
// JS challenges. Some CF challenges just need a delay (simulating JS execution)
// and retry with cookies.
//
// Usage:
//
//	STEALTH_LIVE_TEST=1 go test ./brws/stealth/ -run TestCloudflare_WaitAndRetrySolve -v -count=1 -timeout 3m
func TestCloudflare_WaitAndRetrySolve(t *testing.T) {
	if os.Getenv("STEALTH_LIVE_TEST") != "1" {
		t.Skip("set STEALTH_LIVE_TEST=1 to run live tests")
	}

	sites := []struct {
		name string
		url  string
	}{
		{"Discord", "https://discord.com/"},
		{"NowSecure", "https://nowsecure.nl/"},
	}

	for _, site := range sites {
		t.Run(site.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()

			eng, err := engine.New("native", engine.Options{
				Stealth:     true,
				StealthTLS:  true,
				ProfileName: "chrome-120-macos",
				Timeout:     20 * time.Second,
			})
			if err != nil {
				t.Fatalf("create engine: %v", err)
			}
			defer eng.Close()

			// First request — get the challenge page
			resp, err := eng.Do(ctx, &engine.Request{
				URL:     site.url,
				Timeout: 15 * time.Second,
			})
			if err != nil {
				t.Fatalf("first request failed: %v", err)
			}

			body := strings.ToLower(string(resp.Body))
			hasChallengeMarker := strings.Contains(body, "challenge-platform") ||
				strings.Contains(body, "cf-challenge")
			isClean := resp.Status >= 200 && resp.Status < 400 && strings.Contains(body, "<title>") && !hasChallengeMarker

			t.Logf("First request: status=%d body=%d clean=%v challenged=%v",
				resp.Status, len(resp.Body), isClean, hasChallengeMarker)

			if isClean {
				t.Logf("PASS: Site returned clean response on first try")
				return
			}

			// Extract cookies from challenge response
			var cookies []string
			for k, vals := range resp.Headers {
				if strings.ToLower(k) == "set-cookie" {
					for _, v := range vals {
						parts := strings.SplitN(v, ";", 2)
						cookies = append(cookies, parts[0])
						t.Logf("  Cookie: %s", truncateStr(parts[0], 60))
					}
				}
			}

			// Wait (simulate JS challenge execution time)
			t.Logf("Waiting 5 seconds (simulating JS challenge)...")
			select {
			case <-time.After(5 * time.Second):
			case <-ctx.Done():
				t.Fatal("context cancelled")
			}

			// Retry with cookies
			extraHeaders := map[string]string{}
			if len(cookies) > 0 {
				extraHeaders["Cookie"] = strings.Join(cookies, "; ")
			}

			retryResp, err := eng.Do(ctx, &engine.Request{
				URL:          site.url,
				Timeout:      15 * time.Second,
				ExtraHeaders: extraHeaders,
			})
			if err != nil {
				t.Fatalf("retry request failed: %v", err)
			}

			retryBody := strings.ToLower(string(retryResp.Body))
			retryClean := retryResp.Status >= 200 && retryResp.Status < 400 &&
				strings.Contains(retryBody, "<title>") &&
				!strings.Contains(retryBody, "challenge-platform")

			t.Logf("Retry: status=%d body=%d clean=%v", retryResp.Status, len(retryResp.Body), retryClean)

			if retryClean {
				t.Logf("PASS: Wait-and-retry solved the challenge!")
			} else {
				t.Logf("FAIL: Wait-and-retry did NOT solve the challenge")
				t.Logf("  -> This challenge requires actual JS execution (browser needed)")
			}
		})
	}
}

// TestCloudflare_ChromiumSolve uses the chromium engine (real Chrome via CDP)
// to solve JS challenges that require JavaScript execution.
//
// Usage:
//
//	STEALTH_LIVE_TEST=1 go test ./brws/stealth/ -run TestCloudflare_ChromiumSolve -v -count=1 -timeout 5m
func TestCloudflare_ChromiumSolve(t *testing.T) {
	if os.Getenv("STEALTH_LIVE_TEST") != "1" {
		t.Skip("set STEALTH_LIVE_TEST=1 to run live tests")
	}

	sites := []struct {
		name    string
		url     string
		timeout time.Duration
	}{
		{"NowSecure", "https://nowsecure.nl/", 30 * time.Second},
		{"Discord", "https://discord.com/", 30 * time.Second},
	}

	for _, site := range sites {
		t.Run(site.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), site.timeout)
			defer cancel()

			eng, err := engine.New("chromium", engine.Options{
				Headless: true,
				Timeout:  site.timeout,
			})
			if err != nil {
				t.Fatalf("create chromium engine: %v", err)
			}
			defer eng.Close()

			t.Logf("Navigating with chromium engine (headless)...")

			resp, err := eng.Do(ctx, &engine.Request{
				URL:               site.url,
				Timeout:           site.timeout,
				WaitForNavigation: true,
			})
			if err != nil {
				t.Fatalf("chromium request failed: %v", err)
			}

			body := strings.ToLower(string(resp.Body))
			hasTitle := strings.Contains(body, "<title>")
			t.Logf("Status: %d, Body: %d bytes, FinalURL: %s", resp.Status, len(resp.Body), resp.FinalURL)

			if srv := resp.Headers["Server"]; len(srv) > 0 {
				t.Logf("Server: %s", srv[0])
			}

			// Check for active challenge (blocking overlay, not just string reference)
			hasActiveChallenge := strings.Contains(body, "cf-challenge-running") ||
				strings.Contains(body, "jschl-answer") ||
				(strings.Contains(body, "challenge-platform") && !hasTitle)

			isClean := resp.Status >= 200 && resp.Status < 400 && hasTitle && !hasActiveChallenge

			if isClean {
				t.Logf("PASS: Chromium solved the JS challenge! Clean page returned.")
			} else {
				if !hasTitle {
					t.Logf("WARN: No <title> tag in response")
				}
				if hasActiveChallenge {
					t.Logf("WARN: Active challenge detected (may need more wait time)")
				}
				if resp.Status >= 400 {
					t.Logf("WARN: Got error status %d", resp.Status)
				}
			}

			// Check for cf_clearance cookie
			for k, vals := range resp.Headers {
				if strings.ToLower(k) == "set-cookie" {
					for _, v := range vals {
						if strings.Contains(v, "cf_clearance") {
							t.Logf("  cf_clearance cookie: FOUND")
						}
					}
				}
			}

			// Check for real content signals
			contentSignals := []string{"<meta", "<script", "<link", "<!doctype"}
			contentCount := 0
			for _, sig := range contentSignals {
				if strings.Contains(body, sig) {
					contentCount++
				}
			}
			t.Logf("  Content signals: %d/%d (meta, script, link, doctype)", contentCount, len(contentSignals))
		})
	}
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
