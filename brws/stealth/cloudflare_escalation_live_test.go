package stealth

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/skunkworq/stealth/brws/browser/engine"
	_ "github.com/skunkworq/stealth/brws/browser/engine/chromium"
	_ "github.com/skunkworq/stealth/brws/browser/engine/native"
	wf "github.com/skunkworq/stealth/brws/browser/engine/waterfall"
)

// TestCloudflare_WaterfallEscalation tests the full escalation path:
// 1. Native engine (uTLS) makes request
// 2. Gets JS challenge that can't be solved without browser
// 3. Evasion FSM detects unsolvable challenge and escalates
// 4. Waterfall promotes to chromium tier
// 5. Chromium engine solves the JS challenge via real browser
//
// Usage:
//
//	STEALTH_LIVE_TEST=1 go test ./brws/stealth/ -run TestCloudflare_WaterfallEscalation -v -count=1 -timeout 3m
func TestCloudflare_WaterfallEscalation(t *testing.T) {
	if os.Getenv("STEALTH_LIVE_TEST") != "1" {
		t.Skip("set STEALTH_LIVE_TEST=1 to run live tests")
	}

	// Build a waterfall with HTTP (native) → chromium escalation
	httpEng, err := engine.New("native", engine.Options{
		Stealth:     true,
		StealthTLS:  true,
		ProfileName: "chrome-120-macos",
		Timeout:     15 * time.Second,
	})
	if err != nil {
		t.Fatalf("create native engine: %v", err)
	}
	defer httpEng.Close()

	chromiumEng, err := engine.New("chromium", engine.Options{
		Headless: true,
		Timeout:  30 * time.Second,
	})
	if err != nil {
		t.Fatalf("create chromium engine: %v", err)
	}
	defer chromiumEng.Close()

	// Create waterfall: http first, chromium as escalation target
	waterfall, err := wf.New(
		wf.Tier{Name: "http", Engine: httpEng, LaunchAfter: 0},
		wf.Tier{Name: "chromium", Engine: chromiumEng, LaunchAfter: 10 * time.Second},
	)
	if err != nil {
		t.Fatalf("create waterfall: %v", err)
	}

	sites := []struct {
		name string
		url  string
	}{
		{"NowSecure", "https://nowsecure.nl/"},
		{"Discord", "https://discord.com/"},
	}

	for _, site := range sites {
		t.Run(site.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()

			// Step 1: Try with HTTP tier first
			t.Logf("Step 1: HTTP (native + uTLS) request...")
			resp, err := waterfall.Do(ctx, &engine.Request{
				URL:     site.url,
				Timeout: 15 * time.Second,
			})
			if err != nil {
				t.Fatalf("HTTP request failed: %v", err)
			}

			body := strings.ToLower(string(resp.Body))
			hasTitle := strings.Contains(body, "<title>")
			hasActiveChallenge := (strings.Contains(body, "cf-challenge-running") ||
				strings.Contains(body, "jschl-answer")) ||
				(strings.Contains(body, "challenge-platform") && !hasTitle)

			t.Logf("  HTTP: status=%d body=%d title=%v active_challenge=%v",
				resp.Status, len(resp.Body), hasTitle, hasActiveChallenge)

			if hasTitle && !hasActiveChallenge {
				t.Logf("  HTTP tier solved it! No escalation needed.")
				return
			}

			// Step 2: JS challenge detected — escalate to chromium
			t.Logf("Step 2: JS challenge detected, promoting to chromium tier...")
			waterfall.PromoteTier("chromium")

			resp, err = waterfall.Do(ctx, &engine.Request{
				URL:               site.url,
				Timeout:           30 * time.Second,
				WaitForNavigation: true,
			})
			if err != nil {
				t.Fatalf("Chromium request failed: %v", err)
			}

			body = strings.ToLower(string(resp.Body))
			hasTitle = strings.Contains(body, "<title>")
			hasActiveChallenge = strings.Contains(body, "cf-challenge-running") ||
				(strings.Contains(body, "challenge-platform") && !hasTitle)

			t.Logf("  Chromium: status=%d body=%d title=%v active_challenge=%v",
				resp.Status, len(resp.Body), hasTitle, hasActiveChallenge)

			if hasTitle && !hasActiveChallenge {
				t.Logf("PASS: Chromium tier solved the JS challenge!")
			} else {
				t.Errorf("FAIL: Chromium tier did not solve the challenge")
			}
		})
	}
}
