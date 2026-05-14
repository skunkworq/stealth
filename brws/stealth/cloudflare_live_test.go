package stealth

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/skunkworq/stealth/brws/browser/engine"
	_ "github.com/skunkworq/stealth/brws/browser/engine/http/native"
)

// findProjectRoot returns the absolute path to the project root.
func findProjectRoot(t *testing.T) string {
	t.Helper()
	_, f, _, _ := runtime.Caller(0)
	// cloudflare_live_test.go is in brws/stealth/, go up 2 levels
	return filepath.Join(filepath.Dir(f), "..", "..")
}

// TestCloudflare_LiveSites tests the stealth client against real Cloudflare-protected
// sites. Gated behind STEALTH_LIVE_TEST=1 since it hits real servers.
//
// Usage:
//
//	STEALTH_LIVE_TEST=1 go test ./brws/stealth/ -run TestCloudflare_LiveSites -v -count=1 -timeout 2m
func TestCloudflare_LiveSites(t *testing.T) {
	if os.Getenv("STEALTH_LIVE_TEST") != "1" {
		t.Skip("set STEALTH_LIVE_TEST=1 to run live tests")
	}

	sites := []struct {
		name string
		url  string
		// bodyNotContains are challenge markers that should NOT be in a clean response
		bodyNotContains []string
	}{
		{
			name: "Cloudflare Blog",
			url:  "https://blog.cloudflare.com/",
			bodyNotContains: []string{
				"cf-challenge-running",
				"challenge-platform",
				"jschl-answer",
			},
		},
		{
			name: "Cloudflare Radar",
			url:  "https://radar.cloudflare.com/",
			bodyNotContains: []string{
				"cf-challenge-running",
			},
		},
		{
			name: "Discord",
			url:  "https://discord.com/",
		},
		{
			name: "Medium",
			url:  "https://medium.com/",
		},
		{
			name: "Canva",
			url:  "https://www.canva.com/",
		},
		{
			name: "NowSecure",
			url:  "https://nowsecure.nl/",
		},
	}

	for _, site := range sites {
		t.Run(site.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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

			resp, err := eng.Do(ctx, &engine.Request{
				URL:     site.url,
				Timeout: 20 * time.Second,
			})
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}

			body := string(resp.Body)
			bodyLower := strings.ToLower(body)

			t.Logf("Status: %d, Body: %d bytes", resp.Status, len(resp.Body))

			if srv := resp.Headers["Server"]; len(srv) > 0 {
				t.Logf("Server: %s", srv[0])
			}
			if cfRay := resp.Headers["Cf-Ray"]; len(cfRay) > 0 {
				t.Logf("CF-Ray: %s", cfRay[0])
			}

			// Check we got a real page
			isSuccess := resp.Status >= 200 && resp.Status < 400
			hasTitle := strings.Contains(bodyLower, "<title>")

			if !isSuccess {
				preview := body
				if len(preview) > 500 {
					preview = preview[:500]
				}
				t.Logf("Non-success status %d\nBody preview: %s", resp.Status, preview)
			}

			if isSuccess && hasTitle {
				t.Logf("PASS: Got clean response with title")
			} else if isSuccess {
				t.Logf("WARN: Got %d but no <title> tag", resp.Status)
			} else {
				t.Logf("WARN: Got blocked with status %d", resp.Status)
			}

			// Check for challenge markers
			for _, unwanted := range site.bodyNotContains {
				if strings.Contains(bodyLower, strings.ToLower(unwanted)) {
					t.Errorf("body contains challenge marker %q — likely blocked", unwanted)
				}
			}
		})
	}
}

// TestCloudflare_LiveWithStealthClient tests the full stealth Client with evasion
// FSM, challenge detection, and captcha solving against real sites.
//
// Usage:
//
//	STEALTH_LIVE_TEST=1 go test ./brws/stealth/ -run TestCloudflare_LiveWithStealthClient -v -count=1 -timeout 3m
func TestCloudflare_LiveWithStealthClient(t *testing.T) {
	if os.Getenv("STEALTH_LIVE_TEST") != "1" {
		t.Skip("set STEALTH_LIVE_TEST=1 to run live tests")
	}

	sites := []struct {
		name string
		url  string
	}{
		{"Cloudflare Blog", "https://blog.cloudflare.com/"},
		{"Discord", "https://discord.com/"},
		{"Medium", "https://medium.com/"},
		{"Canva", "https://www.canva.com/"},
	}

	for _, site := range sites {
		t.Run(site.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Find project root for trace data
			traceDir := findProjectRoot(t) + "/training-data/traces"

			client, err := NewAdaptive(
				WithEngine("native"),
				WithStealth(true),
				WithEvasionFSM(),
				WithTraceLibrary(traceDir),
				WithLogging("info", false),
			)
			if err != nil {
				t.Fatalf("create client: %v", err)
			}
			// Enable auto-solve on the config directly
			client.config.Challenge.AutoDetect = true
			client.config.Challenge.AutoSolve = true

			resp, err := client.Navigate(ctx, site.url)
			if err != nil {
				t.Fatalf("navigate failed: %v", err)
			}

			t.Logf("Status: %d, Body: %d bytes, FinalURL: %s", resp.Status, len(resp.Body), resp.FinalURL)

			body := strings.ToLower(string(resp.Body))
			hasTitle := strings.Contains(body, "<title>")
			isSuccess := resp.Status >= 200 && resp.Status < 400

			if isSuccess && hasTitle {
				t.Logf("PASS: Got clean response")
			} else if !isSuccess {
				t.Logf("BLOCKED: Status %d", resp.Status)
			}

			challengeMarkers := []string{"cf-challenge-running", "challenge-platform", "jschl-answer"}
			for _, marker := range challengeMarkers {
				if strings.Contains(body, marker) {
					t.Logf("CHALLENGE: response contains %q", marker)
				}
			}

			// Report evasion FSM state
			if client.evasionFSM != nil {
				t.Logf("Evasion FSM: %s", client.evasionFSM.Summary())
				det, solves, failures := client.evasionFSM.CaptchaStats()
				if det > 0 {
					t.Logf("Captcha stats: detected=%d solved=%d failed=%d", det, solves, failures)
				}
			}
		})
	}
}

// TestCloudflare_LiveComparison compares stealth vs non-stealth requests
// to the same Cloudflare-protected sites.
//
// Usage:
//
//	STEALTH_LIVE_TEST=1 go test ./brws/stealth/ -run TestCloudflare_LiveComparison -v -count=1 -timeout 2m
func TestCloudflare_LiveComparison(t *testing.T) {
	if os.Getenv("STEALTH_LIVE_TEST") != "1" {
		t.Skip("set STEALTH_LIVE_TEST=1 to run live tests")
	}

	urls := []string{
		"https://blog.cloudflare.com/",
		"https://discord.com/",
		"https://www.canva.com/",
		"https://nowsecure.nl/",
	}

	type compResult struct {
		status     int
		bodySize   int
		hasTitle   bool
		challenged bool
	}

	label := func(r compResult) string {
		if r.status == -1 {
			return "(error)"
		}
		if r.challenged {
			return fmt.Sprintf("%d (challenged)", r.status)
		}
		if r.status >= 200 && r.status < 400 && r.hasTitle {
			return fmt.Sprintf("%d (clean)", r.status)
		}
		if r.status == 403 || r.status == 503 {
			return fmt.Sprintf("%d (blocked)", r.status)
		}
		return fmt.Sprintf("%d (%d bytes)", r.status, r.bodySize)
	}

	runWith := func(stealth bool) []compResult {
		eng, err := engine.New("native", engine.Options{
			Stealth:     stealth,
			StealthTLS:  stealth,
			ProfileName: "chrome-120-macos",
			Timeout:     20 * time.Second,
		})
		if err != nil {
			t.Fatalf("create engine (stealth=%v): %v", stealth, err)
		}
		defer eng.Close()

		var results []compResult
		for _, u := range urls {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			resp, err := eng.Do(ctx, &engine.Request{
				URL:     u,
				Timeout: 20 * time.Second,
			})
			cancel()

			r := compResult{}
			if err != nil {
				r.status = -1
			} else {
				r.status = resp.Status
				r.bodySize = len(resp.Body)
				body := strings.ToLower(string(resp.Body))
				r.hasTitle = strings.Contains(body, "<title>")
				r.challenged = strings.Contains(body, "challenge-platform") ||
					strings.Contains(body, "cf-challenge") ||
					strings.Contains(body, "jschl-answer")
			}
			results = append(results, r)
		}
		return results
	}

	plainResults := runWith(false)
	stealthResults := runWith(true)

	t.Logf("\n%-35s | %-20s | %-20s", "URL", "Plain (Go TLS)", "Stealth (uTLS)")
	t.Logf("%-35s-+-%-20s-+-%-20s", strings.Repeat("-", 35), strings.Repeat("-", 20), strings.Repeat("-", 20))

	for i, u := range urls {
		t.Logf("%-35s | %-20s | %-20s", u, label(plainResults[i]), label(stealthResults[i]))
	}
}
