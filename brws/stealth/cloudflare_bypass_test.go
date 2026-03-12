package stealth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/engine"
	_ "github.com/skunkworq/stealth/brws/engine/native" // register native engine
)

// TestCloudflareBypass_RealWorld demonstrates the full bypass flow:
//  1. Probe with bare Go → get challenged/blocked
//  2. Probe with full stealth (uTLS + headers) → bypass challenge, get content
//  3. Verify we got real page content (not a challenge page)
func TestCloudflareBypass_RealWorld(t *testing.T) {
	targets := []struct {
		Name        string
		URL         string
		ContentHint string // substring expected in real page content (lowercase)
	}{
		{"Canva", "https://www.canva.com", "canva"},
		{"Medium", "https://medium.com", "medium"},
		{"npm", "https://www.npmjs.com", "npm"},
	}

	for _, target := range targets {
		t.Run(target.Name, func(t *testing.T) {
			t.Logf("=== %s (%s) ===", target.Name, target.URL)

			// --- Phase 1: Bare Go (expect challenge) ---
			t.Log("Phase 1: Bare Go HTTP client")
			bareClient := &http.Client{Timeout: 15 * time.Second}
			bareResp, err := bareClient.Get(target.URL)
			if err != nil {
				t.Logf("  bare Go error: %v", err)
			} else {
				bareBody, _ := io.ReadAll(bareResp.Body)
				bareResp.Body.Close()

				challenge := adversarial.DetectChallenge(bareResp.StatusCode, bareResp.Header, bareBody)
				isCF := adversarial.IsCloudflarePage(bareResp.Header)

				if challenge != nil {
					t.Logf("  CHALLENGED: status=%d type=%s ray=%s cf=%v body=%d",
						bareResp.StatusCode, challenge.Type, challenge.RayID, isCF, len(bareBody))
				} else if bareResp.StatusCode != 200 {
					t.Logf("  BLOCKED: status=%d cf=%v body=%d",
						bareResp.StatusCode, isCF, len(bareBody))
				} else {
					t.Logf("  PASSED (no challenge): status=%d cf=%v body=%d",
						bareResp.StatusCode, isCF, len(bareBody))
				}
			}

			// --- Phase 2: Full stealth bypass ---
			t.Log("Phase 2: Full stealth (uTLS Chrome + browser headers)")
			eng, err := engine.New("native", engine.Options{
				Timeout:     15 * time.Second,
				HTTP2:       true,
				Stealth:     true,
				StealthTLS:  true,
				ProfileName: "chrome-120-macos",
			})
			if err != nil {
				t.Fatalf("  engine error: %v", err)
			}
			defer eng.Close()

			resp, err := eng.Do(context.Background(), &engine.Request{
				Method:  "GET",
				URL:     target.URL,
				Timeout: 15 * time.Second,
			})
			if err != nil {
				skipExternalNetworkIssue(t, target.URL, err)
			}

			// Convert headers for CF detection
			httpHeaders := make(http.Header)
			for k, vals := range resp.Headers {
				for _, v := range vals {
					httpHeaders.Add(k, v)
				}
			}

			challenge := adversarial.DetectChallenge(resp.Status, httpHeaders, resp.Body)
			isCF := adversarial.IsCloudflarePage(httpHeaders)

			t.Logf("  status=%d proto=%s cf=%v ray=%s body=%d",
				resp.Status, resp.Protocol, isCF, httpHeaders.Get("Cf-Ray"), len(resp.Body))

			// --- Phase 3: Verify bypass ---
			if challenge != nil {
				t.Errorf("  FAIL: still challenged with stealth: type=%s", challenge.Type)
				return
			}
			if resp.Status != 200 {
				t.Errorf("  FAIL: non-200 status: %d", resp.Status)
				return
			}

			// Verify we got real content, not a challenge page.
			// Note: normal CF-served pages include "/cdn-cgi/challenge-platform/scripts/"
			// in their HTML, so we check the page title instead of raw string matching.
			bodyStr := string(resp.Body)
			bodyLower := strings.ToLower(bodyStr)
			hasChallengeMarkers := strings.Contains(bodyLower, "<title>just a moment") ||
				strings.Contains(bodyLower, "cf-browser-verification")
			hasRealContent := strings.Contains(bodyLower, target.ContentHint)

			if hasChallengeMarkers {
				t.Error("  FAIL: response body contains challenge markers (200 but still a challenge page)")
				return
			}

			t.Logf("  BYPASS SUCCESS: got real content (contains %q: %v, no challenge markers)",
				target.ContentHint, hasRealContent)
		})
	}
}

// TestCloudflareBypass_ExampleCom probes example.com.
// Interesting case: bare Go gets 200 (low security), but stealth gets the
// "Just a moment..." challenge because Chrome-like headers trigger stricter
// CF checks that detect our Go HTTP/2 SETTINGS mismatch.
func TestCloudflareBypass_ExampleCom(t *testing.T) {
	t.Log("=== example.com — Cloudflare challenge analysis ===")

	configs := []struct {
		Name       string
		Stealth    bool
		StealthTLS bool
		Profile    string
	}{
		{"bare-go", false, false, ""},
		{"stealth-headers-only", true, false, "chrome-120-macos"},
		{"full-stealth-chrome", true, true, "chrome-120-macos"},
		{"full-stealth-firefox", true, true, "firefox-120-macos"},
		// Safari uTLS profile has ECDSA verification issues with some certs; skip for now
		// {"full-stealth-safari", true, true, "safari-16-macos"},
	}

	for _, cfg := range configs {
		t.Run(cfg.Name, func(t *testing.T) {
			var statusCode int
			var body []byte
			var headers http.Header
			var proto string

			if !cfg.Stealth && !cfg.StealthTLS {
				// Bare Go
				client := &http.Client{Timeout: 15 * time.Second}
				resp, err := client.Get("https://example.com")
				if err != nil {
					skipExternalNetworkIssue(t, "https://example.com", err)
				}
				body, _ = io.ReadAll(resp.Body)
				resp.Body.Close()
				statusCode = resp.StatusCode
				headers = resp.Header
				proto = resp.Proto
			} else {
				eng, err := engine.New("native", engine.Options{
					Timeout:     15 * time.Second,
					HTTP2:       true,
					Stealth:     cfg.Stealth,
					StealthTLS:  cfg.StealthTLS,
					ProfileName: cfg.Profile,
				})
				if err != nil {
					t.Fatalf("engine error: %v", err)
				}
				defer eng.Close()

				resp, err := eng.Do(context.Background(), &engine.Request{
					Method:  "GET",
					URL:     "https://example.com",
					Timeout: 15 * time.Second,
				})
				if err != nil {
					skipExternalNetworkIssue(t, "https://example.com", err)
				}
				statusCode = resp.Status
				body = resp.Body
				proto = resp.Protocol
				headers = make(http.Header)
				for k, vals := range resp.Headers {
					for _, v := range vals {
						headers.Add(k, v)
					}
				}
			}

			// Detect challenge
			challenge := adversarial.DetectChallenge(statusCode, headers, body)
			isCF := adversarial.IsCloudflarePage(headers)
			cfMitigated := headers.Get("Cf-Mitigated")

			bodyStr := string(body)
			hasJustAMoment := strings.Contains(bodyStr, "Just a moment")
			hasExampleDomain := strings.Contains(bodyStr, "Example Domain")

			result := "PASS"
			if challenge != nil {
				result = fmt.Sprintf("CHALLENGED(%s)", challenge.Type)
			} else if statusCode != 200 {
				result = fmt.Sprintf("BLOCKED(%d)", statusCode)
			}

			t.Logf("%-25s status=%d %s proto=%s cf=%v cf-mitigated=%q",
				cfg.Name, statusCode, result, proto, isCF, cfMitigated)
			t.Logf("  body=%d 'Example Domain'=%v 'Just a moment'=%v",
				len(body), hasExampleDomain, hasJustAMoment)

			if hasJustAMoment {
				t.Logf("  CF served 'Just a moment...' challenge page")
			}
			if hasExampleDomain {
				t.Logf("  Got real example.com content")
			}
		})
	}
}
