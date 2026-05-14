package stealth_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/skunkworq/stealth/brws/stealth/challenge"
	"github.com/skunkworq/stealth/brws/browser/engine"
	_ "github.com/skunkworq/stealth/brws/browser/engine/http/native" // register native engine
	"github.com/skunkworq/stealth/brws/browser/engine/profile"
)

// cfTarget is a site to test against.
type cfTarget struct {
	Name string
	URL  string
}

// knownCFTargets are sites known to be behind Cloudflare.
// These are public sites chosen because they use CF bot protection.
var knownCFTargets = []cfTarget{
	{"Cloudflare", "https://www.cloudflare.com"},
	{"Discord", "https://discord.com"},
	{"Canva", "https://www.canva.com"},
	{"Medium", "https://medium.com"},
	{"npm", "https://www.npmjs.com"},
}

// TestCloudflareDetection_BareGoHTTP tests if a bare Go http.Client gets
// detected/challenged by real Cloudflare-protected sites.
// This is the baseline — no stealth, no TLS spoofing, just raw Go.
func TestCloudflareDetection_BareGoHTTP(t *testing.T) {
	t.Log("=== Bare Go HTTP Client vs Cloudflare ===")
	t.Log("Testing with default Go TLS fingerprint, no stealth headers")
	t.Log("")

	client := &http.Client{Timeout: 15 * time.Second}

	results := make([]detectionResult, 0, len(knownCFTargets))

	for _, target := range knownCFTargets {
		result := probeWithHTTPClient(t, client, target, "bare-go")
		results = append(results, result)
	}

	printDetectionSummary(t, "Bare Go HTTP", results)
}

// TestCloudflareDetection_StealthHeaders tests with stealth headers but
// Go's default TLS fingerprint. This isolates whether header spoofing
// alone is enough to bypass CF.
func TestCloudflareDetection_StealthHeaders(t *testing.T) {
	t.Log("=== Stealth Headers (no TLS spoof) vs Cloudflare ===")
	t.Log("Testing with browser-like headers but Go TLS fingerprint")
	t.Log("")

	eng, err := engine.New("native", engine.Options{
		Timeout:     15 * time.Second,
		HTTP2:       true,
		Stealth:     true,
		StealthTLS:  false,
		ProfileName: "chrome-120-macos",
	})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer eng.Close()

	results := make([]detectionResult, 0, len(knownCFTargets))

	for _, target := range knownCFTargets {
		result := probeWithEngine(t, eng, target, "stealth-headers")
		results = append(results, result)
	}

	printDetectionSummary(t, "Stealth Headers Only", results)
}

// TestCloudflareDetection_FullStealth tests with stealth headers + TLS
// fingerprint spoofing via uTLS. This is our best HTTP-level stealth.
func TestCloudflareDetection_FullStealth(t *testing.T) {
	t.Log("=== Full Stealth (headers + TLS spoof) vs Cloudflare ===")
	t.Log("Testing with browser headers + uTLS Chrome fingerprint")
	t.Log("")

	eng, err := engine.New("native", engine.Options{
		Timeout:     15 * time.Second,
		HTTP2:       true,
		Stealth:     true,
		StealthTLS:  true,
		ProfileName: "chrome-120-macos",
	})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	defer eng.Close()

	results := make([]detectionResult, 0, len(knownCFTargets))

	for _, target := range knownCFTargets {
		result := probeWithEngine(t, eng, target, "full-stealth")
		results = append(results, result)
	}

	printDetectionSummary(t, "Full Stealth (headers+TLS)", results)
}

// TestCloudflareDetection_ProfileRotation tests multiple browser profiles
// against a single CF target to see if any profiles are better at evading.
func TestCloudflareDetection_ProfileRotation(t *testing.T) {
	t.Log("=== Profile Rotation vs Cloudflare ===")
	t.Log("Testing all available profiles against cloudflare.com")
	t.Log("")

	target := cfTarget{"Cloudflare", "https://www.cloudflare.com"}

	for _, profileName := range profiles.AvailableProfiles() {
		t.Run(profileName, func(t *testing.T) {
			eng, err := engine.New("native", engine.Options{
				Timeout:     15 * time.Second,
				HTTP2:       true,
				Stealth:     true,
				StealthTLS:  true,
				ProfileName: profileName,
			})
			if err != nil {
				t.Fatalf("Failed to create engine with profile %s: %v", profileName, err)
			}
			defer eng.Close()

			result := probeWithEngine(t, eng, target, profileName)
			t.Logf("profile=%-25s status=%d challenged=%v blocked=%v protocol=%s",
				profileName, result.StatusCode, result.Challenged, result.Blocked, result.Protocol)
		})
	}
}

// TestCloudflareDetection_SelfAnalysis runs our CloudflareDetector against
// the request headers each profile would send, scoring how likely CF would
// flag it — before ever hitting the network.
func TestCloudflareDetection_SelfAnalysis(t *testing.T) {
	t.Log("=== Self-Analysis: CloudflareDetector scoring our own profiles ===")
	t.Log("")

	cfDetector := challenge.NewCloudflareDetector()

	for _, profileName := range profiles.AvailableProfiles() {
		profile := profiles.GetByName(profileName)
		headers := profile.ToHeaders()

		req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		signals := cfDetector.AnalyzeRequest(req)
		score := cfDetector.ScoreRequest(req)

		sigNames := make([]string, 0, len(signals))
		for _, s := range signals {
			sigNames = append(sigNames, fmt.Sprintf("%s(%.1f)", s.Name, s.Score))
		}

		t.Logf("profile=%-25s cf_score=%.2f signals=[%s]",
			profileName, score, strings.Join(sigNames, ", "))
	}

	// Also test bare Go (no profile headers)
	bareReq, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	bareReq.Header.Set("User-Agent", "Go-http-client/2.0")
	bareSignals := cfDetector.AnalyzeRequest(bareReq)
	bareScore := cfDetector.ScoreRequest(bareReq)

	sigNames := make([]string, 0, len(bareSignals))
	for _, s := range bareSignals {
		sigNames = append(sigNames, fmt.Sprintf("%s(%.1f)", s.Name, s.Score))
	}
	t.Logf("profile=%-25s cf_score=%.2f signals=[%s]",
		"bare-go-http", bareScore, strings.Join(sigNames, ", "))
}

// TestCloudflareDetection_CompareAll runs all three configurations against
// all targets and produces a comparison matrix.
func TestCloudflareDetection_CompareAll(t *testing.T) {
	t.Log("=== Comparison Matrix: Bare vs Stealth Headers vs Full Stealth ===")
	t.Log("")

	configs := []struct {
		Name    string
		Stealth bool
		TLS     bool
		Profile string
	}{
		{"bare-go", false, false, ""},
		{"stealth-headers", true, false, "chrome-120-macos"},
		{"full-stealth-chrome", true, true, "chrome-120-macos"},
		{"full-stealth-firefox", true, true, "firefox-120-macos"},
	}

	// Header
	t.Logf("%-24s", "Target")
	for _, cfg := range configs {
		t.Logf("  %-22s", cfg.Name)
	}
	t.Log("")

	for _, target := range knownCFTargets {
		line := fmt.Sprintf("%-24s", target.Name)

		for _, cfg := range configs {
			var result detectionResult

			if !cfg.Stealth && !cfg.TLS {
				// Bare Go client
				client := &http.Client{Timeout: 15 * time.Second}
				result = probeWithHTTPClient(t, client, target, cfg.Name)
			} else {
				eng, err := engine.New("native", engine.Options{
					Timeout:     15 * time.Second,
					HTTP2:       true,
					Stealth:     cfg.Stealth,
					StealthTLS:  cfg.TLS,
					ProfileName: cfg.Profile,
				})
				if err != nil {
					t.Logf("  engine error: %v", err)
					continue
				}
				result = probeWithEngine(t, eng, target, cfg.Name)
				eng.Close()
			}

			status := "✓"
			if result.Challenged {
				status = "⚠ challenged"
			}
			if result.Blocked {
				status = "✗ blocked"
			}
			if result.Error != "" {
				status = "! error"
			}

			line += fmt.Sprintf("  %-22s", fmt.Sprintf("%d %s", result.StatusCode, status))
		}

		t.Log(line)
	}
}

// --- Helpers ---

// detectionResult captures what happened when we probed a target.
type detectionResult struct {
	Target        string
	Config        string
	StatusCode    int
	Protocol      string
	IsCF          bool // Response came from Cloudflare
	Challenged    bool // CF presented a challenge (JS/managed/turnstile)
	Blocked       bool // CF hard-blocked (403 with no challenge)
	ChallengeType string
	RayID         string
	Error         string
	Headers       http.Header
	BodySize      int
	TimingMs      int64
}

// probeWithHTTPClient probes a target using a raw http.Client.
func probeWithHTTPClient(t *testing.T, client *http.Client, target cfTarget, configName string) detectionResult {
	t.Helper()

	result := detectionResult{
		Target: target.Name,
		Config: configName,
	}

	start := time.Now()
	resp, err := client.Get(target.URL)
	result.TimingMs = time.Since(start).Milliseconds()

	if err != nil {
		result.Error = err.Error()
		t.Logf("[%s] %-12s ERROR: %v", configName, target.Name, err)
		return result
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	result.StatusCode = resp.StatusCode
	result.Headers = resp.Header
	result.BodySize = len(body)
	result.Protocol = resp.Proto
	result.RayID = resp.Header.Get("Cf-Ray")
	result.IsCF = challenge.IsCloudflarePage(resp.Header)

	// Run challenge detection
	cfChallenge := challenge.DetectChallenge(resp.StatusCode, resp.Header, body)
	if cfChallenge != nil {
		result.Challenged = cfChallenge.Type != challenge.ChallengeBlocked
		result.Blocked = cfChallenge.Type == challenge.ChallengeBlocked
		result.ChallengeType = string(cfChallenge.Type)
	}

	logProbeResult(t, result)
	return result
}

// probeWithEngine probes a target using the native engine.
func probeWithEngine(t *testing.T, eng engine.Engine, target cfTarget, configName string) detectionResult {
	t.Helper()

	result := detectionResult{
		Target: target.Name,
		Config: configName,
	}

	start := time.Now()
	resp, err := eng.Do(context.Background(), &engine.Request{
		Method:  "GET",
		URL:     target.URL,
		Timeout: 15 * time.Second,
	})
	result.TimingMs = time.Since(start).Milliseconds()

	if err != nil {
		result.Error = err.Error()
		t.Logf("[%s] %-12s ERROR: %v", configName, target.Name, err)
		return result
	}

	result.StatusCode = resp.Status
	result.BodySize = len(resp.Body)
	result.Protocol = resp.Protocol

	// Convert engine headers to http.Header for analysis
	httpHeaders := make(http.Header)
	for k, vals := range resp.Headers {
		for _, v := range vals {
			httpHeaders.Add(k, v)
		}
	}
	result.Headers = httpHeaders
	result.RayID = httpHeaders.Get("Cf-Ray")
	result.IsCF = challenge.IsCloudflarePage(httpHeaders)

	// Run challenge detection
	cfChallenge := challenge.DetectChallenge(resp.Status, httpHeaders, resp.Body)
	if cfChallenge != nil {
		result.Challenged = cfChallenge.Type != challenge.ChallengeBlocked
		result.Blocked = cfChallenge.Type == challenge.ChallengeBlocked
		result.ChallengeType = string(cfChallenge.Type)
	}

	logProbeResult(t, result)
	return result
}

func logProbeResult(t *testing.T, r detectionResult) {
	t.Helper()

	status := "PASS"
	if r.Challenged {
		status = fmt.Sprintf("CHALLENGED(%s)", r.ChallengeType)
	}
	if r.Blocked {
		status = "BLOCKED"
	}

	cfTag := ""
	if r.IsCF {
		cfTag = " [CF]"
	}

	t.Logf("[%-20s] %-12s status=%d %s proto=%s ray=%s body=%d timing=%dms%s",
		r.Config, r.Target, r.StatusCode, status,
		r.Protocol, r.RayID, r.BodySize, r.TimingMs, cfTag)
}

func printDetectionSummary(t *testing.T, configName string, results []detectionResult) {
	t.Helper()

	t.Log("")
	t.Logf("--- Summary: %s ---", configName)

	total := len(results)
	passed := 0
	challenged := 0
	blocked := 0
	errors := 0
	cfSites := 0

	for _, r := range results {
		if r.Error != "" {
			errors++
			continue
		}
		if r.IsCF {
			cfSites++
		}
		if r.Challenged {
			challenged++
		} else if r.Blocked {
			blocked++
		} else {
			passed++
		}
	}

	t.Logf("Total: %d | Passed: %d | Challenged: %d | Blocked: %d | Errors: %d | CF sites: %d",
		total, passed, challenged, blocked, errors, cfSites)

	if total-errors > 0 {
		passRate := float64(passed) / float64(total-errors) * 100
		t.Logf("Pass rate: %.0f%%", passRate)
	}
}
