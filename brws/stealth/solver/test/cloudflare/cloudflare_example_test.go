package cloudflare_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/skunkworq/stealth/brws/stealth/challenge"
	solverpkg "github.com/skunkworq/stealth/brws/stealth/solver"
	"github.com/skunkworq/stealth/brws/core/detection"
)

// TestCloudflareOnExampleCom fetches example.com, runs CF detection on the
// response, then exercises the full lab sword-vs-shield pipeline against
// the lab's reproduced challenge.
func TestCloudflareOnExampleCom(t *testing.T) {
	// ── Phase 1: Probe example.com for real Cloudflare presence ────────
	t.Log("=== Phase 1: Probing example.com ===")

	resp, err := http.Get("https://example.com")
	if err != nil {
		t.Logf("skipping external example.com probe: %v", err)
	} else {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		t.Logf("example.com status=%d server=%q cf-ray=%q content-length=%d",
			resp.StatusCode, resp.Header.Get("Server"), resp.Header.Get("Cf-Ray"), len(body))

		// Run DetectChallenge on the real response
		cfChallenge := challenge.DetectChallenge(resp.StatusCode, resp.Header, body)
		if cfChallenge != nil {
			t.Logf("Cloudflare challenge detected: type=%s ray=%s sitekey=%s",
				cfChallenge.Type, cfChallenge.RayID, cfChallenge.SiteKey)
			if cfChallenge.PoWParams != nil {
				t.Logf("  PoW params: prefix=%s... difficulty=%d algo=%s",
					cfChallenge.PoWParams.Prefix[:16], cfChallenge.PoWParams.Difficulty, cfChallenge.PoWParams.Algorithm)
			}
		} else {
			t.Log("No Cloudflare challenge on example.com (expected — it's not behind CF)")
		}

		isCF := challenge.IsCloudflarePage(resp.Header)
		t.Logf("IsCloudflarePage: %v", isCF)

		// ── Phase 2: Run CloudflareDetector analysis on example.com request ──
		t.Log("\n=== Phase 2: CloudflareDetector signal analysis ===")

		cfDetector := detection.NewCloudflareDetector()

		probeReq, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
		probeReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9")
		probeReq.Header.Set("Accept-Language", "en-US,en;q=0.9")
		probeReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		signals := cfDetector.AnalyzeRequest(probeReq)
		score := cfDetector.ScoreRequest(probeReq)
		t.Logf("CF detector score: %.2f (%d signals)", score, len(signals))
		for _, s := range signals {
			t.Logf("  signal: %s score=%.2f", s.Name, s.Score)
		}
	}

	// ── Phase 3: Full lab sword-vs-shield exercise ─────────────────────
	t.Log("\n=== Phase 3: Lab sword-vs-shield (all 3 challenge types) ===")

	ts, cc := mountCloudflareLabServer()
	defer ts.Close()

	solver := solverpkg.NewCloudflareSolverClient()

	// 3a. JS Challenge
	t.Log("\n--- 3a: JS Challenge ---")
	jsResult, err := solver.SolveJSChallenge(ts.URL)
	if err != nil {
		t.Fatalf("JS challenge failed: %v", err)
	}
	t.Logf("JS: passed=%v difficulty=%d iterations=%d pow=%dms total=%dms cookie=%v",
		jsResult.Passed, jsResult.PoWDifficulty, jsResult.PoWIterations,
		jsResult.PoWTimeMs, jsResult.TotalTimeMs, jsResult.ClearanceCookie != nil)
	if !jsResult.Passed {
		t.Error("JS challenge should pass")
	}

	// Verify cookie works
	if jsResult.ClearanceCookie != nil {
		valid := cc.ValidateClearanceCookie(jsResult.ClearanceCookie.Value)
		t.Logf("  clearance cookie valid: %v", valid)
	}

	// 3b. Managed Challenge (behavioral analysis is stochastic; retry up to 3 times)
	t.Log("\n--- 3b: Managed Challenge ---")
	var managedResult *solverpkg.CloudflareSolveResult
	for attempt := 1; attempt <= 3; attempt++ {
		managedResult, err = solver.SolveManagedChallenge(ts.URL)
		if err == nil && managedResult.Passed {
			break
		}
		t.Logf("  attempt %d: passed=%v err=%v", attempt, managedResult != nil && managedResult.Passed, err)
	}
	if err != nil {
		t.Fatalf("Managed challenge failed after retries: %v", err)
	}
	t.Logf("Managed: passed=%v difficulty=%d iterations=%d pow=%dms total=%dms",
		managedResult.Passed, managedResult.PoWDifficulty, managedResult.PoWIterations,
		managedResult.PoWTimeMs, managedResult.TotalTimeMs)
	if !managedResult.Passed {
		t.Error("Managed challenge should pass after retries")
	}

	// 3c. Turnstile Challenge
	t.Log("\n--- 3c: Turnstile Challenge ---")
	turnstileResult, err := solver.SolveTurnstileLab(ts.URL)
	if err != nil {
		t.Fatalf("Turnstile challenge failed: %v", err)
	}
	t.Logf("Turnstile: passed=%v token=%s... pow=%dms total=%dms",
		turnstileResult.Passed,
		truncate(turnstileResult.TurnstileToken, 24),
		turnstileResult.PoWTimeMs, turnstileResult.TotalTimeMs)
	if !turnstileResult.Passed {
		t.Error("Turnstile challenge should pass")
	}

	// ── Phase 4: Detection → reproduction round-trip ──────────────────
	t.Log("\n=== Phase 4: Detection ↔ Reproduction round-trip ===")

	// Fetch the lab challenge page
	challengeResp, err := http.Get(ts.URL + "/api/cloudflare/challenge")
	if err != nil {
		t.Fatalf("failed to fetch challenge page: %v", err)
	}
	challengeBody, _ := io.ReadAll(challengeResp.Body)
	challengeResp.Body.Close()

	t.Logf("Challenge page: status=%d server=%q cf-ray=%q",
		challengeResp.StatusCode, challengeResp.Header.Get("Server"),
		challengeResp.Header.Get("Cf-Ray"))

	// Run DetectChallenge on the lab page — should find a managed challenge
	labChallenge := challenge.DetectChallenge(
		challengeResp.StatusCode, challengeResp.Header, challengeBody)
	if labChallenge == nil {
		t.Fatal("DetectChallenge should detect the lab challenge page")
	}
	t.Logf("Detected: type=%s ray=%s", labChallenge.Type, labChallenge.RayID)

	if labChallenge.PoWParams != nil {
		t.Logf("  PoW params extracted: prefix=%s... difficulty=%d",
			labChallenge.PoWParams.Prefix[:16], labChallenge.PoWParams.Difficulty)
	} else {
		t.Error("expected PoW params to be extracted from challenge page")
	}

	// ── Phase 5: Stats ────────────────────────────────────────────────
	t.Log("\n=== Phase 5: Challenge statistics ===")
	stats := cc.GetStats()
	t.Logf("Stats: total=%v passed=%v solve_rate=%.0f%% by_type=%v",
		stats["total_sessions"], stats["passed"],
		stats["solve_rate"].(float64)*100, stats["by_type"])

	t.Log("\n=== All phases complete ===")
}

// mountCloudflareLabServer creates a full lab server with all CF endpoints.
func mountCloudflareLabServer() (*httptest.Server, *challenge.CloudflareChallenger) {
	cc := challenge.NewCloudflareChallenger(nil, nil)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/cloudflare/challenge", cc.HandleChallengePage)
	mux.HandleFunc("/api/cloudflare/init", cc.HandleInit)
	mux.HandleFunc("/api/cloudflare/solve/js", cc.HandleSolveJS)
	mux.HandleFunc("/api/cloudflare/solve/managed", cc.HandleSolveManaged)
	mux.HandleFunc("/api/cloudflare/solve/turnstile", cc.HandleSolveTurnstile)
	mux.HandleFunc("/api/cloudflare/turnstile/widget", cc.HandleTurnstileWidgetPage)
	mux.HandleFunc("/api/cloudflare/turnstile/siteverify", cc.HandleTurnstileSiteVerify)
	mux.HandleFunc("/turnstile/v0/siteverify", cc.HandleTurnstileSiteVerify)
	mux.HandleFunc("/api/cloudflare/verify", cc.HandleVerifyClearance)
	mux.HandleFunc("/api/cloudflare/status", cc.HandleStatus)
	mux.HandleFunc("/cdn-cgi/challenge-platform/h/g/cv/result/", cc.HandleChallengeCallback)

	return httptest.NewServer(mux), cc
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return fmt.Sprintf("%s...", s[:n])
}
