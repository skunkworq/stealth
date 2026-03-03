package stealth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
)

// mountCloudflareServer creates a test server with all Cloudflare challenge endpoints.
func mountCloudflareServer() (*httptest.Server, *adversarial.CloudflareChallenger) {
	cc := adversarial.NewCloudflareChallenger(nil, nil)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/cloudflare/init", cc.HandleInit)
	mux.HandleFunc("/api/cloudflare/solve/js", cc.HandleSolveJS)
	mux.HandleFunc("/api/cloudflare/solve/managed", cc.HandleSolveManaged)
	mux.HandleFunc("/api/cloudflare/solve/turnstile", cc.HandleSolveTurnstile)
	mux.HandleFunc("/api/cloudflare/verify", cc.HandleVerifyClearance)
	mux.HandleFunc("/api/cloudflare/challenge", cc.HandleChallengePage)
	mux.HandleFunc("/api/cloudflare/status", cc.HandleStatus)

	ts := httptest.NewServer(mux)
	return ts, cc
}

func TestSwordSolvesJSChallenge(t *testing.T) {
	ts, _ := mountCloudflareServer()
	defer ts.Close()

	solver := NewCloudflareSolverClient()
	result, err := solver.SolveJSChallenge(ts.URL)
	if err != nil {
		t.Fatalf("SolveJSChallenge failed: %v", err)
	}

	if !result.Passed {
		t.Fatal("JS challenge should have passed")
	}
	if result.ClearanceCookie == nil {
		t.Fatal("expected clearance cookie")
	}
	if result.PoWTimeMs <= 0 {
		t.Error("PoW time should be > 0")
	}
	if result.PoWIterations <= 0 {
		t.Error("PoW iterations should be > 0")
	}
	if result.ChallengeType != "cloudflare_js" {
		t.Errorf("expected cloudflare_js, got %s", result.ChallengeType)
	}

	t.Logf("JS challenge: difficulty=%d iterations=%d pow_time=%dms total=%dms",
		result.PoWDifficulty, result.PoWIterations, result.PoWTimeMs, result.TotalTimeMs)
}

func TestSwordSolvesManagedChallenge(t *testing.T) {
	ts, _ := mountCloudflareServer()
	defer ts.Close()

	solver := NewCloudflareSolverClient()

	// Behavioral analysis is stochastic; retry up to 5 times for CI stability
	var result *CloudflareSolveResult
	var err error
	for attempt := 1; attempt <= 5; attempt++ {
		result, err = solver.SolveManagedChallenge(ts.URL)
		if err == nil && result.Passed {
			break
		}
		t.Logf("attempt %d: passed=%v err=%v", attempt, result != nil && result.Passed, err)
	}
	if err != nil {
		t.Fatalf("SolveManagedChallenge failed after retries: %v", err)
	}

	if !result.Passed {
		t.Fatal("managed challenge should have passed")
	}
	if result.ClearanceCookie == nil {
		t.Fatal("expected clearance cookie")
	}
	if result.ChallengeType != "cloudflare_managed" {
		t.Errorf("expected cloudflare_managed, got %s", result.ChallengeType)
	}

	t.Logf("Managed challenge: difficulty=%d iterations=%d pow_time=%dms total=%dms",
		result.PoWDifficulty, result.PoWIterations, result.PoWTimeMs, result.TotalTimeMs)
}

func TestSwordSolvesTurnstile(t *testing.T) {
	ts, _ := mountCloudflareServer()
	defer ts.Close()

	solver := NewCloudflareSolverClient()
	result, err := solver.SolveTurnstile(ts.URL)
	if err != nil {
		t.Fatalf("SolveTurnstile failed: %v", err)
	}

	if !result.Passed {
		t.Fatal("turnstile challenge should have passed")
	}
	if result.TurnstileToken == "" {
		t.Fatal("expected turnstile token")
	}
	if result.ClearanceCookie == nil {
		t.Fatal("expected clearance cookie")
	}
	if result.ChallengeType != "cloudflare_turnstile" {
		t.Errorf("expected cloudflare_turnstile, got %s", result.ChallengeType)
	}

	t.Logf("Turnstile challenge: token=%s... pow_time=%dms total=%dms",
		result.TurnstileToken[:20], result.PoWTimeMs, result.TotalTimeMs)
}

func TestSwordClearanceCookieReuse(t *testing.T) {
	ts, cc := mountCloudflareServer()
	defer ts.Close()

	solver := NewCloudflareSolverClient()
	result, err := solver.SolveJSChallenge(ts.URL)
	if err != nil {
		t.Fatalf("initial solve failed: %v", err)
	}

	if !result.Passed || result.ClearanceCookie == nil {
		t.Fatal("initial solve should pass with cookie")
	}

	// Verify the cookie is valid
	if !cc.ValidateClearanceCookie(result.ClearanceCookie.Value) {
		t.Fatal("clearance cookie should be valid")
	}

	// Make a verify request with the cookie
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/cloudflare/verify", nil)
	req.AddCookie(result.ClearanceCookie)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("verify request failed: %v", err)
	}
	defer resp.Body.Close()

	var verifyResp struct {
		Valid bool `json:"valid"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&verifyResp)

	if !verifyResp.Valid {
		t.Fatal("clearance cookie should be accepted by verify endpoint")
	}
}

func TestBotBehavioralRejection(t *testing.T) {
	ts, _ := mountCloudflareServer()
	defer ts.Close()

	solver := NewCloudflareSolverClient()

	// Init a managed challenge
	initResp, err := solver.initChallenge(ts.URL, "cloudflare_managed", 0.5, "")
	if err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Solve PoW correctly
	powSolution, err := solver.solvePoW(initResp.PoW.Prefix, initResp.PoW.Difficulty)
	if err != nil {
		t.Fatalf("PoW solve failed: %v", err)
	}

	// Generate valid fingerprint but send ZERO events
	fp := solver.generateFingerprint()

	body, _ := json.Marshal(map[string]interface{}{
		"session_id":  initResp.SessionID,
		"solution":    powSolution,
		"fingerprint": fp,
		"events":      []adversarial.CaptchaEvent{}, // empty!
	})

	// Use the solver's httpClient which has the __cf_bm cookie from init
	resp, err := solver.httpClient.Post(ts.URL+"/api/cloudflare/solve/managed", "application/json",
		bytes.NewReader(body))
	if err != nil {
		t.Fatalf("solve request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for zero events, got %d", resp.StatusCode)
	}

	var solveResp struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&solveResp)

	if solveResp.Success {
		t.Fatal("zero-event submission should be rejected")
	}
	t.Logf("correctly rejected: %s", solveResp.Error)
}

func TestEmptyFingerprintRejection(t *testing.T) {
	ts, _ := mountCloudflareServer()
	defer ts.Close()

	solver := NewCloudflareSolverClient()

	initResp, err := solver.initChallenge(ts.URL, "cloudflare_managed", 0.5, "")
	if err != nil {
		t.Fatalf("init failed: %v", err)
	}

	powSolution, err := solver.solvePoW(initResp.PoW.Prefix, initResp.PoW.Difficulty)
	if err != nil {
		t.Fatalf("PoW solve failed: %v", err)
	}

	// Generate some events but send nil fingerprint
	events := solver.eventGen.GenerateHumanEvents(3000)

	body, _ := json.Marshal(map[string]interface{}{
		"session_id":  initResp.SessionID,
		"solution":    powSolution,
		"fingerprint": nil, // empty!
		"events":      events,
	})

	// Use the solver's httpClient which has the __cf_bm cookie from init
	resp, err := solver.httpClient.Post(ts.URL+"/api/cloudflare/solve/managed", "application/json",
		bytes.NewReader(body))
	if err != nil {
		t.Fatalf("solve request failed: %v", err)
	}
	defer resp.Body.Close()

	// Nil fingerprint scores 1.0 × 0.30 = 0.30 contribution
	// Even with good behavioral, this combined with behavioral might push over threshold
	var solveResp struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&solveResp)

	if solveResp.Success {
		t.Fatal("nil fingerprint submission should be rejected")
	}
	t.Logf("correctly rejected: %s", solveResp.Error)
}

func TestDifficultyProgression(t *testing.T) {
	ts, _ := mountCloudflareServer()
	defer ts.Close()

	solver := NewCloudflareSolverClient()

	scores := []float64{0.1, 0.3, 0.5}
	prevDifficulty := 0

	for _, score := range scores {
		initResp, err := solver.initChallenge(ts.URL, "cloudflare_js", score, "")
		if err != nil {
			t.Fatalf("init failed for score %.1f: %v", score, err)
		}

		if initResp.PoW.Difficulty < prevDifficulty {
			t.Errorf("difficulty should increase: score=%.1f difficulty=%d < prev=%d",
				score, initResp.PoW.Difficulty, prevDifficulty)
		}
		prevDifficulty = initResp.PoW.Difficulty

		t.Logf("score=%.1f → difficulty=%d bits", score, initResp.PoW.Difficulty)
	}
}

func TestStatusEndpoint(t *testing.T) {
	ts, _ := mountCloudflareServer()
	defer ts.Close()

	solver := NewCloudflareSolverClient()

	// Solve a few challenges
	_, _ = solver.SolveJSChallenge(ts.URL)
	_, _ = solver.SolveTurnstile(ts.URL)

	resp, err := http.Get(ts.URL + "/api/cloudflare/status")
	if err != nil {
		t.Fatalf("status request failed: %v", err)
	}
	defer resp.Body.Close()

	var stats map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&stats)

	total := int(stats["total_sessions"].(float64))
	if total < 2 {
		t.Errorf("expected at least 2 sessions, got %d", total)
	}
	t.Logf("status: %+v", stats)
}

