package cloudflare_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/skunkworq/stealth/brws/stealth/challenge"
	solverpkg "github.com/skunkworq/stealth/brws/stealth/solver"
)

// mountProtectedServer creates a test server with CF protection wrapping actual content.
func mountProtectedServer(content string) (*httptest.Server, *challenge.CloudflareChallenger) {
	cc := challenge.NewCloudflareChallenger(nil, nil)

	mux := http.NewServeMux()

	// CF API endpoints (needed for solve flow)
	mux.HandleFunc("/api/cloudflare/init", cc.HandleInit)
	mux.HandleFunc("/api/cloudflare/solve/js", cc.HandleSolveJS)
	mux.HandleFunc("/api/cloudflare/solve/managed", cc.HandleSolveManaged)
	mux.HandleFunc("/api/cloudflare/solve/turnstile", cc.HandleSolveTurnstile)
	mux.HandleFunc("/api/cloudflare/verify", cc.HandleVerifyClearance)
	mux.HandleFunc("/api/cloudflare/challenge", cc.HandleChallengePage)
	mux.HandleFunc("/api/cloudflare/status", cc.HandleStatus)

	// Protected page: serves content only with valid cf_clearance
	contentHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(content))
	})
	mux.Handle("/protected", cc.HandleProtectedPage(contentHandler))

	ts := httptest.NewServer(mux)
	return ts, cc
}

func TestProtectedPage_NoCookie_ReturnsChallenge(t *testing.T) {
	ts, _ := mountProtectedServer("Welcome to the protected page")
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/protected")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Cf-Mitigated") != "challenge" {
		t.Error("expected Cf-Mitigated: challenge header")
	}
	if resp.Header.Get("Server") != "cloudflare" {
		t.Error("expected Server: cloudflare header")
	}
	if resp.Header.Get("X-Frame-Options") != "SAMEORIGIN" {
		t.Error("expected X-Frame-Options: SAMEORIGIN")
	}
	if resp.Header.Get("Cache-Control") == "" {
		t.Error("expected Cache-Control header")
	}

	// Check __cf_bm cookie
	var cfbm *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "__cf_bm" {
			cfbm = c
			break
		}
	}
	if cfbm == nil {
		t.Error("expected __cf_bm cookie")
	}

	t.Log("protected page correctly returns challenge page without clearance cookie")
}

func TestProtectedPage_WithValidCookie_ReturnsContent(t *testing.T) {
	expectedContent := "Welcome to the protected page"
	ts, cc := mountProtectedServer(expectedContent)
	defer ts.Close()

	// Solve a challenge to get a valid cookie
	solver := solverpkg.NewCloudflareSolverClient()
	result, err := solver.SolveJSChallenge(ts.URL)
	if err != nil {
		t.Fatalf("solve failed: %v", err)
	}
	if !result.Passed || result.ClearanceCookie == nil {
		t.Fatal("expected successful solve with cookie")
	}

	// Verify the cookie is valid
	if !cc.ValidateClearanceCookie(result.ClearanceCookie.Value) {
		t.Fatal("cookie should be valid")
	}

	// Request the protected page with the clearance cookie
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/protected", nil)
	req.AddCookie(result.ClearanceCookie)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var body [4096]byte
	n, _ := resp.Body.Read(body[:])
	if string(body[:n]) != expectedContent {
		t.Errorf("expected content %q, got %q", expectedContent, string(body[:n]))
	}

	t.Log("protected page returns content with valid clearance cookie")
}

func TestProtectedPage_ExpiredCookie_ReturnsChallenge(t *testing.T) {
	ts, _ := mountProtectedServer("Should not see this")
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "cf_clearance",
		Value: "fake_session.0.invalidsig",
	})

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for invalid cookie, got %d", resp.StatusCode)
	}
	t.Log("protected page rejects invalid/expired clearance cookie")
}

func TestDetectCFChallenge_FromResponse(t *testing.T) {
	headers := http.Header{
		"Server": {"cloudflare"},
		"Cf-Ray": {"abc123-LAB"},
	}
	body := []byte(`<!DOCTYPE html>
<html><head><title>Just a moment...</title></head>
<body>
  <div id="cf-browser-verification" class="cf-im-under-attack">
    <div id="cf-challenge-running" class="challenge-platform">
      <div class="managed_challenge" id="challenge-stage"></div>
    </div>
    <script>var _cf_chl_opt={"pow":{"prefix":"deadbeef","difficulty":10,"algorithm":"SHA-256"}};</script>
  </div>
</body></html>`)

	ch := challenge.DetectChallenge(503, headers, body)

	if ch == nil {
		t.Fatal("expected challenge to be detected")
	}
	if ch.Type != challenge.ChallengeManaged {
		t.Errorf("expected managed challenge, got %s", ch.Type)
	}
	if ch.RayID != "abc123-LAB" {
		t.Errorf("expected ray ID abc123-LAB, got %s", ch.RayID)
	}
	if ch.PoWParams == nil {
		t.Fatal("expected PoW params")
	}
	if ch.PoWParams.Prefix != "deadbeef" {
		t.Errorf("expected prefix deadbeef, got %s", ch.PoWParams.Prefix)
	}
	if ch.PoWParams.Difficulty != 10 {
		t.Errorf("expected difficulty 10, got %d", ch.PoWParams.Difficulty)
	}

	t.Logf("detected: %s", ch)
}

func TestDetectCFChallenge_NonCF_ReturnsNil(t *testing.T) {
	headers := http.Header{
		"Server": {"nginx"},
	}
	body := []byte(`<html><body>Normal page</body></html>`)

	ch := challenge.DetectChallenge(200, headers, body)
	if ch != nil {
		t.Errorf("expected nil for non-CF page, got %s", ch)
	}
}

func TestDetectCFChallenge_HardBlock(t *testing.T) {
	headers := http.Header{
		"Server": {"cloudflare"},
		"Cf-Ray": {"block123-LAB"},
	}
	body := []byte(`<html><body>Access denied</body></html>`)

	ch := challenge.DetectChallenge(403, headers, body)
	if ch == nil {
		t.Fatal("expected blocked challenge to be detected")
	}
	if ch.Type != challenge.ChallengeBlocked {
		t.Errorf("expected blocked, got %s", ch.Type)
	}
}

func TestSolverSubmitSolution_JSChallenge(t *testing.T) {
	ts, _ := mountCloudflareServer()
	defer ts.Close()

	solver := solverpkg.NewCloudflareSolverClient()

	// Init via HTTP to get __cf_bm cookie in the solver's jar
	initResp, err := solver.InitChallenge(ts.URL, "cloudflare_js", 0.3, "")
	if err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Solve the PoW
	powSolution, err := solver.SolvePoW(initResp.PoW.Prefix, initResp.PoW.Difficulty)
	if err != nil {
		t.Fatalf("PoW solve failed: %v", err)
	}

	// Use SubmitSolution
	ch := &challenge.CloudflareChallenge{
		Type:  challenge.ChallengeJS,
		RayID: initResp.SessionID,
	}
	cookie, err := solver.SubmitSolution(ts.URL, ch, powSolution, nil, nil)
	if err != nil {
		t.Fatalf("SubmitSolution failed: %v", err)
	}
	if cookie == nil {
		t.Fatal("expected clearance cookie")
	}
	if cookie.Name != "cf_clearance" {
		t.Errorf("expected cf_clearance cookie, got %s", cookie.Name)
	}

	t.Logf("SubmitSolution returned cookie: %s...", cookie.Value[:30])
}

func TestSolverSubmitSolution_ManagedChallenge(t *testing.T) {
	ts, _ := mountCloudflareServer()
	defer ts.Close()

	solver := solverpkg.NewCloudflareSolverClient()

	// Try up to 3 times since managed challenges are stochastic
	for attempt := 1; attempt <= 3; attempt++ {
		// Init via HTTP to get __cf_bm cookie in the solver's jar
		initResp, err := solver.InitChallenge(ts.URL, "cloudflare_managed", 0.3, "")
		if err != nil {
			t.Fatalf("init failed: %v", err)
		}

		// Wait for minimum solve time
		time.Sleep(1600 * time.Millisecond)

		powSolution, err := solver.SolvePoW(initResp.PoW.Prefix, initResp.PoW.Difficulty)
		if err != nil {
			t.Fatalf("PoW solve failed: %v", err)
		}

		fp := solver.GenerateFingerprint()
		events := solver.EventGen().GenerateHumanEvents(5000)

		ch := &challenge.CloudflareChallenge{
			Type:  challenge.ChallengeManaged,
			RayID: initResp.SessionID,
		}
		cookie, err := solver.SubmitSolution(ts.URL, ch, powSolution, fp, events)
		if err != nil {
			t.Logf("attempt %d failed (stochastic): %v", attempt, err)
			continue
		}
		if cookie == nil {
			t.Fatal("expected clearance cookie")
		}
		t.Logf("managed SubmitSolution succeeded on attempt %d", attempt)
		return
	}
	t.Fatal("managed SubmitSolution failed after 3 attempts")
}

func TestChallengeEscalation(t *testing.T) {
	cc := challenge.NewCloudflareChallenger(nil, nil)

	// Create a JS challenge
	session := cc.CreateJSChallenge("esc_test", 0.5)
	if session.State != challenge.StatePending {
		t.Errorf("expected pending, got %s", session.State)
	}

	// Escalate: JS → Managed
	escalated := cc.EscalateChallenge("esc_test")
	if escalated == nil {
		t.Fatal("expected escalated session")
	}
	if escalated.Type != challenge.ChallengeManaged {
		t.Errorf("expected managed after escalation, got %s", escalated.Type)
	}
	if escalated.EscalatedFrom != string(challenge.ChallengeJS) {
		t.Errorf("expected escalated from js_challenge, got %s", escalated.EscalatedFrom)
	}
	if escalated.State != challenge.StateEscalated {
		t.Errorf("expected escalated state, got %s", escalated.State)
	}

	// Escalate again: Managed → Blocked
	blocked := cc.EscalateChallenge(escalated.ID)
	if blocked == nil {
		t.Fatal("expected blocked session")
	}
	if blocked.Type != challenge.ChallengeBlocked {
		t.Errorf("expected blocked after double escalation, got %s", blocked.Type)
	}

	t.Log("escalation chain: JS → Managed → Blocked")
}

func TestSolveTimeBounds_TooFast(t *testing.T) {
	cc := challenge.NewCloudflareChallenger(nil, nil)

	// Create a managed challenge and immediately try to solve
	session := cc.CreateManagedChallenge("fast_test", 0.3)

	solution, err := challenge.SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, 50_000_000)
	if err != nil {
		t.Fatalf("PoW failed: %v", err)
	}

	fp := &challenge.FingerprintPayload{
		CanvasHash:          "test",
		WebGLVendor:         "Google Inc.",
		WebGLRenderer:       "ANGLE",
		Platform:            "Win32",
		Languages:           []string{"en-US"},
		HardwareConcurrency: 8,
		ScreenWidth:         1920,
		ScreenHeight:        1080,
		ColorDepth:          24,
		Timezone:            "America/New_York",
	}

	// Should fail because < 1500ms have elapsed
	_, err = cc.CompleteChallengeManaged("fast_test", solution, fp, nil)
	if err == nil {
		t.Fatal("expected rejection for too-fast solve")
	}
	t.Logf("correctly rejected: %v", err)
}

func TestSessionStateTracking(t *testing.T) {
	cc := challenge.NewCloudflareChallenger(nil, nil)

	session := cc.CreateJSChallenge("state_test", 0.3)
	if session.State != challenge.StatePending {
		t.Errorf("initial state should be pending, got %s", session.State)
	}

	solution, _ := challenge.SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, 50_000_000)
	_, err := cc.CompleteChallengeJS("state_test", solution)
	if err != nil {
		t.Fatalf("solve failed: %v", err)
	}

	solved, ok := cc.GetSession("state_test")
	if !ok {
		t.Fatal("session not found")
	}
	if solved.State != challenge.StateSolved {
		t.Errorf("expected solved state, got %s", solved.State)
	}
	if !solved.Passed {
		t.Error("expected Passed=true")
	}
}

func TestRealisticHeaders_ChallengePage(t *testing.T) {
	ts, _ := mountProtectedServer("content")
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/protected")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	checks := map[string]string{
		"Server":          "cloudflare",
		"Cf-Mitigated":    "challenge",
		"X-Frame-Options": "SAMEORIGIN",
	}
	for header, expected := range checks {
		got := resp.Header.Get(header)
		if got != expected {
			t.Errorf("header %s: expected %q, got %q", header, expected, got)
		}
	}
	if resp.Header.Get("Cf-Ray") == "" {
		t.Error("expected Cf-Ray header")
	}
	if resp.Header.Get("Cache-Control") == "" {
		t.Error("expected Cache-Control header")
	}

	t.Log("all realistic CF headers present on challenge page")
}

func TestRealisticHeaders_SolveRejection(t *testing.T) {
	ts, _ := mountCloudflareServer()
	defer ts.Close()

	solver := solverpkg.NewCloudflareSolverClient()

	initResp, _ := solver.InitChallenge(ts.URL, "cloudflare_managed", 0.5, "")

	body, _ := json.Marshal(map[string]interface{}{
		"session_id": initResp.SessionID,
		"solution": map[string]interface{}{
			"nonce":      "wrong",
			"hash":       "wrong",
			"iterations": 1,
			"time_ms":    1,
		},
		"fingerprint": nil,
		"events":      []interface{}{},
	})

	// Use the solver's HTTPClient() which has the __cf_bm cookie from init
	resp, err := solver.HTTPClient().Post(ts.URL+"/api/cloudflare/solve/managed", "application/json",
		bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("Cf-Mitigated") != "challenge" {
		t.Error("expected Cf-Mitigated: challenge on rejection")
	}
	if resp.Header.Get("Server") != "cloudflare" {
		t.Error("expected Server: cloudflare on rejection")
	}
}

func TestCFBMCookie_Generated(t *testing.T) {
	cc := challenge.NewCloudflareChallenger(nil, nil)

	session := cc.CreateManagedChallenge("cfbm_test", 0.5)
	if session.CFBMValue == "" {
		t.Fatal("expected CFBMValue to be set")
	}
	if len(session.CFBMValue) < 20 {
		t.Errorf("CFBMValue seems too short: %s", session.CFBMValue)
	}
	t.Logf("__cf_bm value: %s", session.CFBMValue)
}

func TestFullProtectedPageFlow(t *testing.T) {
	expectedContent := "Secret treasure behind CF wall"
	ts, _ := mountProtectedServer(expectedContent)
	defer ts.Close()

	solver := solverpkg.NewCloudflareSolverClient()

	// Step 1: Hit protected page, get challenge
	resp, err := http.Get(ts.URL + "/protected")
	if err != nil {
		t.Fatalf("step 1 failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
	}

	// Step 2: Solve challenge via the API
	result, err := solver.SolveJSChallenge(ts.URL)
	if err != nil {
		t.Fatalf("step 2 failed: %v", err)
	}
	if !result.Passed || result.ClearanceCookie == nil {
		t.Fatal("expected successful solve")
	}

	// Step 3: Retry protected page with clearance cookie
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/protected", nil)
	req.AddCookie(result.ClearanceCookie)

	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("step 3 failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != 200 {
		t.Fatalf("expected 200 after solve, got %d", resp2.StatusCode)
	}

	var buf [4096]byte
	n, _ := resp2.Body.Read(buf[:])
	if string(buf[:n]) != expectedContent {
		t.Errorf("expected %q, got %q", expectedContent, string(buf[:n]))
	}

	t.Log("full protected page flow: challenge → solve → content access")
}

// --- Phase 7: Sword Fingerprint Pinning Tests ---

func TestSolverFingerprint_PinnedAcrossCalls(t *testing.T) {
	solver := solverpkg.NewCloudflareSolverClient()

	fp1 := solver.GenerateFingerprint()
	fp2 := solver.GenerateFingerprint()
	fp3 := solver.GenerateFingerprint()

	// All calls should return the exact same fingerprint
	if fp1.CanvasHash != fp2.CanvasHash {
		t.Error("canvas hash changed between calls — fingerprint not pinned")
	}
	if fp1.WebGLRenderer != fp2.WebGLRenderer {
		t.Errorf("WebGL renderer changed: %q → %q", fp1.WebGLRenderer, fp2.WebGLRenderer)
	}
	if fp1.Platform != fp3.Platform {
		t.Errorf("platform changed: %q → %q", fp1.Platform, fp3.Platform)
	}
	if fp1.HardwareConcurrency != fp3.HardwareConcurrency {
		t.Errorf("hardware concurrency changed: %d → %d", fp1.HardwareConcurrency, fp3.HardwareConcurrency)
	}
	if fp1.DeviceMemory != fp3.DeviceMemory {
		t.Errorf("device memory changed: %.0f → %.0f", fp1.DeviceMemory, fp3.DeviceMemory)
	}
	if fp1.ScreenWidth != fp2.ScreenWidth || fp1.ScreenHeight != fp2.ScreenHeight {
		t.Errorf("screen dimensions changed: %dx%d → %dx%d",
			fp1.ScreenWidth, fp1.ScreenHeight, fp2.ScreenWidth, fp2.ScreenHeight)
	}
	if fp1.Timezone != fp2.Timezone {
		t.Errorf("timezone changed: %q → %q", fp1.Timezone, fp2.Timezone)
	}
	if fp1.ColorDepth != fp2.ColorDepth {
		t.Errorf("color depth changed: %d → %d", fp1.ColorDepth, fp2.ColorDepth)
	}

	// Verify it's the exact same pointer (not just equal)
	if fp1 != fp2 {
		t.Error("GenerateFingerprint should return the exact same pointer on subsequent calls")
	}

	t.Logf("pinned fingerprint: platform=%s, gpu=%s, %dx%d, tz=%s",
		fp1.Platform, fp1.WebGLRenderer, fp1.ScreenWidth, fp1.ScreenHeight, fp1.Timezone)
}

func TestSolverFingerprint_ResetClearsPin(t *testing.T) {
	solver := solverpkg.NewCloudflareSolverClient()

	fp1 := solver.GenerateFingerprint()
	solver.ResetFingerprint()
	fp2 := solver.GenerateFingerprint()

	// After reset, a new fingerprint is generated (may differ)
	if fp1 == fp2 {
		t.Error("after ResetFingerprint, pointer should differ (new fingerprint generated)")
	}
	t.Logf("pre-reset platform=%s, post-reset platform=%s", fp1.Platform, fp2.Platform)
}

func TestSolverFingerprint_CanvasIsValidPNG(t *testing.T) {
	solver := solverpkg.NewCloudflareSolverClient()
	fp := solver.GenerateFingerprint()

	if !strings.HasPrefix(fp.CanvasHash, "data:image/png;base64,") {
		t.Errorf("canvas hash should be data:image/png;base64,... got %q", fp.CanvasHash[:40])
	}

	// Decode and verify PNG signature
	b64 := fp.CanvasHash[len("data:image/png;base64,"):]
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("failed to decode canvas base64: %v", err)
	}
	if len(decoded) < 8 {
		t.Fatal("decoded PNG too short")
	}
	pngSig := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	if !bytes.Equal(decoded[:8], pngSig) {
		t.Error("decoded data doesn't have PNG signature")
	}
	t.Logf("canvas PNG: %d bytes", len(decoded))
}

func TestSolverFingerprint_TimezoneMatchesProfile(t *testing.T) {
	solver := solverpkg.NewCloudflareSolverClient()
	fp := solver.GenerateFingerprint()

	if fp.Timezone == "" {
		t.Error("timezone should be set from profile")
	}
	expectedOffset := solverpkg.TimezoneToOffset(fp.Timezone)
	if fp.TimezoneOffset != expectedOffset {
		t.Errorf("timezone offset mismatch: tz=%s expected=%d got=%d",
			fp.Timezone, expectedOffset, fp.TimezoneOffset)
	}
	t.Logf("timezone: %s → offset %d", fp.Timezone, fp.TimezoneOffset)
}

func TestSolverFingerprint_PassesShieldDriftCheck(t *testing.T) {
	// Verify that the pinned fingerprint produces zero drift when submitted twice
	// to the shield's fingerprint validator
	cc := challenge.NewCloudflareChallenger(nil, nil)
	cc.CreateManagedChallenge("pinned-test", 0.5)

	solver := solverpkg.NewCloudflareSolverClient()
	fp := solver.GenerateFingerprint()

	// First submission — binds
	score1 := cc.ValidateFingerprint("pinned-test", fp)
	// Second submission — same fp, should produce zero drift
	score2 := cc.ValidateFingerprint("pinned-test", fp)

	drift := cc.GetFingerprintDrift("pinned-test")
	if drift != 0.0 {
		t.Errorf("pinned fingerprint should produce zero drift, got %.4f", drift)
	}
	t.Logf("first score=%.2f, second score=%.2f, drift=%.4f", score1, score2, drift)
}

// --- Phase 8: Bug Fix Validation Tests ---

func TestTimezoneToOffset_KnownTimezones(t *testing.T) {
	tests := []struct {
		tz     string
		offset int
	}{
		{"America/New_York", -300},
		{"America/Chicago", -360},
		{"America/Los_Angeles", -480},
		{"Europe/London", 0},
		{"Europe/Berlin", 60},
		{"Asia/Tokyo", 540},
		{"Asia/Shanghai", 480},
		{"Australia/Sydney", 660},
	}

	for _, tt := range tests {
		got := solverpkg.TimezoneToOffset(tt.tz)
		if got != tt.offset {
			t.Errorf("TimezoneToOffset(%q) = %d, want %d", tt.tz, got, tt.offset)
		}
	}
}

func TestTimezoneToOffset_UnknownFallback(t *testing.T) {
	got := solverpkg.TimezoneToOffset("Mars/Olympus_Mons")
	if got != -300 {
		t.Errorf("unknown timezone should default to -300, got %d", got)
	}
}
