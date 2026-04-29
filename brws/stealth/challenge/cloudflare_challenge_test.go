package challenge

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPoWValidation_Valid(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)
	session := cc.CreateJSChallenge("test-pow-valid", 0.3)

	// Solve the PoW
	solution, err := SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, session.PoW.MaxIterations)
	if err != nil {
		t.Fatalf("failed to solve PoW: %v", err)
	}

	// Validate
	if err := cc.ValidatePoW("test-pow-valid", solution); err != nil {
		t.Fatalf("valid PoW rejected: %v", err)
	}

	// Verify the hash actually has the required leading zero bits
	data := session.PoW.Prefix + solution.Nonce
	hash := sha256.Sum256([]byte(data))
	if !hasLeadingZeroBits(hash[:], session.PoW.Difficulty) {
		t.Errorf("solution hash doesn't have %d leading zero bits", session.PoW.Difficulty)
	}

	t.Logf("PoW solved: difficulty=%d iterations=%d time=%dms",
		session.PoW.Difficulty, solution.Iterations, solution.TimeMs)
}

func TestPoWValidation_Invalid(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)
	cc.CreateJSChallenge("test-pow-invalid", 0.3)

	badSolution := &PoWSolution{
		Nonce: "0000000000000000",
		Hash:  "ffffffffffffffff",
	}

	if err := cc.ValidatePoW("test-pow-invalid", badSolution); err == nil {
		t.Fatal("expected invalid PoW to be rejected")
	}
}

func TestPoWValidation_Expired(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)
	session := cc.CreateJSChallenge("test-pow-expired", 0.3)

	// Manually expire the challenge
	cc.mu.Lock()
	session.PoW.ExpiresAt = time.Now().Add(-1 * time.Second)
	cc.mu.Unlock()

	solution := &PoWSolution{Nonce: "anything"}
	if err := cc.ValidatePoW("test-pow-expired", solution); err == nil {
		t.Fatal("expected expired PoW to be rejected")
	} else if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expiry error, got: %v", err)
	}
}

func TestPoWValidation_SessionNotFound(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)
	solution := &PoWSolution{Nonce: "anything"}

	if err := cc.ValidatePoW("nonexistent", solution); err == nil {
		t.Fatal("expected session not found error")
	}
}

func TestDifficultyScaling(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	tests := []struct {
		score   float64
		minBits int
		maxBits int
	}{
		{0.1, 10, 10},
		{0.3, 14, 14},
		{0.5, 16, 16},
		{0.7, 20, 20},
		{0.85, 22, 24},
		{0.95, 23, 24},
	}

	for _, tt := range tests {
		bits := cc.scaleDifficulty(tt.score)
		if bits < tt.minBits || bits > tt.maxBits {
			t.Errorf("score=%.2f: got %d bits, expected [%d, %d]",
				tt.score, bits, tt.minBits, tt.maxBits)
		}
	}
}

func TestFingerprintValidation_Clean(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)
	cc.CreateManagedChallenge("test-fp-clean", 0.5)

	fp := &FingerprintPayload{
		CanvasHash:          "canvas_abc123",
		WebGLVendor:         "Google Inc. (NVIDIA)",
		WebGLRenderer:       "ANGLE (NVIDIA, GeForce GTX 1080)",
		Platform:            "Win32",
		Languages:           []string{"en-US", "en"},
		HardwareConcurrency: 8,
		DeviceMemory:        16,
		ScreenWidth:         1920,
		ScreenHeight:        1080,
		TimezoneOffset:      -300,
		Timezone:            "America/New_York",
		ColorDepth:          24,
		TouchPoints:         0,
	}

	score := cc.ValidateFingerprint("test-fp-clean", fp)
	if score > 0.3 {
		t.Errorf("realistic fingerprint scored too high (bot-like): %.2f", score)
	}
	t.Logf("clean fingerprint score: %.2f (lower=more human)", score)
}

func TestFingerprintValidation_Bot(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)
	cc.CreateManagedChallenge("test-fp-bot", 0.5)

	// Nil fingerprint should score maximally bot-like
	score := cc.ValidateFingerprint("test-fp-bot", nil)
	if score < 0.9 {
		t.Errorf("nil fingerprint should score high bot: got %.2f", score)
	}

	// Empty fingerprint should also score high
	cc.CreateManagedChallenge("test-fp-empty", 0.5)
	emptyFP := &FingerprintPayload{}
	score = cc.ValidateFingerprint("test-fp-empty", emptyFP)
	if score < 0.5 {
		t.Errorf("empty fingerprint should score bot-like: got %.2f", score)
	}
	t.Logf("empty fingerprint score: %.2f", score)
}

func TestClearanceCookie_HMAC(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	// Create a session and solve it so the cookie value is stored
	session := cc.CreateJSChallenge("test-session", 0.5)
	solution, err := SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, 50_000_000)
	if err != nil {
		t.Fatalf("PoW solve failed: %v", err)
	}
	result, err := cc.CompleteChallengeJS("test-session", solution)
	if err != nil {
		t.Fatalf("CompleteChallengeJS failed: %v", err)
	}

	cookie := result.ClearanceCookie
	if cookie.Name != "cf_clearance" {
		t.Errorf("expected cookie name 'cf_clearance', got '%s'", cookie.Name)
	}

	// Cookie format: {token}-{timestamp}-{version}-{hmac}
	parts := splitClearanceCookie(cookie.Value)
	if parts == nil {
		t.Fatal("cookie should parse into 4 parts")
	}
	if len(parts[0]) != 32 {
		t.Errorf("token should be 32 hex chars, got %d", len(parts[0]))
	}
	if parts[2] != "1.0.1" {
		t.Errorf("version should be 1.0.1, got %s", parts[2])
	}

	// Should be valid (session is solved with this cookie value)
	if !cc.ValidateClearanceCookie(cookie.Value) {
		t.Fatal("valid cookie rejected")
	}

	// Tamper with it
	tampered := cookie.Value + "x"
	if cc.ValidateClearanceCookie(tampered) {
		t.Fatal("tampered cookie should be rejected")
	}

	// Completely wrong value
	if cc.ValidateClearanceCookie("garbage") {
		t.Fatal("garbage cookie should be rejected")
	}
}

func TestClearanceCookie_Expiry(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	// Create a session and solve it
	session := cc.CreateJSChallenge("test-expired", 0.5)
	solution, err := SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, 50_000_000)
	if err != nil {
		t.Fatalf("PoW solve failed: %v", err)
	}
	result, err := cc.CompleteChallengeJS("test-expired", solution)
	if err != nil {
		t.Fatalf("CompleteChallengeJS failed: %v", err)
	}

	// The cookie should be valid now
	if !cc.ValidateClearanceCookie(result.ClearanceCookie.Value) {
		t.Fatal("fresh cookie should be valid")
	}

	// Forge a cookie with an expired timestamp — even if it matches format,
	// the embedded timestamp check should reject it
	expired := "aabbccddeeff00112233445566778899-1000000000-1.0.1-fakehmac"
	if cc.ValidateClearanceCookie(expired) {
		t.Fatal("expired cookie should be rejected")
	}
}

func TestChallengePageMarkers(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	// Serve the challenge page
	req := httptest.NewRequest(http.MethodGet, "/api/cloudflare/challenge", nil)
	w := httptest.NewRecorder()
	cc.HandleChallengePage(w, req)

	resp := w.Result()

	// Check status code
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", resp.StatusCode)
	}

	// Check Server header
	if resp.Header.Get("Server") != "cloudflare" {
		t.Error("missing Server: cloudflare header")
	}

	// Check Cf-Ray header
	if resp.Header.Get("Cf-Ray") == "" {
		t.Error("missing Cf-Ray header")
	}

	body := w.Body.String()

	// Check that DetectChallenge markers are present
	markers := []string{
		"_cf_chl_opt",
		"cf-browser-verification",
		"Just a moment",
		"managed_challenge",
		"challenge-platform",
	}

	for _, m := range markers {
		if !strings.Contains(body, m) {
			t.Errorf("challenge page missing marker: %s", m)
		}
	}

	if !strings.Contains(body, `id="cf-managed-widget"`) {
		t.Fatal("challenge page should render a visible managed widget shell")
	}
	if !strings.Contains(body, "Verify you are human") {
		t.Fatal("challenge page should expose visible managed challenge copy")
	}

	// Now verify DetectChallenge can detect it
	headers := make(http.Header)
	headers.Set("Server", resp.Header.Get("Server"))
	headers.Set("Cf-Ray", resp.Header.Get("Cf-Ray"))

	challenge := DetectChallenge(resp.StatusCode, headers, []byte(body))
	if challenge == nil {
		t.Fatal("DetectChallenge returned nil for challenge page")
	}

	if challenge.Type != ChallengeManaged {
		t.Errorf("expected ChallengeManaged, got %s", challenge.Type)
	}

	if challenge.RayID == "" {
		t.Error("DetectChallenge didn't extract RayID")
	}

	// Check PoW params were extracted
	if challenge.PoWParams != nil {
		t.Logf("extracted PoW: prefix=%s... difficulty=%d",
			challenge.PoWParams.Prefix[:16], challenge.PoWParams.Difficulty)
	}
}

func TestCreateJSChallenge(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)
	session := cc.CreateJSChallenge("js-test", 0.5)

	if session.Type != ChallengeJS {
		t.Errorf("expected ChallengeJS, got %s", session.Type)
	}
	if session.PoW == nil {
		t.Fatal("JS challenge should have PoW params")
	}
	if session.RequiresFingerprint {
		t.Error("JS challenge should not require fingerprint")
	}
	if session.RequiresBehavioral {
		t.Error("JS challenge should not require behavioral")
	}
	if session.PoW.Algorithm != "SHA-256" {
		t.Errorf("expected SHA-256, got %s", session.PoW.Algorithm)
	}
}

func TestCreateManagedChallenge(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)
	session := cc.CreateManagedChallenge("managed-test", 0.7)

	if session.Type != ChallengeManaged {
		t.Errorf("expected ChallengeManaged, got %s", session.Type)
	}
	if !session.RequiresFingerprint {
		t.Error("managed challenge should require fingerprint")
	}
	if !session.RequiresBehavioral {
		t.Error("managed challenge should require behavioral")
	}
	if session.RayID == "" {
		t.Error("should have RayID")
	}
}

func TestCreateTurnstileChallenge(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)
	session := cc.CreateTurnstileChallenge("turnstile-test", "0xABCDEF")

	if session.Type != ChallengeTurnstile {
		t.Errorf("expected ChallengeTurnstile, got %s", session.Type)
	}
	if session.SiteKey != "0xABCDEF" {
		t.Errorf("expected sitekey 0xABCDEF, got %s", session.SiteKey)
	}
	if !session.RequiresBehavioral {
		t.Error("turnstile should require behavioral")
	}
	if session.RequiresFingerprint {
		t.Error("turnstile should not require fingerprint")
	}
}

func TestCompleteChallengeJS(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)
	session := cc.CreateJSChallenge("complete-js", 0.3)

	solution, err := SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, session.PoW.MaxIterations)
	if err != nil {
		t.Fatalf("PoW solve failed: %v", err)
	}

	result, err := cc.CompleteChallengeJS("complete-js", solution)
	if err != nil {
		t.Fatalf("CompleteChallengeJS failed: %v", err)
	}

	if result.ClearanceCookie == nil {
		t.Fatal("expected clearance cookie")
	}
	if result.Method != "cloudflare_js" {
		t.Errorf("expected method 'cloudflare_js', got '%s'", result.Method)
	}

	// Verify session was updated
	s, ok := cc.GetSession("complete-js")
	if !ok {
		t.Fatal("session not found")
	}
	if !s.Passed {
		t.Error("session should be marked as passed")
	}
}

func TestGetStats(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	cc.CreateJSChallenge("s1", 0.3)
	cc.CreateManagedChallenge("s2", 0.5)
	cc.CreateTurnstileChallenge("s3", "key")

	stats := cc.GetStats()
	total := stats["total_sessions"].(int)
	if total != 3 {
		t.Errorf("expected 3 sessions, got %d", total)
	}
}

func TestHasLeadingZeroBits(t *testing.T) {
	tests := []struct {
		hash     []byte
		bits     int
		expected bool
	}{
		{[]byte{0x00, 0x00, 0xFF}, 16, true},
		{[]byte{0x00, 0x00, 0xFF}, 17, false},
		{[]byte{0x00, 0x0F, 0xFF}, 12, true},
		{[]byte{0x00, 0x0F, 0xFF}, 13, false},
		{[]byte{0x00}, 8, true},
		{[]byte{0x01}, 7, true},
		{[]byte{0x01}, 8, false},
		{[]byte{0xFF}, 0, true},
	}

	for _, tt := range tests {
		result := hasLeadingZeroBits(tt.hash, tt.bits)
		if result != tt.expected {
			t.Errorf("hasLeadingZeroBits(%x, %d) = %v, want %v",
				tt.hash, tt.bits, result, tt.expected)
		}
	}
}

func TestSelectCaptchaTypeFromScore(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{0.10, "text"},
		{0.34, "text"},
		{0.35, "hcaptcha"},
		{0.59, "hcaptcha"},
		{0.60, "cloudflare_js"},
		{0.79, "cloudflare_js"},
		{0.80, "cloudflare_managed"},
		{0.95, "cloudflare_managed"},
	}

	for _, tt := range tests {
		result := selectCaptchaTypeFromScore(tt.score)
		if result != tt.expected {
			t.Errorf("selectCaptchaTypeFromScore(%.2f) = %q, want %q",
				tt.score, result, tt.expected)
		}
	}
}

// --- Phase 7: Fingerprint Binding + Drift Detection Tests ---

func TestFingerprintBinding_FirstCallBinds(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)
	cc.CreateManagedChallenge("test-bind", 0.5)

	fp := &FingerprintPayload{
		CanvasHash:          "canvas_abc123",
		WebGLVendor:         "Google Inc. (NVIDIA)",
		WebGLRenderer:       "ANGLE (NVIDIA GeForce GTX 1080)",
		Platform:            "Win32",
		Languages:           []string{"en-US", "en"},
		HardwareConcurrency: 8,
		DeviceMemory:        16,
		ScreenWidth:         1920,
		ScreenHeight:        1080,
		TimezoneOffset:      -300,
		Timezone:            "America/New_York",
		ColorDepth:          24,
	}

	// First call should bind
	score := cc.ValidateFingerprint("test-bind", fp)
	if score > 0.3 {
		t.Errorf("clean fingerprint should score low: got %.2f", score)
	}

	cc.mu.RLock()
	session := cc.sessions["test-bind"]
	cc.mu.RUnlock()

	if session.BoundFingerprint == nil {
		t.Fatal("fingerprint should be bound after first call")
	}
	if session.BoundFingerprint.Platform != "Win32" {
		t.Errorf("bound fingerprint platform = %q, want Win32", session.BoundFingerprint.Platform)
	}
	if session.FingerprintDrift != 0.0 {
		t.Errorf("drift should be 0.0 on first call, got %.2f", session.FingerprintDrift)
	}
}

func TestFingerprintBinding_SameFingerprint_NoDrift(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)
	cc.CreateManagedChallenge("test-no-drift", 0.5)

	fp := &FingerprintPayload{
		CanvasHash:          "canvas_abc123",
		WebGLVendor:         "Google Inc. (NVIDIA)",
		WebGLRenderer:       "ANGLE (NVIDIA GeForce GTX 1080)",
		Platform:            "Win32",
		Languages:           []string{"en-US"},
		HardwareConcurrency: 8,
		DeviceMemory:        16,
		ScreenWidth:         1920,
		ScreenHeight:        1080,
		Timezone:            "America/New_York",
		ColorDepth:          24,
	}

	// First call binds, second with same fp → no drift
	cc.ValidateFingerprint("test-no-drift", fp)
	score := cc.ValidateFingerprint("test-no-drift", fp)

	drift := cc.GetFingerprintDrift("test-no-drift")
	if drift != 0.0 {
		t.Errorf("same fingerprint should produce 0.0 drift, got %.2f", drift)
	}
	t.Logf("score with no drift: %.2f", score)
}

func TestFingerprintBinding_DriftDetected_PlatformChange(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)
	cc.CreateManagedChallenge("test-drift-platform", 0.5)

	fp1 := &FingerprintPayload{
		CanvasHash:          "canvas_abc123",
		WebGLVendor:         "Google Inc. (NVIDIA)",
		WebGLRenderer:       "ANGLE (NVIDIA GeForce GTX 1080)",
		Platform:            "Win32",
		Languages:           []string{"en-US"},
		HardwareConcurrency: 8,
		DeviceMemory:        16,
		ScreenWidth:         1920,
		ScreenHeight:        1080,
		Timezone:            "America/New_York",
		ColorDepth:          24,
	}

	fp2 := &FingerprintPayload{
		CanvasHash:          "canvas_abc123",
		WebGLVendor:         "Google Inc. (NVIDIA)",
		WebGLRenderer:       "ANGLE (NVIDIA GeForce GTX 1080)",
		Platform:            "MacIntel", // CHANGED — impossible mid-session
		Languages:           []string{"en-US"},
		HardwareConcurrency: 8,
		DeviceMemory:        16,
		ScreenWidth:         1920,
		ScreenHeight:        1080,
		Timezone:            "America/New_York",
		ColorDepth:          24,
	}

	cc.ValidateFingerprint("test-drift-platform", fp1)
	score := cc.ValidateFingerprint("test-drift-platform", fp2)

	drift := cc.GetFingerprintDrift("test-drift-platform")
	if drift <= 0.0 {
		t.Errorf("platform change should produce drift > 0.0, got %.2f", drift)
	}
	t.Logf("platform drift: %.2f, resulting score: %.2f", drift, score)
}

func TestFingerprintBinding_DriftDetected_HardwareChange(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)
	cc.CreateManagedChallenge("test-drift-hw", 0.5)

	fp1 := &FingerprintPayload{
		CanvasHash:          "canvas_abc123",
		WebGLVendor:         "Google Inc. (NVIDIA)",
		WebGLRenderer:       "ANGLE (NVIDIA GeForce GTX 1080)",
		Platform:            "Win32",
		Languages:           []string{"en-US"},
		HardwareConcurrency: 8,
		DeviceMemory:        16,
		ScreenWidth:         1920,
		ScreenHeight:        1080,
		Timezone:            "America/New_York",
		ColorDepth:          24,
	}

	// Change GPU, core count, and memory — everything that can't change mid-session
	fp2 := &FingerprintPayload{
		CanvasHash:          "canvas_different",
		WebGLVendor:         "Apple",
		WebGLRenderer:       "Apple M1 GPU",
		Platform:            "MacIntel",
		Languages:           []string{"en-US"},
		HardwareConcurrency: 10,
		DeviceMemory:        32,
		ScreenWidth:         2560,
		ScreenHeight:        1440,
		Timezone:            "Europe/London",
		ColorDepth:          30,
	}

	cc.ValidateFingerprint("test-drift-hw", fp1)
	score := cc.ValidateFingerprint("test-drift-hw", fp2)

	drift := cc.GetFingerprintDrift("test-drift-hw")
	if drift < 0.5 {
		t.Errorf("total hardware swap should produce high drift (>0.5), got %.2f", drift)
	}
	if score < 0.3 {
		t.Errorf("drifted fingerprint should boost bot score, got %.2f", score)
	}
	t.Logf("full hardware drift: %.4f, resulting score: %.4f", drift, score)
}

func TestFingerprintDrift_NonexistentSession(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)
	drift := cc.GetFingerprintDrift("nonexistent")
	if drift != 0.0 {
		t.Errorf("nonexistent session should return 0.0 drift, got %.2f", drift)
	}
}

// --- P12 Cookie Validation & Rate Limiting Tests ---

func TestP12_CFBMCookie_ValidatedOnSolve(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	// Create session via init handler to get __cf_bm cookie
	initBody := `{"challenge_type":"cloudflare_js","detection_score":0.3}`
	initReq := httptest.NewRequest(http.MethodPost, "/api/cloudflare/init", strings.NewReader(initBody))
	initReq.Header.Set("Content-Type", "application/json")
	initW := httptest.NewRecorder()
	cc.HandleInit(initW, initReq)

	var initResp struct {
		SessionID string        `json:"session_id"`
		PoW       *PoWChallenge `json:"pow"`
	}
	_ = json.NewDecoder(initW.Body).Decode(&initResp)

	// Get the __cf_bm cookie from init response
	var cfbmCookie *http.Cookie
	for _, c := range initW.Result().Cookies() {
		if c.Name == "__cf_bm" {
			cfbmCookie = c
			break
		}
	}
	if cfbmCookie == nil {
		t.Fatal("expected __cf_bm cookie from init")
	}

	// Solve the PoW
	solution, err := SolvePoW(initResp.PoW.Prefix, initResp.PoW.Difficulty, 50_000_000)
	if err != nil {
		t.Fatalf("PoW failed: %v", err)
	}

	// Submit WITHOUT __cf_bm — should be rejected
	solveBody, _ := json.Marshal(map[string]interface{}{
		"session_id": initResp.SessionID,
		"solution":   solution,
	})
	solveReq := httptest.NewRequest(http.MethodPost, "/api/cloudflare/solve/js", strings.NewReader(string(solveBody)))
	solveReq.Header.Set("Content-Type", "application/json")
	solveW := httptest.NewRecorder()
	cc.HandleSolveJS(solveW, solveReq)

	if solveW.Code != http.StatusForbidden {
		t.Errorf("expected 403 without __cf_bm cookie, got %d", solveW.Code)
	}

	// Submit WITH correct __cf_bm — should pass
	solveReq2 := httptest.NewRequest(http.MethodPost, "/api/cloudflare/solve/js", strings.NewReader(string(solveBody)))
	solveReq2.Header.Set("Content-Type", "application/json")
	solveReq2.AddCookie(cfbmCookie)
	solveW2 := httptest.NewRecorder()
	cc.HandleSolveJS(solveW2, solveReq2)

	if solveW2.Code == http.StatusForbidden {
		var errResp struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(solveW2.Body).Decode(&errResp)
		t.Errorf("expected success with correct __cf_bm, got 403: %s", errResp.Error)
	}
}

func TestP12_CFBMCookie_WrongValueRejected(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	session := cc.CreateJSChallenge("cfbm-wrong", 0.3)
	solution, err := SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, 50_000_000)
	if err != nil {
		t.Fatalf("PoW failed: %v", err)
	}

	solveBody, _ := json.Marshal(map[string]interface{}{
		"session_id": "cfbm-wrong",
		"solution":   solution,
	})

	// Submit with wrong __cf_bm value
	solveReq := httptest.NewRequest(http.MethodPost, "/api/cloudflare/solve/js", strings.NewReader(string(solveBody)))
	solveReq.Header.Set("Content-Type", "application/json")
	solveReq.AddCookie(&http.Cookie{Name: "__cf_bm", Value: "totally-wrong-value"})
	solveW := httptest.NewRecorder()
	cc.HandleSolveJS(solveW, solveReq)

	if solveW.Code != http.StatusForbidden {
		t.Errorf("expected 403 with wrong __cf_bm, got %d", solveW.Code)
	}
}

func TestP12_ClearanceCookie_RealisticFormat(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	session := cc.CreateJSChallenge("format-test", 0.3)
	solution, _ := SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, 50_000_000)
	result, err := cc.CompleteChallengeJS("format-test", solution)
	if err != nil {
		t.Fatalf("solve failed: %v", err)
	}

	cookie := result.ClearanceCookie
	parts := splitClearanceCookie(cookie.Value)
	if parts == nil {
		t.Fatal("cookie should parse into 4 parts")
	}

	// Part 0: 32-char hex token
	if len(parts[0]) != 32 {
		t.Errorf("token should be 32 hex chars, got %d: %s", len(parts[0]), parts[0])
	}

	// Part 1: unix timestamp (digits)
	for _, c := range parts[1] {
		if c < '0' || c > '9' {
			t.Errorf("timestamp should be digits, got %q", parts[1])
			break
		}
	}

	// Part 2: version string
	if parts[2] != "1.0.1" {
		t.Errorf("version should be 1.0.1, got %s", parts[2])
	}

	// Part 3: base64url-encoded HMAC (non-empty)
	if len(parts[3]) < 10 {
		t.Errorf("HMAC seems too short: %s", parts[3])
	}

	t.Logf("cookie format: token=%s... ts=%s ver=%s hmac=%s...",
		parts[0][:8], parts[1], parts[2], parts[3][:10])
}

func TestP12_ChallengePageHTML_HasFPScript(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/cloudflare/challenge", nil)
	w := httptest.NewRecorder()
	cc.HandleChallengePage(w, req)

	body := w.Body.String()

	// Check for fingerprint collection script markers
	checks := []string{
		"_cf_chl_opt",
		"navigator.userAgent",
		"navigator.hardwareConcurrency",
		"Intl.DateTimeFormat",
		"/cdn-cgi/challenge-platform/h/g/cv/result/",
		"managed.js",
		"Performance &amp; security by Cloudflare",
		"robots",
		"noindex,nofollow",
	}
	for _, marker := range checks {
		if !strings.Contains(body, marker) {
			t.Errorf("challenge page should contain %q", marker)
		}
	}
}

func TestP12_ChallengeCallback_AcceptsPost(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/cdn-cgi/challenge-platform/h/g/cv/result/abc123", strings.NewReader(`{"fp":{},"t":"fp"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	cc.HandleChallengeCallback(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for callback, got %d", w.Code)
	}
	if w.Header().Get("Server") != "cloudflare" {
		t.Error("expected Server: cloudflare header")
	}
}

func TestP12_ManagedJS_ServesScript(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/cdn-cgi/challenge-platform/scripts/turnstile/managed.js", nil)
	w := httptest.NewRecorder()
	cc.HandleManagedJS(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for managed.js, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "application/javascript" {
		t.Errorf("expected application/javascript, got %s", w.Header().Get("Content-Type"))
	}
	if !strings.Contains(w.Body.String(), "_cf_chl_opt") {
		t.Error("managed.js should reference _cf_chl_opt")
	}
}

func TestP12_MountRoutes_WithRateLimiting(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)
	// Set a very low rate limit for testing
	cc.RateLimiter = NewTokenBucket(RateLimitConfig{
		Capacity:   1,
		RefillRate: 0.01,
	})

	mux := http.NewServeMux()
	cc.MountRoutes(mux)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Init a session to get __cf_bm cookie
	initBody := `{"challenge_type":"cloudflare_js","detection_score":0.3}`
	resp1, err := http.Post(ts.URL+"/api/cloudflare/init", "application/json", strings.NewReader(initBody))
	if err != nil {
		t.Fatalf("init failed: %v", err)
	}
	resp1.Body.Close()

	// First solve attempt should get through (rate limit = 1 token)
	solveBody := `{"session_id":"x","solution":{"nonce":"bad","hash":"bad","iterations":1,"time_ms":1}}`
	resp2, err := http.Post(ts.URL+"/api/cloudflare/solve/js", "application/json", strings.NewReader(solveBody))
	if err != nil {
		t.Fatalf("first solve failed: %v", err)
	}
	resp2.Body.Close()

	// First request goes through (gets 403 for bad solution, not 429)
	if resp2.StatusCode == http.StatusTooManyRequests {
		t.Error("first request should not be rate limited")
	}

	// Second solve attempt should be rate limited (429)
	resp3, err := http.Post(ts.URL+"/api/cloudflare/solve/js", "application/json", strings.NewReader(solveBody))
	if err != nil {
		t.Fatalf("second solve failed: %v", err)
	}
	resp3.Body.Close()

	if resp3.StatusCode != http.StatusTooManyRequests {
		t.Errorf("second request should be 429, got %d", resp3.StatusCode)
	}
	if resp3.Header.Get("Retry-After") == "" {
		t.Error("429 response should have Retry-After header")
	}

	t.Logf("rate limiting working: first=%d second=%d", resp2.StatusCode, resp3.StatusCode)
}
