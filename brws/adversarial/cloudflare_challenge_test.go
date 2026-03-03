package adversarial

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

	cookie := cc.generateClearanceCookie("test-session")

	if cookie.Name != "cf_clearance" {
		t.Errorf("expected cookie name 'cf_clearance', got '%s'", cookie.Name)
	}

	// Should be valid
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

	// Create a cookie manually with expired time
	sessionID := "test-expired-cookie"
	expiry := time.Now().Add(-1 * time.Minute)
	data := fmt.Sprintf("%s|%d", sessionID, expiry.UnixMilli())

	mac := hmacSHA256(cc.hmacKey, data)
	value := fmt.Sprintf("%s.%d.%s", sessionID, expiry.UnixMilli(), mac)

	if cc.ValidateClearanceCookie(value) {
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

// hmacSHA256 is a helper for test cookie creation.
func hmacSHA256(key []byte, data string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}
