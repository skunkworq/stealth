package solver

import (
	"encoding/json"
	"testing"
)

// TestNewCaptchaSolver verifies that the constructor returns a non-nil solver
// with an initialized RNG and HTTP client and an empty lastToken.
func TestNewCaptchaSolver(t *testing.T) {
	cs := NewCaptchaSolver()
	if cs == nil {
		t.Fatal("NewCaptchaSolver() returned nil")
	}
	if cs.rng == nil {
		t.Error("expected non-nil rng")
	}
	if cs.httpClient == nil {
		t.Error("expected non-nil httpClient")
	}
	if cs.solver == nil {
		t.Error("expected non-nil captcha solver")
	}
}

// TestLastToken_Initial verifies that a freshly created solver has an empty
// last token (no solve has been performed yet).
func TestLastToken_Initial(t *testing.T) {
	cs := NewCaptchaSolver()
	if tok := cs.LastToken(); tok != "" {
		t.Errorf("expected empty LastToken, got %q", tok)
	}
}

// TestDetectCaptchaResponse_NoCaptchaHeader verifies that DetectCaptchaResponse
// returns nil when the X-Captcha-Required header is absent.
func TestDetectCaptchaResponse_NoCaptchaHeader(t *testing.T) {
	cs := NewCaptchaSolver()

	body := []byte(`{"captcha":{"challenge_id":"abc","type":"text"}}`)
	headers := map[string][]string{}

	cr := cs.DetectCaptchaResponse(body, headers)
	if cr != nil {
		t.Errorf("expected nil CaptchaResponse when header absent, got %+v", cr)
	}
}

// TestDetectCaptchaResponse_HeaderPresentInvalidBody verifies that
// DetectCaptchaResponse returns nil when the header is set but the body is
// not valid JSON.
func TestDetectCaptchaResponse_HeaderPresentInvalidBody(t *testing.T) {
	cs := NewCaptchaSolver()

	headers := map[string][]string{
		"X-Captcha-Required": {"1"},
	}

	cr := cs.DetectCaptchaResponse([]byte(`not-json`), headers)
	if cr != nil {
		t.Errorf("expected nil for invalid JSON body, got %+v", cr)
	}
}

// TestDetectCaptchaResponse_InlineCaptcha verifies correct field extraction
// from a well-formed inline captcha body.
func TestDetectCaptchaResponse_InlineCaptcha(t *testing.T) {
	cs := NewCaptchaSolver()

	payload := map[string]interface{}{
		"captcha": map[string]interface{}{
			"challenge_id": "chg-123",
			"type":         "text",
			"captcha_id":   "cap-456",
			"challenge_data": map[string]interface{}{
				"image":     "base64data",
				"num_chars": float64(6),
			},
		},
	}
	body, _ := json.Marshal(payload)

	headers := map[string][]string{
		"X-Captcha-Required": {"1"},
	}

	cr := cs.DetectCaptchaResponse(body, headers)
	if cr == nil {
		t.Fatal("expected non-nil CaptchaResponse")
	}
	if cr.ChallengeID != "chg-123" {
		t.Errorf("ChallengeID: want %q, got %q", "chg-123", cr.ChallengeID)
	}
	if cr.Type != "text" {
		t.Errorf("Type: want %q, got %q", "text", cr.Type)
	}
	if cr.CaptchaID != "cap-456" {
		t.Errorf("CaptchaID: want %q, got %q", "cap-456", cr.CaptchaID)
	}
	if cr.ImageBase64 != "base64data" {
		t.Errorf("ImageBase64: want %q, got %q", "base64data", cr.ImageBase64)
	}
}

// TestDetectCaptchaResponse_ReCaptchaV2 verifies that a recaptcha-v2 type
// header produces a CaptchaResponse with the correct Type set.
func TestDetectCaptchaResponse_ReCaptchaV2_WithBody(t *testing.T) {
	cs := NewCaptchaSolver()

	payload := map[string]interface{}{
		"init_url": "https://example.com/init",
		"site_key": "6Le-key",
	}
	body, _ := json.Marshal(payload)

	headers := map[string][]string{
		"X-Captcha-Required": {"1"},
		"X-Captcha-Type":     {"recaptcha-v2"},
	}

	cr := cs.DetectCaptchaResponse(body, headers)
	if cr == nil {
		t.Fatal("expected non-nil CaptchaResponse for recaptcha-v2")
	}
	if cr.Type != "recaptcha-v2" {
		t.Errorf("Type: want %q, got %q", "recaptcha-v2", cr.Type)
	}
	if cr.ChallengeData == nil {
		t.Error("expected non-nil ChallengeData for recaptcha-v2 with valid JSON body")
	}
}

// TestDetectCaptchaResponse_ReCaptchaV2_InvalidBody verifies that a
// recaptcha-v2 header with an unparseable body still returns a minimal
// CaptchaResponse (not nil).
func TestDetectCaptchaResponse_ReCaptchaV2_InvalidBody(t *testing.T) {
	cs := NewCaptchaSolver()

	headers := map[string][]string{
		"X-Captcha-Required": {"1"},
		"X-Captcha-Type":     {"recaptcha-v2"},
	}

	cr := cs.DetectCaptchaResponse([]byte(`not-json`), headers)
	if cr == nil {
		t.Fatal("expected non-nil CaptchaResponse even for invalid body with recaptcha-v2 header")
	}
	if cr.Type != "recaptcha-v2" {
		t.Errorf("Type: want %q, got %q", "recaptcha-v2", cr.Type)
	}
}

// TestDetectCaptchaResponse_NoCaptchaKey verifies that a valid JSON body
// without a "captcha" key returns nil.
func TestDetectCaptchaResponse_NoCaptchaKey(t *testing.T) {
	cs := NewCaptchaSolver()

	payload := map[string]interface{}{
		"other": "data",
	}
	body, _ := json.Marshal(payload)

	headers := map[string][]string{
		"X-Captcha-Required": {"1"},
	}

	cr := cs.DetectCaptchaResponse(body, headers)
	if cr != nil {
		t.Errorf("expected nil when no 'captcha' key in body, got %+v", cr)
	}
}

// TestGenerateHumanEvents_BasicShape verifies that GenerateHumanEvents returns
// a non-empty slice containing at least mouse, keystroke, scroll and click
// event types.
func TestGenerateHumanEvents_BasicShape(t *testing.T) {
	cs := NewCaptchaSolver()
	events := cs.GenerateHumanEvents(1000)

	if len(events) == 0 {
		t.Fatal("expected non-empty event slice from GenerateHumanEvents")
	}

	typeSeen := map[string]bool{}
	for _, ev := range events {
		typeSeen[ev.Type] = true
	}

	required := []string{"mousemove", "keydown", "scroll", "click"}
	for _, r := range required {
		if !typeSeen[r] {
			t.Errorf("missing expected event type %q in generated events (seen: %v)", r, typeSeen)
		}
	}
}

// TestGenerateHumanEvents_WithSolution verifies that passing a Solution option
// causes keystroke events to use the provided characters.
func TestGenerateHumanEvents_WithSolution(t *testing.T) {
	cs := NewCaptchaSolver()
	solution := "abc123"
	events := cs.GenerateHumanEvents(1000, HumanEventOpts{Solution: solution})

	if len(events) == 0 {
		t.Fatal("expected non-empty events")
	}

	// Gather keydown events
	var keydowns []string
	for _, ev := range events {
		if ev.Type == "keydown" {
			keydowns = append(keydowns, ev.Key)
		}
	}

	if len(keydowns) != len(solution) {
		t.Errorf("expected %d keydown events for solution %q, got %d", len(solution), solution, len(keydowns))
	}
	for i, ch := range solution {
		if i >= len(keydowns) {
			break
		}
		if keydowns[i] != string(ch) {
			t.Errorf("keydown[%d]: want %q, got %q", i, string(ch), keydowns[i])
		}
	}
}

// TestGenerateHumanEvents_TimestampsMonotonic verifies that mousemove event
// timestamps (array-order) are strictly increasing, which is required for the
// BehavioralAnalyzer's interval entropy check.
func TestGenerateHumanEvents_TimestampsMonotonic(t *testing.T) {
	cs := NewCaptchaSolver()
	events := cs.GenerateHumanEvents(1000)

	var prevTs int64 = -1
	for i, ev := range events {
		if ev.Type != "mousemove" {
			continue
		}
		if ev.Timestamp <= prevTs {
			t.Errorf("mousemove timestamp not strictly increasing at index %d: prev=%d, got=%d",
				i, prevTs, ev.Timestamp)
		}
		prevTs = ev.Timestamp
	}
}

// TestDeriveBaseURL verifies URL base extraction with various inputs.
func TestDeriveBaseURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://example.com/path?q=1", "https://example.com"},
		{"http://foo.bar:8080/baz", "http://foo.bar:8080"},
		{"not-a-url", "://"}, // url.Parse succeeds but scheme/host are empty
	}

	for _, tc := range tests {
		got := DeriveBaseURL(tc.input)
		if got != tc.want {
			t.Errorf("DeriveBaseURL(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestSolveResult_ToFSMOutput verifies that ToFSMOutput correctly maps fields
// and that it handles a nil receiver safely.
func TestSolveResult_ToFSMOutput(t *testing.T) {
	var nilResult *SolveResult
	if out := nilResult.ToFSMOutput(); out != nil {
		t.Errorf("nil.ToFSMOutput() should return nil, got %+v", out)
	}

	sr := &SolveResult{
		Solution:    "ABCDEF",
		Confidence:  0.92,
		SolveTimeMs: 450,
		Token:       "tok-xyz",
	}
	out := sr.ToFSMOutput()
	if out == nil {
		t.Fatal("expected non-nil FSM output")
	}
	if out.Solution != sr.Solution {
		t.Errorf("Solution: want %q, got %q", sr.Solution, out.Solution)
	}
	if out.Confidence != sr.Confidence {
		t.Errorf("Confidence: want %f, got %f", sr.Confidence, out.Confidence)
	}
	if out.Token != sr.Token {
		t.Errorf("Token: want %q, got %q", sr.Token, out.Token)
	}
}

// TestReCaptchaV2Result_ToFSMOutput verifies field mapping and nil safety.
func TestReCaptchaV2Result_ToFSMOutput(t *testing.T) {
	var nilR *ReCaptchaV2Result
	if out := nilR.ToFSMOutput(); out != nil {
		t.Errorf("nil.ToFSMOutput() should return nil, got %+v", out)
	}

	r := &ReCaptchaV2Result{
		Token:           "tok-abc",
		BehavioralScore: 0.75,
		Passed:          true,
		NeedChallenge:   false,
		SolveAttempts:   2,
		RefreshCount:    1,
		TotalTimeMs:     3000,
	}
	out := r.ToFSMOutput()
	if out == nil {
		t.Fatal("expected non-nil FSM output")
	}
	if out.Token != r.Token {
		t.Errorf("Token: want %q, got %q", r.Token, out.Token)
	}
	if out.Passed != r.Passed {
		t.Errorf("Passed: want %v, got %v", r.Passed, out.Passed)
	}
	if out.SolveAttempts != r.SolveAttempts {
		t.Errorf("SolveAttempts: want %d, got %d", r.SolveAttempts, out.SolveAttempts)
	}
}
