package adversarial

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func humanLikeTurnstileEvents() []CaptchaEvent {
	base := time.Now().UnixMilli()
	return []CaptchaEvent{
		{Type: "mousemove", Timestamp: base + 0, X: 118, Y: 266},
		{Type: "mousemove", Timestamp: base + 94, X: 137, Y: 258},
		{Type: "mousemove", Timestamp: base + 213, X: 161, Y: 244},
		{Type: "mousemove", Timestamp: base + 371, X: 186, Y: 223},
		{Type: "mousemove", Timestamp: base + 522, X: 214, Y: 202},
		{Type: "mousemove", Timestamp: base + 705, X: 242, Y: 186},
		{Type: "mousemove", Timestamp: base + 881, X: 269, Y: 179},
		{Type: "wheel", Timestamp: base + 1048, Delta: 114},
		{Type: "wheel", Timestamp: base + 1235, Delta: 78},
		{Type: "mousemove", Timestamp: base + 1412, X: 294, Y: 173},
		{Type: "mousedown", Timestamp: base + 1554, X: 302, Y: 171},
		{Type: "mouseup", Timestamp: base + 1662, X: 303, Y: 170},
		{Type: "click", Timestamp: base + 1669, X: 303, Y: 170},
	}
}

func straightLineTurnstileEvents() []CaptchaEvent {
	base := time.Now().UnixMilli()
	return []CaptchaEvent{
		{Type: "mousemove", Timestamp: base + 0, X: 100, Y: 200},
		{Type: "mousemove", Timestamp: base + 100, X: 140, Y: 200},
		{Type: "mousemove", Timestamp: base + 200, X: 180, Y: 200},
		{Type: "mousemove", Timestamp: base + 300, X: 220, Y: 200},
		{Type: "mousemove", Timestamp: base + 400, X: 260, Y: 200},
		{Type: "mousemove", Timestamp: base + 500, X: 300, Y: 200},
		{Type: "mousedown", Timestamp: base + 650, X: 300, Y: 200},
		{Type: "mouseup", Timestamp: base + 700, X: 300, Y: 200},
		{Type: "click", Timestamp: base + 701, X: 300, Y: 200},
	}
}

func TestTurnstileInitExposesWidgetConfig(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/cloudflare/init", strings.NewReader(`{"challenge_type":"cloudflare_turnstile"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	cc.HandleInit(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		SessionID string                 `json:"session_id"`
		Turnstile *TurnstileWidgetConfig `json:"turnstile"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode init response: %v", err)
	}

	if resp.SessionID == "" {
		t.Fatal("expected session ID")
	}
	if resp.Turnstile == nil {
		t.Fatal("expected turnstile config")
	}
	if resp.Turnstile.Action == "" || resp.Turnstile.CData == "" {
		t.Fatalf("expected action/cdata, got %+v", resp.Turnstile)
	}
	if resp.Turnstile.TokenTTLSeconds != int(defaultTurnstileTokenTTL/time.Second) {
		t.Fatalf("unexpected token TTL: %d", resp.Turnstile.TokenTTLSeconds)
	}
	if resp.Turnstile.RetryPolicy.IntervalMs != 8000 {
		t.Fatalf("unexpected retry interval: %d", resp.Turnstile.RetryPolicy.IntervalMs)
	}
	if resp.Turnstile.CallbackState.Success {
		t.Fatal("callback state should start empty")
	}
}

func TestTurnstileWidgetPageContainsContractFields(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/cloudflare/turnstile/widget?session_id=widget-1&site_key=1x00000000000000000000AA", nil)
	w := httptest.NewRecorder()
	cc.HandleTurnstileWidgetPage(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 widget page, got %d", w.Code)
	}

	body := w.Body.String()
	checks := []string{
		`class="cf-turnstile"`,
		`data-action="managed"`,
		`data-cdata="widget-1"`,
		`data-retry-interval="8000"`,
		`data-refresh-expired="auto"`,
		`data-before-interactive-callback="__tsBeforeInteractive"`,
		`data-after-interactive-callback="__tsAfterInteractive"`,
		`data-callback="__tsSuccess"`,
	}
	for _, marker := range checks {
		if !strings.Contains(body, marker) {
			t.Fatalf("widget page missing %q", marker)
		}
	}

	session, ok := cc.GetSession("widget-1")
	if !ok {
		t.Fatal("expected session to be created")
	}
	if !session.TurnstilePresented {
		t.Fatal("expected widget presentation to be recorded")
	}
}

func TestTurnstilePresentedSessionRequiresLifecycleCallbacks(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	session := cc.CreateTurnstileChallenge("widget-lifecycle", "1x00000000000000000000AA")
	cc.PresentTurnstileWidget(session.ID, "localhost")

	solution, err := SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, session.PoW.MaxIterations)
	if err != nil {
		t.Fatalf("SolvePoW failed: %v", err)
	}

	if _, err := cc.CompleteTurnstile(session.ID, solution, humanLikeTurnstileEvents()); err == nil {
		t.Fatal("expected solve without widget callbacks to be rejected once presented")
	}

	cc.RecordTurnstileCallback(session.ID, "before-interactive")
	cc.RecordTurnstileCallback(session.ID, "after-interactive")
	if _, err := cc.CompleteTurnstile(session.ID, solution, humanLikeTurnstileEvents()); err != nil {
		t.Fatalf("expected solve to pass with lifecycle callbacks: %v", err)
	}
}

func TestTurnstileRejectsTimeoutCallback(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	session := cc.CreateTurnstileChallenge("widget-timeout", "1x00000000000000000000AA")
	cc.PresentTurnstileWidget(session.ID, "localhost")
	cc.RecordTurnstileCallback(session.ID, "before-interactive")
	cc.RecordTurnstileCallback(session.ID, "timeout")

	solution, err := SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, session.PoW.MaxIterations)
	if err != nil {
		t.Fatalf("SolvePoW failed: %v", err)
	}

	if _, err := cc.CompleteTurnstile(session.ID, solution, humanLikeTurnstileEvents()); err == nil {
		t.Fatal("expected timeout lifecycle to force rejection")
	}
}

func TestTurnstileSiteVerifySingleUseAndExpiry(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	session := cc.CreateTurnstileChallenge("siteverify-1", "1x00000000000000000000AA")
	session.Hostname = "localhost"
	solution, err := SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, session.PoW.MaxIterations)
	if err != nil {
		t.Fatalf("SolvePoW failed: %v", err)
	}

	result, err := cc.CompleteTurnstile(session.ID, solution, humanLikeTurnstileEvents())
	if err != nil {
		t.Fatalf("CompleteTurnstile failed: %v", err)
	}

	postVerify := func(token string) map[string]any {
		body, _ := json.Marshal(map[string]string{
			"secret":   cc.TurnstileSecretKey(),
			"response": token,
		})
		req := httptest.NewRequest(http.MethodPost, "/turnstile/v0/siteverify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Host = "localhost"
		w := httptest.NewRecorder()
		cc.HandleTurnstileSiteVerify(w, req)

		var decoded map[string]any
		if err := json.NewDecoder(w.Body).Decode(&decoded); err != nil {
			t.Fatalf("decode verify response: %v", err)
		}
		return decoded
	}

	first := postVerify(result.TurnstileToken)
	if success, _ := first["success"].(bool); !success {
		t.Fatalf("expected first verification to succeed: %+v", first)
	}

	second := postVerify(result.TurnstileToken)
	if success, _ := second["success"].(bool); success {
		t.Fatalf("expected duplicate verification to fail: %+v", second)
	}

	expiredSession := cc.CreateTurnstileChallenge("siteverify-expired", "1x00000000000000000000AA")
	expiredSession.Hostname = "localhost"
	expiredSolution, err := SolvePoW(expiredSession.PoW.Prefix, expiredSession.PoW.Difficulty, expiredSession.PoW.MaxIterations)
	if err != nil {
		t.Fatalf("SolvePoW expired failed: %v", err)
	}
	expiredResult, err := cc.CompleteTurnstile(expiredSession.ID, expiredSolution, humanLikeTurnstileEvents())
	if err != nil {
		t.Fatalf("CompleteTurnstile expired failed: %v", err)
	}

	cc.mu.Lock()
	cc.sessions[expiredSession.ID].TurnstileToken.ExpiresAt = time.Now().Add(-time.Second)
	cc.mu.Unlock()

	expired := postVerify(expiredResult.TurnstileToken)
	if success, _ := expired["success"].(bool); success {
		t.Fatalf("expected expired verification to fail: %+v", expired)
	}
}

func TestEvaluateTurnstileDefense(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	report, err := cc.EvaluateTurnstileDefense([]TurnstileEvaluationCase{
		{
			Name:               "human-like",
			ExpectPass:         true,
			PresentWidget:      true,
			LifecycleCallbacks: []string{"before-interactive", "after-interactive"},
			VerifyToken:        true,
			BuildEvents: func() []CaptchaEvent {
				return humanLikeTurnstileEvents()
			},
		},
		{
			Name:               "straight-line-bot",
			ExpectPass:         false,
			PresentWidget:      true,
			LifecycleCallbacks: []string{"before-interactive", "after-interactive"},
			BuildEvents: func() []CaptchaEvent {
				return straightLineTurnstileEvents()
			},
		},
		{
			Name:               "timed-out-widget",
			ExpectPass:         false,
			PresentWidget:      true,
			LifecycleCallbacks: []string{"before-interactive", "timeout"},
			BuildEvents: func() []CaptchaEvent {
				return humanLikeTurnstileEvents()
			},
		},
		{
			Name:       "empty-bot",
			ExpectPass: false,
			BuildEvents: func() []CaptchaEvent {
				return nil
			},
		},
	}, 3)
	if err != nil {
		t.Fatalf("EvaluateTurnstileDefense failed: %v", err)
	}

	if len(report.Samples) != 4 {
		t.Fatalf("expected 4 samples, got %d", len(report.Samples))
	}

	if report.Samples[0].PassRate <= 0 {
		t.Fatalf("expected human-like sample to pass at least once: %+v", report.Samples[0])
	}
	if report.Samples[0].VerificationPasses != report.Samples[0].Passes {
		t.Fatalf("expected human-like sample to verify each issued token: %+v", report.Samples[0])
	}
	if report.Samples[1].RejectRate != 1 {
		t.Fatalf("expected straight-line bot sample to reject every time: %+v", report.Samples[1])
	}
	if report.Samples[2].RejectRate != 1 {
		t.Fatalf("expected timeout sample to reject every time: %+v", report.Samples[2])
	}
	if report.Samples[3].RejectRate != 1 {
		t.Fatalf("expected empty bot sample to reject every time: %+v", report.Samples[3])
	}
	if report.Accuracy < 0.75 {
		t.Fatalf("expected aggregate accuracy >= 0.75, got %.2f", report.Accuracy)
	}
}
