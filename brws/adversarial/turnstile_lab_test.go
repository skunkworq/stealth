package adversarial

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestTurnstileWidgetConfigNormalizeAndParse(t *testing.T) {
	cfg := (&TurnstileWidgetConfig{
		SiteKey:         "0x4AAAAAAADnPIDROrmt1Wwj",
		Action:          "checkout",
		CData:           "cart-17",
		Retry:           TurnstileRetryAuto,
		RefreshExpired:  TurnstileRefreshAuto,
		TokenTTLSeconds: 120,
	}).Normalize()

	if cfg.Mode != TurnstileModeManaged {
		t.Fatalf("expected managed mode by default, got %s", cfg.Mode)
	}
	if !cfg.ShouldAutoRetry() {
		t.Fatal("expected auto retry")
	}
	if !cfg.ShouldAutoRefreshExpired() {
		t.Fatal("expected auto refresh on expiry")
	}

	html := `<!DOCTYPE html><html><body>
	<div class="cf-turnstile"
		data-sitekey="0x4AAAAAAADnPIDROrmt1Wwj"
		data-action="checkout"
		data-cdata="cart-17"
		data-size="normal"
		data-appearance="always"
		data-execution="render"
		data-retry="auto"
		data-retry-interval="1200"
		data-refresh-expired="auto"
		data-refresh-timeout="manual"
		data-response-field-name="cf-turnstile-response"
		data-token-ttl="180"></div>
	<script src="/turnstile/v0/api.js?render=explicit"></script>
	</body></html>`

	parsed := ParseTurnstileWidgetConfigFromHTML(html)
	if parsed == nil {
		t.Fatal("expected widget config to be parsed")
	}
	if parsed.SiteKey != "0x4AAAAAAADnPIDROrmt1Wwj" {
		t.Fatalf("unexpected sitekey: %s", parsed.SiteKey)
	}
	if parsed.Action != "checkout" || parsed.CData != "cart-17" {
		t.Fatalf("unexpected action/cdata: %#v", parsed)
	}
	if parsed.RetryIntervalMS != 1200 {
		t.Fatalf("expected retry interval 1200ms, got %d", parsed.RetryIntervalMS)
	}
	if parsed.TokenTTLSeconds != 180 {
		t.Fatalf("expected token ttl 180s, got %d", parsed.TokenTTLSeconds)
	}
}

func TestTurnstileVerifyLifecycle(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)
	session := cc.CreateTurnstileChallengeWithConfig("ts-flow", &TurnstileWidgetConfig{
		SiteKey:         TurnstileTestingSiteKeyVisiblePass,
		Action:          "checkout",
		CData:           "cart-17",
		TokenTTLSeconds: 300,
	})

	solution, err := SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, 50_000_000)
	if err != nil {
		t.Fatalf("SolvePoW failed: %v", err)
	}

	result, err := cc.CompleteTurnstileInteraction("ts-flow", solution, turnstileHumanEvents(), nil, "localhost")
	if err != nil {
		t.Fatalf("CompleteTurnstileInteraction failed: %v", err)
	}
	if result.LabToken == nil || result.TurnstileToken == "" {
		t.Fatal("expected lab token metadata")
	}

	verify := cc.VerifyTurnstileToken(cc.GetTurnstileSecretKey(), result.TurnstileToken, "localhost")
	if !verify.Success {
		t.Fatalf("expected verify success, got %#v", verify)
	}
	if verify.Action != "checkout" || verify.CData != "cart-17" {
		t.Fatalf("unexpected verify metadata: %#v", verify)
	}

	duplicate := cc.VerifyTurnstileToken(cc.GetTurnstileSecretKey(), result.TurnstileToken, "localhost")
	if duplicate.Success {
		t.Fatal("expected duplicate verification to fail")
	}
	if len(duplicate.ErrorCodes) == 0 || duplicate.ErrorCodes[0] != "timeout-or-duplicate" {
		t.Fatalf("expected timeout-or-duplicate, got %#v", duplicate.ErrorCodes)
	}
}

func TestTurnstileVerifyRejectsExpiredToken(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)
	session := cc.CreateTurnstileChallengeWithConfig("ts-expired", &TurnstileWidgetConfig{
		SiteKey:         TurnstileTestingSiteKeyVisiblePass,
		TokenTTLSeconds: 1,
	})

	solution, err := SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, 50_000_000)
	if err != nil {
		t.Fatalf("SolvePoW failed: %v", err)
	}
	if _, err := cc.CompleteTurnstileInteraction("ts-expired", solution, turnstileHumanEvents(), nil, "localhost"); err != nil {
		t.Fatalf("CompleteTurnstileInteraction failed: %v", err)
	}

	stored, ok := cc.GetSession("ts-expired")
	if !ok || stored.TurnstileToken == nil {
		t.Fatal("expected stored turnstile token")
	}
	stored.TurnstileToken.ExpiresAt = time.Now().Add(-time.Second)

	verify := cc.VerifyTurnstileToken(cc.GetTurnstileSecretKey(), stored.TurnstileToken.Token, "localhost")
	if verify.Success {
		t.Fatal("expected expired verification to fail")
	}
	if len(verify.ErrorCodes) == 0 || verify.ErrorCodes[0] != "timeout-or-duplicate" {
		t.Fatalf("expected timeout-or-duplicate, got %#v", verify.ErrorCodes)
	}
}

func TestTurnstileCallbackStateRecorded(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)
	cc.CreateTurnstileChallenge("ts-callback", TurnstileTestingSiteKeyVisiblePass)

	for _, callback := range []string{"render", "execute", "success"} {
		body := `{"session_id":"ts-callback","callback":"` + callback + `"}`
		req := httptest.NewRequest(http.MethodPost, "/api/cloudflare/turnstile/callback", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		cc.HandleTurnstileCallback(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("callback %s returned %d", callback, w.Code)
		}
	}

	session, ok := cc.GetSession("ts-callback")
	if !ok || session.CallbackState == nil {
		t.Fatal("expected callback state")
	}
	if !session.CallbackState.Rendered || !session.CallbackState.Executed || !session.CallbackState.Succeeded {
		t.Fatalf("expected render/execute/success state, got %#v", session.CallbackState)
	}
	if session.CallbackState.RenderCount != 1 {
		t.Fatalf("expected one render count, got %d", session.CallbackState.RenderCount)
	}
}

func TestTurnstileWidgetPageAndSiteverifyEndpoint(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)
	mux := http.NewServeMux()
	cc.MountRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	pageResp, err := http.Get(ts.URL + "/api/cloudflare/turnstile/widget")
	if err != nil {
		t.Fatalf("widget page request failed: %v", err)
	}
	defer pageResp.Body.Close()
	rawBody, _ := io.ReadAll(pageResp.Body)
	body := string(rawBody)

	if pageResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 widget page, got %d", pageResp.StatusCode)
	}
	for _, marker := range []string{"cf-turnstile", "/turnstile/v0/api.js", "cf-turnstile-response", "Owned-environment Turnstile harness"} {
		if !strings.Contains(body, marker) {
			t.Fatalf("expected widget page marker %q", marker)
		}
	}

	statusResp, err := http.Get(ts.URL + "/api/cloudflare/status")
	if err != nil {
		t.Fatalf("status request failed: %v", err)
	}
	statusResp.Body.Close()
}

func TestTurnstileSiteverifyHandlerAcceptsFormEncodedBody(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)
	session := cc.CreateTurnstileChallenge("ts-siteverify", TurnstileTestingSiteKeyVisiblePass)
	solution, err := SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, 50_000_000)
	if err != nil {
		t.Fatalf("SolvePoW failed: %v", err)
	}
	result, err := cc.CompleteTurnstileInteraction("ts-siteverify", solution, turnstileHumanEvents(), nil, "localhost")
	if err != nil {
		t.Fatalf("CompleteTurnstileInteraction failed: %v", err)
	}

	form := url.Values{
		"secret":   {cc.GetTurnstileSecretKey()},
		"response": {result.TurnstileToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/turnstile/v0/siteverify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	cc.HandleTurnstileSiteVerify(w, req)

	var verify VerificationResult
	if err := json.NewDecoder(w.Body).Decode(&verify); err != nil {
		t.Fatalf("decode verify response: %v", err)
	}
	if !verify.Success {
		t.Fatalf("expected success, got %#v", verify)
	}
}

func turnstileHumanEvents() []CaptchaEvent {
	now := time.Now().UnixMilli()
	return []CaptchaEvent{
		{Type: "mousemove", Timestamp: now, X: 10, Y: 10},
		{Type: "mousemove", Timestamp: now + 45, X: 22, Y: 16},
		{Type: "mousemove", Timestamp: now + 92, X: 31, Y: 21},
		{Type: "mousedown", Timestamp: now + 140, X: 31, Y: 21},
		{Type: "mouseup", Timestamp: now + 170, X: 31, Y: 21},
		{Type: "click", Timestamp: now + 175, X: 31, Y: 21},
	}
}
