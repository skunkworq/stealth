package stealth

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/skunkworq/stealth/brws/adversarial"
)

func TestHandleTurnstileLabIncludesTelemetryAndVerification(t *testing.T) {
	ts, cc := mountCloudflareServer()
	defer ts.Close()

	solver := NewCloudflareSolverClient()
	solver.SetTurnstileVerificationAdapter(NewLabTurnstileVerifier(ts.URL, cc.GetTurnstileSecretKey()))

	result, err := solver.HandleTurnstileLab(ts.URL)
	if err != nil {
		t.Fatalf("HandleTurnstileLab failed: %v", err)
	}

	if !result.Passed {
		t.Fatal("expected turnstile lab flow to pass")
	}
	if result.Widget == nil {
		t.Fatal("expected widget config")
	}
	if result.Token == nil || result.Token.Token == "" {
		t.Fatal("expected structured turnstile token")
	}
	if result.Verification == nil || !result.Verification.Success {
		t.Fatalf("expected verification success, got %#v", result.Verification)
	}
	if result.Telemetry == nil || result.Telemetry.EventCount == 0 || result.Telemetry.MouseMoves == 0 {
		t.Fatalf("expected telemetry to be collected, got %#v", result.Telemetry)
	}
	if result.ClearanceCookie == nil {
		t.Fatal("expected clearance cookie")
	}
}

func TestHandleTurnstileLabRejectsUnallowlistedHost(t *testing.T) {
	solver := NewCloudflareSolverClient()

	_, err := solver.HandleTurnstileLab("https://example.com")
	if err == nil {
		t.Fatal("expected non-allowlisted host to be rejected")
	}
	if !strings.Contains(err.Error(), "allowlisted") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOfficialTurnstileTestVerifierRejectsHostnameMismatch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"challenge_ts":"2026-03-12T10:00:00Z","hostname":"evil.example"}`))
	}))
	defer ts.Close()

	verifier := NewOfficialTurnstileTestVerifier("dummy-secret", "owned.example")
	verifier.Endpoint = ts.URL

	result, err := verifier.VerifyToken(t.Context(), adversarial.TurnstileTestingDummyToken)
	if err != nil {
		t.Fatalf("VerifyToken failed: %v", err)
	}
	if result.Success {
		t.Fatalf("expected hostname mismatch failure, got %#v", result)
	}
	if len(result.ErrorCodes) == 0 || result.ErrorCodes[0] != "hostname-mismatch" {
		t.Fatalf("expected hostname-mismatch, got %#v", result.ErrorCodes)
	}
}

func TestOfficialTurnstileDummyTokenIntegration(t *testing.T) {
	if os.Getenv("STEALTH_RUN_CLOUDFLARE_TESTMODE") == "" {
		t.Skip("set STEALTH_RUN_CLOUDFLARE_TESTMODE=1 to exercise Cloudflare's public test-mode siteverify endpoint")
	}

	verifier := NewOfficialTurnstileTestVerifier(adversarial.TurnstileTestingSecretKeyPass)
	start := time.Now()
	result, err := verifier.VerifyToken(t.Context(), adversarial.TurnstileTestingDummyToken)
	if err != nil {
		t.Fatalf("VerifyToken failed: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success with Cloudflare dummy token, got %#v", result)
	}
	t.Logf("official test-mode verification succeeded in %dms for hostname=%s", time.Since(start).Milliseconds(), result.Hostname)
}
