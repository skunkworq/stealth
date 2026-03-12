package adversarial

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

func TestTurnstileWidgetBrowserFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser regression in short mode")
	}

	cc := NewCloudflareChallenger(nil, nil)
	mux := http.NewServeMux()
	cc.MountRoutes(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), chromedp.DefaultExecAllocatorOptions[:]...)
	defer cancelAlloc()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	var token string
	var sessionID string
	var state string
	err := chromedp.Run(ctx,
		chromedp.EmulateViewport(1280, 900),
		chromedp.Navigate(ts.URL+"/api/cloudflare/turnstile/widget"),
		chromedp.WaitVisible(`#turnstile-checkbox`, chromedp.ByID),
		chromedp.Click(`#turnstile-checkbox`, chromedp.ByID),
		chromedp.Sleep(2*time.Second),
		chromedp.Value(`#cf-turnstile-response`, &token, chromedp.ByID),
		chromedp.AttributeValue(`#cf-turnstile-widget`, "data-session-id", &sessionID, nil, chromedp.ByID),
		chromedp.Text(`#turnstile-state`, &state, chromedp.ByID),
	)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "executable file not found") ||
			strings.Contains(strings.ToLower(err.Error()), "chrome") {
			t.Skipf("chromium not available: %v", err)
		}
		t.Fatalf("chromedp flow failed: %v", err)
	}

	if token == "" {
		t.Fatal("expected widget to issue a token")
	}
	if sessionID == "" {
		t.Fatal("expected widget page to expose session id")
	}
	if !strings.Contains(strings.ToLower(state), "complete") {
		t.Fatalf("expected completion state, got %q", state)
	}

	statusResp, err := http.Get(ts.URL + "/api/cloudflare/status?session_id=" + sessionID)
	if err != nil {
		t.Fatalf("status request failed: %v", err)
	}
	defer statusResp.Body.Close()
	body, _ := io.ReadAll(statusResp.Body)

	var status struct {
		CallbackState *WidgetCallbackState `json:"callback_state"`
	}
	if err := json.Unmarshal(body, &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status.CallbackState == nil {
		t.Fatalf("expected callback state in status response: %s", string(body))
	}
	if !status.CallbackState.Rendered || !status.CallbackState.Executed || !status.CallbackState.Succeeded {
		t.Fatalf("expected render/execute/success lifecycle, got %#v", status.CallbackState)
	}

	mobileCtx, cancelMobile := chromedp.NewContext(allocCtx)
	defer cancelMobile()

	var frameWidth float64
	err = chromedp.Run(mobileCtx,
		chromedp.EmulateViewport(390, 844),
		chromedp.Navigate(ts.URL+"/api/cloudflare/turnstile/widget"),
		chromedp.WaitVisible(`#turnstile-frame`, chromedp.ByID),
		chromedp.Evaluate(`document.getElementById("turnstile-frame").getBoundingClientRect().width`, &frameWidth),
	)
	if err != nil {
		t.Fatalf("mobile render flow failed: %v", err)
	}
	if frameWidth > 390 {
		t.Fatalf("expected widget frame to fit mobile viewport, got %.2fpx", frameWidth)
	}
}
