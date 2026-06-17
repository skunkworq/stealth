package stealth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	_ "github.com/skunkworq/stealth/brws/engine/chromium"
)

// chromiumAvailable returns true if a chrome/chromium binary is on PATH.
// chromedp falls back to looking for "google-chrome", "chromium", etc.
func chromiumAvailable() bool {
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"} {
		if _, err := exec.LookPath(name); err == nil {
			return true
		}
	}
	// macOS app bundle
	if _, err := os.Stat("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"); err == nil {
		return true
	}
	if _, err := os.Stat("/Applications/Chromium.app/Contents/MacOS/Chromium"); err == nil {
		return true
	}
	return false
}

const dynamicFormPage = `<!doctype html>
<html><body>
<div id="container"></div>
<script>
setTimeout(function() {
  var form = document.createElement('form');
  form.id = 'late-form';
  var input = document.createElement('input');
  input.name = 'late-search';
  input.type = 'search';
  form.appendChild(input);
  document.getElementById('container').appendChild(form);
}, 500);
</script>
</body></html>`

// TestNavigateWithOptions_AdditionalSleep verifies that AdditionalSleep gives
// JS time to inject DOM nodes before HTML capture.
func TestNavigateWithOptions_AdditionalSleep(t *testing.T) {
	if !chromiumAvailable() {
		t.Skip("chromium binary not available")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(dynamicFormPage))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.EngineName = "chromium"
	cfg.Headless = true
	cfg.Stealth.Enabled = false
	cfg.Challenge.AutoSolve = false
	cfg.Challenge.AutoDetect = false
	cfg.EvasionFSMDisabled = true
	client, err := NewWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewWithConfig: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.NavigateWithOptions(ctx, srv.URL, NavigateOptions{
		WaitForLoad:     true,
		AdditionalSleep: 1500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NavigateWithOptions: %v", err)
	}
	body := string(resp.Body)
	if !strings.Contains(body, `id="late-form"`) {
		t.Fatalf("expected late-injected form in body, got: %s", body)
	}
	if !strings.Contains(body, `name="late-search"`) {
		t.Fatalf("expected late-injected input in body, got: %s", body)
	}
}
