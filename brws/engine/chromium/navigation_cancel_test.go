package chromium

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/skunkworq/stealth/brws/engine"
)

func TestBrowserNavigationHonorsCallerCancellation(t *testing.T) {
	browser := "/Applications/Chromium.app/Contents/MacOS/Chromium"
	if _, err := os.Stat(browser); err != nil {
		browser = ""
		for _, name := range []string{"chromium", "chromium-browser", "google-chrome"} {
			if path, lookupErr := exec.LookPath(name); lookupErr == nil {
				browser = path
				break
			}
		}
		if browser == "" {
			t.Skip("local Chromium unavailable")
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(4 * time.Second):
			}
		}
		_, _ = w.Write([]byte("<html>ok</html>"))
	}))
	defer srv.Close()
	for _, tc := range []struct {
		name string
		new  func(engine.Options) (engine.Engine, error)
	}{{"chromium", New}, {"stealth", NewStealth}} {
		t.Run(tc.name, func(t *testing.T) {
			e, err := tc.new(engine.Options{Headless: true, ExecutablePath: browser})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = e.Close() }()
			if _, err = e.Do(context.Background(), &engine.Request{URL: srv.URL, Timeout: 20 * time.Second, WaitForNavigation: true}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			start := time.Now()
			_, err = e.Do(ctx, &engine.Request{URL: srv.URL + "/slow", Timeout: 10 * time.Second, WaitForNavigation: true})
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expected caller deadline, got %v", err)
			}
			if elapsed := time.Since(start); elapsed > 3*time.Second {
				t.Fatalf("caller cancellation took %s", elapsed)
			}
			if _, err := e.Do(context.Background(), &engine.Request{URL: srv.URL, Timeout: 20 * time.Second, WaitForNavigation: true}); err != nil {
				t.Fatalf("browser unusable after cancelling tab: %v", err)
			}
		})
	}
}
