package solver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTestTwoCaptcha builds a TwoCaptchaSolver wired to a test server.
func newTestTwoCaptcha(srvURL string) *TwoCaptchaSolver {
	return &TwoCaptchaSolver{
		apiKey:   "test-key",
		client:   &http.Client{Timeout: 5 * time.Second},
		timeout:  3 * time.Second,
		pollRate: 25 * time.Millisecond,
		inURL:    srvURL + "/in.php",
		resURL:   srvURL + "/res.php",
	}
}

func TestTwoCaptchaSolveRecaptchaV2_Success(t *testing.T) {
	var polls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/in.php", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if got := r.Form.Get("method"); got != "userrecaptcha" {
			t.Errorf("method = %q, want userrecaptcha", got)
		}
		if got := r.Form.Get("googlekey"); got != "site-key-abc" {
			t.Errorf("googlekey = %q", got)
		}
		if got := r.Form.Get("pageurl"); got != "https://example.com/login" {
			t.Errorf("pageurl = %q", got)
		}
		_, _ = w.Write([]byte(`{"status":1,"request":"1234"}`))
	})
	mux.HandleFunc("/res.php", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") != "1234" {
			t.Errorf("id = %q", r.URL.Query().Get("id"))
		}
		n := atomic.AddInt32(&polls, 1)
		if n < 3 {
			_, _ = w.Write([]byte(`{"status":0,"request":"CAPCHA_NOT_READY"}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":1,"request":"03AGdBq..token..XYZ"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tc := newTestTwoCaptcha(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	token, err := tc.SolveRecaptchaV2(ctx, "site-key-abc", "https://example.com/login")
	if err != nil {
		t.Fatalf("SolveRecaptchaV2: %v", err)
	}
	if !strings.Contains(token, "token") {
		t.Errorf("token = %q", token)
	}
	if atomic.LoadInt32(&polls) < 3 {
		t.Errorf("expected at least 3 polls, got %d", polls)
	}
}

func TestTwoCaptchaSolveRecaptchaV2_BadKey(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/in.php", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":0,"request":"ERROR_KEY_DOES_NOT_EXIST"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tc := newTestTwoCaptcha(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := tc.SolveRecaptchaV2(ctx, "k", "https://example.com")
	if err == nil || !strings.Contains(err.Error(), "ERROR_KEY_DOES_NOT_EXIST") {
		t.Fatalf("expected ERROR_KEY_DOES_NOT_EXIST error, got %v", err)
	}
}

func TestTwoCaptchaSolveRecaptchaV2_Timeout(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/in.php", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":1,"request":"42"}`))
	})
	mux.HandleFunc("/res.php", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":0,"request":"CAPCHA_NOT_READY"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tc := newTestTwoCaptcha(srv.URL)
	tc.timeout = 100 * time.Millisecond
	tc.pollRate = 25 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := tc.SolveRecaptchaV2(ctx, "k", "https://example.com")
	if err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func TestTwoCaptchaGetBalance(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/res.php", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("action") != "getbalance" {
			t.Errorf("action = %q", r.URL.Query().Get("action"))
		}
		_, _ = w.Write([]byte(`{"status":1,"request":"5.123"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tc := newTestTwoCaptcha(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	bal, err := tc.GetBalance(ctx)
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if bal < 5.12 || bal > 5.13 {
		t.Errorf("balance = %v, want ~5.123", bal)
	}
}

func TestNewSolverTwoCaptcha(t *testing.T) {
	s, err := NewSolver(SolverConfig{Provider: "twocaptcha", APIKey: "abc"})
	if err != nil {
		t.Fatalf("NewSolver: %v", err)
	}
	if _, ok := s.(*TwoCaptchaSolver); !ok {
		t.Fatalf("got %T, want *TwoCaptchaSolver", s)
	}
	s2, err := NewSolver(SolverConfig{Provider: "2captcha", APIKey: "abc"})
	if err != nil {
		t.Fatalf("NewSolver 2captcha alias: %v", err)
	}
	if _, ok := s2.(*TwoCaptchaSolver); !ok {
		t.Fatalf("alias: got %T", s2)
	}
}
