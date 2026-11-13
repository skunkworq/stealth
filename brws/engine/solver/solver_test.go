package solver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/skunkworq/stealth/brws/engine"
)

func TestHTTPSolverFetchesThroughTheService(t *testing.T) {
	t.Parallel()

	var got FetchRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/fetch" {
			t.Errorf("path = %q, want /v1/fetch", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(FetchResponse{
			Status: 200,
			URL:    "https://example.com/",
			HTML:   "<html><body>hello</body></html>",
			Headers: map[string]string{
				"Content-Type": "text/html; charset=utf-8",
			},
			Solver: "scrapling",
		}); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	defer server.Close()

	s, err := NewHTTPSolver("scrapling", "STEALTH_SOLVER_SCRAPLING_URL", engine.Options{Endpoint: server.URL})
	if err != nil {
		t.Fatalf("NewHTTPSolver: %v", err)
	}
	resp, err := s.Do(context.Background(), &engine.Request{URL: "https://example.com"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.Status != 200 {
		t.Errorf("status = %d, want 200", resp.Status)
	}
	if string(resp.Body) != "<html><body>hello</body></html>" {
		t.Errorf("body = %q", resp.Body)
	}
	if resp.FinalURL != "https://example.com/" {
		t.Errorf("final URL = %q", resp.FinalURL)
	}
	if ct := resp.Headers["Content-Type"]; len(ct) != 1 || ct[0] != "text/html; charset=utf-8" {
		t.Errorf("content type header = %v", ct)
	}
	if got.URL != "https://example.com" {
		t.Errorf("service saw url %q", got.URL)
	}
	if !got.Solve {
		t.Error("service did not receive solve=true")
	}
}

func TestHTTPSolverNeedsAnEndpoint(t *testing.T) {
	t.Setenv("STEALTH_SOLVER_SCRAPLING_URL", "")
	if _, err := NewHTTPSolver("scrapling", "STEALTH_SOLVER_SCRAPLING_URL", engine.Options{}); err == nil {
		t.Fatal("expected an error without an endpoint")
	}
}

func TestHTTPSolverReadsTheEnvironmentEndpoint(t *testing.T) {
	t.Setenv("STEALTH_SOLVER_SCRAPLING_URL", "http://solver.local:9000")
	s, err := NewHTTPSolver("scrapling", "STEALTH_SOLVER_SCRAPLING_URL", engine.Options{})
	if err != nil {
		t.Fatalf("NewHTTPSolver: %v", err)
	}
	hs, ok := s.(*HTTPSolver)
	if !ok {
		t.Fatalf("solver is %T", s)
	}
	if hs.baseURL != "http://solver.local:9000" {
		t.Errorf("base URL = %q", hs.baseURL)
	}
}

func TestHTTPSolverSurfacesAServiceError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(FetchResponse{Error: "challenge timed out"}); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	defer server.Close()

	s, err := NewHTTPSolver("scrapling", "STEALTH_SOLVER_SCRAPLING_URL", engine.Options{Endpoint: server.URL})
	if err != nil {
		t.Fatalf("NewHTTPSolver: %v", err)
	}
	if _, err := s.Do(context.Background(), &engine.Request{URL: "https://example.com"}); err == nil {
		t.Fatal("expected an error from the service")
	}
}

func TestFlareSolverrReusesOneSession(t *testing.T) {
	t.Parallel()

	var creates, destroys, gets int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode command: %v", err)
		}
		cmd, _ := payload["cmd"].(string)
		w.Header().Set("Content-Type", "application/json")
		switch cmd {
		case "sessions.create":
			creates++
			if err := json.NewEncoder(w).Encode(map[string]any{"session_id": "sess-1"}); err != nil {
				t.Errorf("encode create: %v", err)
			}
		case "sessions.destroy":
			destroys++
			if err := json.NewEncoder(w).Encode(map[string]any{"status": "ok"}); err != nil {
				t.Errorf("encode destroy: %v", err)
			}
		case "request.get":
			gets++
			if payload["session"] != "sess-1" {
				t.Errorf("request carried session %v", payload["session"])
			}
			if err := json.NewEncoder(w).Encode(map[string]any{
				"status": "ok",
				"solution": map[string]any{
					"status":   200,
					"url":      "https://example.com/",
					"response": "<html>flare</html>",
				},
			}); err != nil {
				t.Errorf("encode solution: %v", err)
			}
		default:
			t.Errorf("unexpected cmd %q", cmd)
		}
	}))
	defer server.Close()

	f, err := NewFlareSolverr(engine.Options{Endpoint: server.URL})
	if err != nil {
		t.Fatalf("NewFlareSolverr: %v", err)
	}
	for i := 0; i < 3; i++ {
		resp, err := f.Do(context.Background(), &engine.Request{URL: "https://example.com"})
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		if string(resp.Body) != "<html>flare</html>" {
			t.Errorf("body = %q", resp.Body)
		}
	}
	if creates != 1 {
		t.Errorf("sessions created = %d, want 1 (the session is reused)", creates)
	}
	if gets != 3 {
		t.Errorf("requests = %d, want 3", gets)
	}
	if destroys != 0 {
		t.Errorf("sessions destroyed = %d, want 0", destroys)
	}
}

func TestFlareSolverrRotatesAnExhaustedSession(t *testing.T) {
	t.Parallel()

	var creates, destroys int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode command: %v", err)
		}
		cmd, _ := payload["cmd"].(string)
		w.Header().Set("Content-Type", "application/json")
		switch cmd {
		case "sessions.create":
			creates++
			if err := json.NewEncoder(w).Encode(map[string]any{"session_id": "sess"}); err != nil {
				t.Errorf("encode create: %v", err)
			}
		case "sessions.destroy":
			destroys++
			if err := json.NewEncoder(w).Encode(map[string]any{"status": "ok"}); err != nil {
				t.Errorf("encode destroy: %v", err)
			}
		default:
			if err := json.NewEncoder(w).Encode(map[string]any{
				"status":   "ok",
				"solution": map[string]any{"status": 200, "response": "ok"},
			}); err != nil {
				t.Errorf("encode solution: %v", err)
			}
		}
	}))
	defer server.Close()

	f, err := NewFlareSolverr(engine.Options{Endpoint: server.URL})
	if err != nil {
		t.Fatalf("NewFlareSolverr: %v", err)
	}
	fs := f.(*FlareSolverr)
	fs.maxRequests = 2

	for i := 0; i < 3; i++ {
		if _, err := f.Do(context.Background(), &engine.Request{URL: "https://example.com"}); err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	if creates != 2 {
		t.Errorf("sessions created = %d, want 2 (one session is recycled after maxRequests)", creates)
	}
	if destroys != 1 {
		t.Errorf("sessions destroyed = %d, want 1", destroys)
	}
}

func TestFlareSolverrNeedsAnEndpoint(t *testing.T) {
	t.Setenv(DefaultFlareSolverrEnvVar, "")
	if _, err := NewFlareSolverr(engine.Options{}); err == nil {
		t.Fatal("expected an error without an endpoint")
	}
}

func TestSolverEnginesAreRegistered(t *testing.T) {
	t.Parallel()

	available := engine.Available()
	for _, want := range []string{"flaresolverr", "scrapling", "browseruse"} {
		found := false
		for _, name := range available {
			if name == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("engine %q is not registered (have %v)", want, available)
		}
	}
}

func TestHTTPSolverHonoursTheRequestTimeout(t *testing.T) {
	t.Parallel()

	var got FetchRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(FetchResponse{Status: 200, HTML: "ok"}); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	defer server.Close()

	s, err := NewHTTPSolver("scrapling", "STEALTH_SOLVER_SCRAPLING_URL", engine.Options{Endpoint: server.URL})
	if err != nil {
		t.Fatalf("NewHTTPSolver: %v", err)
	}
	_, err = s.Do(context.Background(), &engine.Request{URL: "https://example.com", Timeout: 45 * time.Second})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got.TimeoutMS != 45000 {
		t.Errorf("timeout_ms = %d, want 45000", got.TimeoutMS)
	}
}
