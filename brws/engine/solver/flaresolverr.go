package solver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/skunkworq/stealth/brws/engine"
)

// FlareSolverr is an Engine that fetches through a FlareSolverr service
// (https://github.com/FlareSolverr/FlareSolverr).
//
// FlareSolverr drives a real browser to clear Cloudflare interstitials and
// Turnstile challenges and returns the final HTML. It is the tier that
// answers walls a local browser cannot: the stealth engine's challenge FSM
// serves our browser the non-interactive Cloudflare variant (no Turnstile
// iframe renders at all), while FlareSolverr's session clears it.
//
// The session is created lazily and reused, so the browser keeps the cleared
// cookies between calls — a fresh solve per request is roughly ten times
// slower. Chrome instances leak under sustained churn, so the session is
// rotated after a bounded number of requests.
type FlareSolverr struct {
	baseURL string
	client  *http.Client
	path    string

	mu          sync.Mutex
	session     string
	sessionOpen bool
	maxRequests int
	requests    int
	timeoutMS   int

	reqs     int64
	failures int64
}

// DefaultFlareSolverrEnvVar is the environment variable read when no
// endpoint is configured on the engine options.
const DefaultFlareSolverrEnvVar = "STEALTH_SOLVER_FLARESOLVERR_URL"

// NewFlareSolverr creates a FlareSolverr engine. opts.Endpoint is the
// service base URL (e.g. "http://localhost:8191"); when empty the
// STEALTH_SOLVER_FLARESOLVERR_URL environment variable is used.
func NewFlareSolverr(opts engine.Options) (engine.Engine, error) {
	base := strings.TrimRight(strings.TrimSpace(opts.Endpoint), "/")
	if base == "" {
		base = strings.TrimRight(strings.TrimSpace(os.Getenv(DefaultFlareSolverrEnvVar)), "/")
	}
	if base == "" {
		return nil, fmt.Errorf("solver flaresolverr: no endpoint (set %s)", DefaultFlareSolverrEnvVar)
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultSolverTimeout
	}
	return &FlareSolverr{
		baseURL:     base,
		client:      &http.Client{Timeout: timeout + 30*time.Second},
		path:        "/v1",
		maxRequests: 15,
		timeoutMS:   int(timeout / time.Millisecond),
	}, nil
}

// Name returns the engine identifier.
func (f *FlareSolverr) Name() string { return "flaresolverr" }

// Capabilities reports what the engine supports. FlareSolverr renders
// JavaScript — that is the whole point of it.
func (f *FlareSolverr) Capabilities() engine.Capabilities {
	return engine.Capabilities{JavaScript: true}
}

// Close destroys the session, if one is open.
func (f *FlareSolverr) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.sessionOpen || f.session == "" {
		return nil
	}
	_, _ = f.command(context.Background(), map[string]any{
		"cmd":     "sessions.destroy",
		"session": f.session,
	})
	f.session = ""
	f.sessionOpen = false
	return nil
}

// Do fetches the URL through FlareSolverr.
func (f *FlareSolverr) Do(ctx context.Context, req *engine.Request) (*engine.Response, error) {
	if req == nil || strings.TrimSpace(req.URL) == "" {
		return nil, fmt.Errorf("solver flaresolverr: empty request URL")
	}
	atomic.AddInt64(&f.reqs, 1)

	session, err := f.ensureSession(ctx)
	if err != nil {
		atomic.AddInt64(&f.failures, 1)
		return nil, err
	}

	payload := map[string]any{
		"cmd":        "request.get",
		"url":        req.URL,
		"maxTimeout": f.timeoutMS,
		"session":    session,
	}
	raw, err := f.command(ctx, payload)
	if err != nil {
		// A session error is recoverable: rotate once and retry. A second
		// failure propagates.
		f.rotateSession(ctx)
		atomic.AddInt64(&f.failures, 1)
		return nil, fmt.Errorf("solver flaresolverr: %w", err)
	}

	var out struct {
		Status   string `json:"status"`
		Message  string `json:"message"`
		Solution struct {
			URL      string            `json:"url"`
			Status   int               `json:"status"`
			Response string            `json:"response"`
			Headers  map[string]string `json:"headers"`
		} `json:"solution"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		atomic.AddInt64(&f.failures, 1)
		return nil, fmt.Errorf("solver flaresolverr: decode response: %w", err)
	}
	if !strings.EqualFold(out.Status, "ok") {
		atomic.AddInt64(&f.failures, 1)
		msg := out.Message
		if msg == "" {
			msg = out.Status
		}
		return nil, fmt.Errorf("solver flaresolverr: %s", msg)
	}

	finalURL := out.Solution.URL
	if finalURL == "" {
		finalURL = req.URL
	}
	respHeaders := map[string][]string{}
	for k, v := range out.Solution.Headers {
		respHeaders[k] = []string{v}
	}
	status := out.Solution.Status
	if status == 0 {
		status = http.StatusOK
	}
	return &engine.Response{
		Status:     status,
		StatusText: http.StatusText(status),
		Headers:    respHeaders,
		Body:       []byte(out.Solution.Response),
		FinalURL:   finalURL,
		Protocol:   "solver",
		Trace: engine.Trace{
			Engine: "flaresolverr",
			Raw:    map[string]any{"session": session},
		},
	}, nil
}

// ensureSession returns a live session id, creating one when needed and
// rotating it once it has served too many requests.
func (f *FlareSolverr) ensureSession(ctx context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sessionOpen && f.session != "" && f.requests < f.maxRequests {
		f.requests++
		return f.session, nil
	}
	if f.sessionOpen && f.session != "" {
		// Too many requests on this session: Chrome instances leak under
		// sustained churn, so recycle before it wedges.
		_, _ = f.command(ctx, map[string]any{"cmd": "sessions.destroy", "session": f.session})
		f.session = ""
		f.sessionOpen = false
		f.requests = 0
	}
	raw, err := f.command(ctx, map[string]any{"cmd": "sessions.create"})
	if err != nil {
		return "", fmt.Errorf("solver flaresolverr: create session: %w", err)
	}
	var out struct {
		// FlareSolverr names the id "session"; older builds and some
		// proxies answer "session_id". Accept either.
		Session   string `json:"session"`
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("solver flaresolverr: decode session: %w", err)
	}
	sessionID := out.Session
	if sessionID == "" {
		sessionID = out.SessionID
	}
	if sessionID == "" {
		return "", fmt.Errorf("solver flaresolverr: service returned no session id")
	}
	f.session = sessionID
	f.sessionOpen = true
	f.requests = 1
	return f.session, nil
}

// rotateSession destroys the current session so the next call creates one.
func (f *FlareSolverr) rotateSession(ctx context.Context) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sessionOpen && f.session != "" {
		_, _ = f.command(ctx, map[string]any{"cmd": "sessions.destroy", "session": f.session})
	}
	f.session = ""
	f.sessionOpen = false
	f.requests = 0
}

// command posts one FlareSolverr command and returns the raw response body.
func (f *FlareSolverr) command(ctx context.Context, payload map[string]any) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode command: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.baseURL+f.path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build command: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("read command response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}
