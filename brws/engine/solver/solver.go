// Package solver provides Engine implementations that delegate a fetch to an
// external solver service — a stealth HTTP stack or a browser farm that runs
// somewhere other than this process.
//
// The motivation is the wall classes a local browser cannot clear. An Akamai
// edge deny is keyed on the client fingerprint and the egress reputation of
// the request; a Cloudflare interstitial may need a solver's warm session
// rather than a fresh fingerprint. Neither is fixed by trying harder with the
// same browser, and both are answered by a different client.
//
// Three services speak the same small JSON protocol, so one client drives all
// of them — Scrapling, browser-use, and any sidecar that implements it:
//
//	POST {base}/v1/fetch
//	{"url": "https://example.com", "method": "GET", "headers": {...},
//	 "timeout_ms": 30000, "wait_ms": 0, "solve": true}
//	→ 200 {"status": 200, "url": "https://example.com/", "html": "<html>…",
//	       "headers": {...}, "solver": "scrapling", "elapsed_ms": 1234}
//
// FlareSolverr has its own API and gets its own engine in this package.
//
// Every engine here is optional: when its endpoint is unset the constructor
// returns an error and the caller drops it from the escalation chain.
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
	"sync/atomic"
	"time"

	"github.com/skunkworq/stealth/brws/engine"
)

// FetchRequest is the JSON body a solver service accepts.
type FetchRequest struct {
	URL       string            `json:"url"`
	Method    string            `json:"method,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	TimeoutMS int               `json:"timeout_ms,omitempty"`
	WaitMS    int               `json:"wait_ms,omitempty"`
	// Solve asks the service to attempt challenge solving rather than just
	// fetching. Services that cannot solve may ignore it.
	Solve bool `json:"solve,omitempty"`
}

// FetchResponse is the JSON body a solver service returns.
type FetchResponse struct {
	Status    int               `json:"status"`
	URL       string            `json:"url,omitempty"`
	HTML      string            `json:"html,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Solver    string            `json:"solver,omitempty"`
	ElapsedMS int               `json:"elapsed_ms,omitempty"`
	Error     string            `json:"error,omitempty"`
}

// defaultSolverTimeout bounds one solver call. A challenge solve can take
// tens of seconds, so this is generous compared to a plain HTTP timeout.
const defaultSolverTimeout = 90 * time.Second

// HTTPSolver is an Engine that fetches through an external solver service
// speaking the JSON protocol described in the package doc.
//
// It is the adapter for every service that implements that protocol:
// Scrapling, browser-use, and anything else that wants to be a tier.
type HTTPSolver struct {
	name     string
	baseURL  string
	client   *http.Client
	path     string
	waitMS   int
	solve    bool
	reqs     int64
	failures int64
}

// NewHTTPSolver creates a solver engine for a service speaking the JSON
// protocol. opts.Endpoint is the service base URL; when it is empty the
// engine's environment variable is used (envVar, e.g.
// "STEALTH_SOLVER_SCRAPLING_URL").
//
// The fetch path is "/v1/fetch" unless overridden with opts.CustomHeaders'
// sibling — solvers that expose a different route pass it explicitly.
func NewHTTPSolver(name, envVar string, opts engine.Options) (engine.Engine, error) {
	base := strings.TrimRight(strings.TrimSpace(opts.Endpoint), "/")
	if base == "" {
		base = strings.TrimRight(strings.TrimSpace(os.Getenv(envVar)), "/")
	}
	if base == "" {
		return nil, fmt.Errorf("solver %s: no endpoint (set %s)", name, envVar)
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultSolverTimeout
	}
	return &HTTPSolver{
		name: name,
		// Asking the service to solve is the point of a solver tier: a
		// service that cannot solve may ignore the flag, but one that can
		// should be asked.
		solve:   true,
		baseURL: base,
		client:  &http.Client{Timeout: timeout + 10*time.Second},
		path:    "/v1/fetch",
	}, nil
}

// Name returns the engine identifier.
func (s *HTTPSolver) Name() string { return s.name }

// Capabilities reports what the solver can do. A solver service renders
// JavaScript, but only if it says so — the protocol's response carries no
// such flag, so the safe answer is "it does not".
func (s *HTTPSolver) Capabilities() engine.Capabilities {
	return engine.Capabilities{JavaScript: false}
}

// Close releases the HTTP client.
func (s *HTTPSolver) Close() error { return nil }

// Do fetches the URL through the solver service.
func (s *HTTPSolver) Do(ctx context.Context, req *engine.Request) (*engine.Response, error) {
	if req == nil || strings.TrimSpace(req.URL) == "" {
		return nil, fmt.Errorf("solver %s: empty request URL", s.name)
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	headers := map[string]string{}
	for k, vs := range req.Headers {
		if len(vs) > 0 {
			headers[k] = vs[0]
		}
	}
	for k, v := range req.ExtraHeaders {
		headers[k] = v
	}
	timeoutMS := int(req.Timeout / time.Millisecond)
	if timeoutMS <= 0 {
		timeoutMS = int(defaultSolverTimeout / time.Millisecond)
	}

	payload := FetchRequest{
		URL:       req.URL,
		Method:    method,
		Headers:   headers,
		TimeoutMS: timeoutMS,
		WaitMS:    s.waitMS,
		Solve:     s.solve,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("solver %s: encode request: %w", s.name, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+s.path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("solver %s: build request: %w", s.name, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	atomic.AddInt64(&s.reqs, 1)
	resp, err := s.client.Do(httpReq)
	if err != nil {
		atomic.AddInt64(&s.failures, 1)
		return nil, fmt.Errorf("solver %s: %w", s.name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		atomic.AddInt64(&s.failures, 1)
		return nil, fmt.Errorf("solver %s: read response: %w", s.name, err)
	}
	if resp.StatusCode != http.StatusOK {
		atomic.AddInt64(&s.failures, 1)
		return nil, fmt.Errorf("solver %s: HTTP %d: %s", s.name, resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var out FetchResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		atomic.AddInt64(&s.failures, 1)
		return nil, fmt.Errorf("solver %s: decode response: %w", s.name, err)
	}
	if out.Error != "" {
		atomic.AddInt64(&s.failures, 1)
		return nil, fmt.Errorf("solver %s: %s", s.name, out.Error)
	}
	if out.Status == 0 {
		out.Status = http.StatusOK
	}
	finalURL := out.URL
	if finalURL == "" {
		finalURL = req.URL
	}
	respHeaders := map[string][]string{}
	for k, v := range out.Headers {
		respHeaders[k] = []string{v}
	}
	return &engine.Response{
		Status:     out.Status,
		StatusText: http.StatusText(out.Status),
		Headers:    respHeaders,
		Body:       []byte(out.HTML),
		FinalURL:   finalURL,
		Protocol:   "solver",
		Trace: engine.Trace{
			Engine: s.name,
			Raw:    map[string]any{"solver": out.Solver, "elapsed_ms": out.ElapsedMS},
		},
	}, nil
}
