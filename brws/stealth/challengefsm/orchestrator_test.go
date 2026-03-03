package challengefsm

import (
	"context"
	"testing"
	"time"

	"github.com/stealth/brwslab/brws/challenge"
	"github.com/stealth/brwslab/brws/engine"
	"github.com/stealth/brwslab/brws/instrumentation"
)

// mockSolver implements ChallengeSolver for testing.
type mockSolver struct {
	provider    string
	canSolve    bool
	solveResult *SolveResult
	solveErr    error
	solveCalls  int
}

func (m *mockSolver) CanSolve(_ *challenge.Challenge) bool { return m.canSolve }
func (m *mockSolver) Provider() string                     { return m.provider }
func (m *mockSolver) Solve(_ *ChallengeContext) (*SolveResult, error) {
	m.solveCalls++
	return m.solveResult, m.solveErr
}

func newTestLogger(t *testing.T) *instrumentation.Logger {
	t.Helper()
	logger, err := instrumentation.NewLogger(&instrumentation.Config{
		LogLevel: "warn",
	})
	if err != nil {
		t.Fatalf("create logger: %v", err)
	}
	return logger
}

func TestOrchestratorNoChallenge(t *testing.T) {
	registry := NewSolverRegistry()
	logger := newTestLogger(t)
	orch := NewChallengeOrchestrator(registry, nil, logger)

	resp := &engine.Response{
		Status:  200,
		Headers: map[string][]string{"Content-Type": {"text/html"}},
		Body:    []byte("<html>OK</html>"),
	}

	result, err := orch.HandleResponse(context.Background(), "https://example.com", resp, nil, 30*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != resp {
		t.Fatal("expected original response when no challenge detected")
	}
}

func TestOrchestratorDataDomeDetection(t *testing.T) {
	registry := NewSolverRegistry()
	logger := newTestLogger(t)

	solver := &mockSolver{
		provider: "datadome",
		canSolve: true,
		solveResult: &SolveResult{
			Solved:   true,
			Response: &engine.Response{Status: 200, Body: []byte("OK")},
		},
	}
	registry.Register(solver)

	orch := NewChallengeOrchestrator(registry, nil, logger)

	resp := &engine.Response{
		Status:  403,
		Headers: map[string][]string{"X-DataDome": {"protected"}},
		Body:    []byte("blocked by datadome"),
	}

	result, err := orch.HandleResponse(context.Background(), "https://example.com", resp, nil, 30*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != 200 {
		t.Fatalf("expected solved response status 200, got %d", result.Status)
	}
	if solver.solveCalls != 1 {
		t.Fatalf("expected 1 solve call, got %d", solver.solveCalls)
	}
}

func TestOrchestratorCloudflareDetection(t *testing.T) {
	registry := NewSolverRegistry()
	logger := newTestLogger(t)

	solver := &mockSolver{
		provider: "cloudflare",
		canSolve: true,
		solveResult: &SolveResult{
			Solved:   true,
			Response: &engine.Response{Status: 200, Body: []byte("CF OK")},
		},
	}
	registry.Register(solver)

	orch := NewChallengeOrchestrator(registry, nil, logger)

	// Cloudflare 503 challenge page
	resp := &engine.Response{
		Status: 503,
		Headers: map[string][]string{
			"Server": {"cloudflare"},
			"Cf-Ray": {"abc123-LAX"},
		},
		Body: []byte(`<html><head><title>Just a moment...</title></head><body>
			<div id="cf-browser-verification">
				<form id="challenge-form" action="/cdn-cgi/l/chk_jschl" method="get">
					<input type="hidden" name="jschl_vc" value="test123"/>
				</form>
			</div>
		</body></html>`),
	}

	result, err := orch.HandleResponse(context.Background(), "https://example.com", resp, nil, 30*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != 200 {
		t.Fatalf("expected solved response status 200, got %d", result.Status)
	}
}

func TestOrchestratorNoSolverRegistered(t *testing.T) {
	registry := NewSolverRegistry()
	logger := newTestLogger(t)
	orch := NewChallengeOrchestrator(registry, nil, logger)

	// DataDome challenge but no solver registered
	resp := &engine.Response{
		Status:  403,
		Headers: map[string][]string{"X-DataDome": {"protected"}},
		Body:    []byte("blocked by datadome"),
	}

	result, err := orch.HandleResponse(context.Background(), "https://example.com", resp, nil, 30*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should return original response when no solver is available
	if result != resp {
		t.Fatal("expected original response when no solver matches")
	}
}

func TestOrchestratorSolverPriority(t *testing.T) {
	registry := NewSolverRegistry()
	logger := newTestLogger(t)

	// Register two solvers that can both handle the same challenge
	highPriority := &mockSolver{
		provider: "high",
		canSolve: true,
		solveResult: &SolveResult{
			Solved:   true,
			Response: &engine.Response{Status: 200, Body: []byte("high priority")},
		},
	}
	lowPriority := &mockSolver{
		provider: "low",
		canSolve: true,
		solveResult: &SolveResult{
			Solved:   true,
			Response: &engine.Response{Status: 200, Body: []byte("low priority")},
		},
	}

	registry.Register(highPriority)
	registry.Register(lowPriority)

	orch := NewChallengeOrchestrator(registry, nil, logger)

	resp := &engine.Response{
		Status:  403,
		Headers: map[string][]string{"X-DataDome": {"protected"}},
		Body:    []byte("blocked"),
	}

	result, err := orch.HandleResponse(context.Background(), "https://example.com", resp, nil, 30*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result.Body) != "high priority" {
		t.Fatalf("expected high priority solver to be used, got: %s", string(result.Body))
	}
	if highPriority.solveCalls != 1 {
		t.Fatalf("expected high priority solver called once, got %d", highPriority.solveCalls)
	}
	if lowPriority.solveCalls != 0 {
		t.Fatalf("expected low priority solver not called, got %d", lowPriority.solveCalls)
	}
}

func TestOrchestratorMetricsRecording(t *testing.T) {
	registry := NewSolverRegistry()
	logger := newTestLogger(t)

	solver := &mockSolver{
		provider: "test",
		canSolve: true,
		solveResult: &SolveResult{
			Solved:   true,
			Response: &engine.Response{Status: 200},
		},
	}
	registry.Register(solver)

	orch := NewChallengeOrchestrator(registry, nil, logger)

	resp := &engine.Response{
		Status:  403,
		Headers: map[string][]string{"X-DataDome": {"protected"}},
		Body:    []byte("blocked"),
	}

	_, _ = orch.HandleResponse(context.Background(), "https://example.com", resp, nil, 30*time.Second)
	_, _ = orch.HandleResponse(context.Background(), "https://example.com", resp, nil, 30*time.Second)

	rate := orch.Metrics().SuccessRate("test")
	if rate != 1.0 {
		t.Fatalf("expected success rate 1.0, got %.2f", rate)
	}

	pm := orch.Metrics().GetProviderMetrics("test")
	if pm.TotalAttempts != 2 {
		t.Fatalf("expected 2 total attempts, got %d", pm.TotalAttempts)
	}
}

func TestUnifiedDetectorDataDome(t *testing.T) {
	detector := NewUnifiedDetector()

	tests := []struct {
		name    string
		headers map[string][]string
		body    []byte
		want    challenge.ChallengeType
	}{
		{
			name:    "x-datadome header",
			headers: map[string][]string{"X-DataDome": {"protected"}},
			body:    []byte(""),
			want:    challenge.ChallengeDataDome,
		},
		{
			name:    "datadome.js in body",
			headers: map[string][]string{},
			body:    []byte(`<script src="datadome.js"></script>`),
			want:    challenge.ChallengeDataDome,
		},
		{
			name:    "captcha-delivery URL",
			headers: map[string][]string{},
			body:    []byte(`location.href="https://geo.captcha-delivery.com/captcha/abc123"`),
			want:    challenge.ChallengeDataDome,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &engine.Response{
				Status:  403,
				Headers: tt.headers,
				Body:    tt.body,
			}
			ch := detector.Detect(resp)
			if ch == nil {
				t.Fatal("expected challenge to be detected")
			}
			if ch.Type != tt.want {
				t.Fatalf("expected type %s, got %s", tt.want, ch.Type)
			}
		})
	}
}

func TestUnifiedDetectorNil(t *testing.T) {
	detector := NewUnifiedDetector()
	ch := detector.Detect(nil)
	if ch != nil {
		t.Fatal("expected nil for nil response")
	}
}

func TestUnifiedDetectorCleanPage(t *testing.T) {
	detector := NewUnifiedDetector()
	resp := &engine.Response{
		Status:  200,
		Headers: map[string][]string{"Content-Type": {"text/html"}},
		Body:    []byte("<html><body>Hello World</body></html>"),
	}
	ch := detector.Detect(resp)
	if ch != nil {
		t.Fatalf("expected nil for clean page, got %+v", ch)
	}
}
