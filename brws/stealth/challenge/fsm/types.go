// Package challengefsm provides a unified challenge-solving framework backed
// by per-solve FSMs. Each solver implements ChallengeSolver and drives a fresh
// FSM instance through provider-specific states.
package fsm

import (
	"context"
	"net/http"
	"time"

	"github.com/skunkworq/stealth/brws/browser/engine"
	"github.com/skunkworq/stealth/brws/core/constants"
	"github.com/skunkworq/stealth/brws/core/instrumentation"
	"github.com/skunkworq/stealth/brws/stealth/challenge"
)

// ChallengeSolver is the interface that all challenge solvers implement.
// Each solver wraps an existing solver (e.g., CloudflareSolverClient) or
// implements a new one (e.g., DataDomeFSMSolver).
type ChallengeSolver interface {
	// CanSolve returns true if this solver can handle the given challenge.
	CanSolve(ch *challenge.Challenge) bool

	// Solve attempts to solve the challenge, driving a per-solve FSM.
	// Returns a SolveResult on success or an error.
	Solve(cctx *ChallengeContext) (*SolveResult, error)

	// Provider returns the name of this solver (e.g., "cloudflare", "datadome").
	Provider() string
}

// ChallengeContext carries all the context needed by a solver to solve a challenge.
type ChallengeContext struct {
	Ctx       context.Context
	TargetURL string
	Response  *engine.Response
	Challenge *challenge.Challenge
	Engine    engine.Engine
	Config    *SolverConfig
	Logger    *instrumentation.Logger

	// TraceEvents are pre-generated behavioral events from trace replay.
	// When set, solvers use these instead of generating synthetic events.
	TraceEvents []challenge.CaptchaEvent
}

// SolveResult holds the outcome of a challenge solve attempt.
type SolveResult struct {
	Solved          bool
	Response        *engine.Response
	ClearanceCookie *http.Cookie
	Token           string
	Metrics         SolveAttemptMetrics
}

// SolveAttemptMetrics records timing and attempt data for a single solve.
type SolveAttemptMetrics struct {
	Provider   string
	StartTime  time.Time
	Duration   time.Duration
	Attempts   int
	FinalState string
	Success    bool
}

// SolverConfig holds configuration shared across solvers.
type SolverConfig struct {
	APIKey string
	// MaxRetries is the number of solve attempts before giving up.
	// Defaults to 1 via DefaultSolverConfig.
	MaxRetries int
	// Timeout is the per-solve deadline. Zero falls back to the timeout supplied
	// by the caller at HandleResponse time. Use DefaultSolverConfig to get
	// constants.DefaultTimeout as the explicit default.
	Timeout    time.Duration
	HumanDelay bool
	VerifyURL  string
}

// DefaultSolverConfig returns a SolverConfig with sensible defaults drawn from
// core/constants. Use this instead of constructing a zero-value struct.
func DefaultSolverConfig() *SolverConfig {
	return &SolverConfig{
		MaxRetries: 1,
		Timeout:    constants.DefaultTimeout,
		HumanDelay: true,
	}
}
