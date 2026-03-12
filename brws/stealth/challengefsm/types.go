// Package challengefsm provides a unified challenge-solving framework backed
// by per-solve FSMs. Each solver implements ChallengeSolver and drives a fresh
// FSM instance through provider-specific states.
package challengefsm

import (
	"context"
	"net/http"
	"time"

	"github.com/skunkworq/stealth/brws/challenge"
	"github.com/skunkworq/stealth/brws/engine"
	"github.com/skunkworq/stealth/brws/instrumentation"
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
	APIKey     string
	MaxRetries int
	Timeout    time.Duration
	HumanDelay bool
	VerifyURL  string
}
