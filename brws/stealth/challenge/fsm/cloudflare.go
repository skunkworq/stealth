package fsm

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/skunkworq/stealth/brws/stealth/challenge"
	"github.com/skunkworq/stealth/brws/browser/engine"
	"github.com/skunkworq/stealth/brws/core/instrumentation"
)

// CloudflareSolveResult mirrors stealth.CloudflareSolveResult for the interface.
type CloudflareSolveResult struct {
	SessionID        string
	ChallengeType    string
	Passed           bool
	ClearanceCookie  *http.Cookie
	TurnstileToken   string
	PoWTimeMs        int64
	TotalTimeMs      int64
	PoWIterations    int64
	PoWDifficulty    int
	BehavioralScore  float64
	FingerprintScore float64
}

// CFDetectFunc is a function that detects Cloudflare challenges from a response.
type CFDetectFunc func(resp *engine.Response) *challenge.CloudflareChallenge

// CFSolveFunc is a function that solves a detected CF challenge and returns a new response.
type CFSolveFunc func(ctx context.Context, targetURL string, resp *engine.Response, ch *challenge.CloudflareChallenge) (*engine.Response, error)

// CloudflareFSMSolver wraps the existing CloudflareSolverClient behind the
// ChallengeSolver interface, driving a per-solve Cloudflare FSM.
type CloudflareFSMSolver struct {
	detectCF CFDetectFunc
	solveCF  CFSolveFunc
}

// NewCloudflareFSMSolver creates a new CloudflareFSMSolver.
// detectCF and solveCF are typically bound to the Client's detectCFChallenge
// and solveCFChallenge methods.
func NewCloudflareFSMSolver(detectCF CFDetectFunc, solveCF CFSolveFunc) *CloudflareFSMSolver {
	return &CloudflareFSMSolver{
		detectCF: detectCF,
		solveCF:  solveCF,
	}
}

// CanSolve returns true for Cloudflare and Turnstile challenge types.
func (s *CloudflareFSMSolver) CanSolve(ch *challenge.Challenge) bool {
	switch ch.Type {
	case challenge.ChallengeCloudflare, challenge.ChallengeTurnstile:
		return true
	default:
		return false
	}
}

// Provider returns "cloudflare".
func (s *CloudflareFSMSolver) Provider() string {
	return "cloudflare"
}

// Solve drives the Cloudflare FSM through detection → solving → submission.
func (s *CloudflareFSMSolver) Solve(cctx *ChallengeContext) (*SolveResult, error) {
	start := time.Now()
	fsm := NewCloudflareFSM()
	fsm.SetTransitionFunc(func(_ context.Context, from, to instrumentation.State, event instrumentation.Event) error {
		if cctx.Logger != nil {
			cctx.Logger.Debug("cf_fsm_transition", "from", from, "to", to, "event", event)
		}
		return nil
	})

	// Detect → Initializing
	_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Detect)
	_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Init)

	// Detect the Cloudflare challenge from the response
	cfChallenge := s.detectCF(cctx.Response)
	if cfChallenge == nil {
		_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Fail)
		return &SolveResult{
			Solved: false,
			Metrics: SolveAttemptMetrics{
				Provider:   s.Provider(),
				StartTime:  start,
				Duration:   time.Since(start),
				FinalState: string(fsm.GetState()),
				Success:    false,
			},
		}, fmt.Errorf("no cloudflare challenge detected in response")
	}

	// Solving
	_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Solve)

	solvedResp, err := s.solveCF(cctx.Ctx, cctx.TargetURL, cctx.Response, cfChallenge)
	if err != nil {
		_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Fail)
		return &SolveResult{
			Solved: false,
			Metrics: SolveAttemptMetrics{
				Provider:   s.Provider(),
				StartTime:  start,
				Duration:   time.Since(start),
				FinalState: string(fsm.GetState()),
				Success:    false,
			},
		}, fmt.Errorf("cloudflare solve failed: %w", err)
	}

	// Submit → Verify → Solved
	_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Submit)
	_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Verify)
	_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Success)

	return &SolveResult{
		Solved:   true,
		Response: solvedResp,
		Metrics: SolveAttemptMetrics{
			Provider:   s.Provider(),
			StartTime:  start,
			Duration:   time.Since(start),
			FinalState: string(fsm.GetState()),
			Success:    true,
		},
	}, nil
}

// ensure compile-time interface satisfaction
var _ ChallengeSolver = (*CloudflareFSMSolver)(nil)

