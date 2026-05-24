package fsm

import (
	"context"
	"fmt"
	"time"

	"github.com/skunkworq/stealth/brws/stealth/challenge"
	"github.com/skunkworq/stealth/brws/browser/engine"
	"github.com/skunkworq/stealth/brws/core/instrumentation"
)

// DynamicFSMSolver wraps the challenge.DynamicSolver behind the
// ChallengeSolver interface. It handles challenges that no other solver
// can handle by classifying the interaction type and replaying matching traces.
type DynamicFSMSolver struct {
	solver *challenge.DynamicSolver
	engine engine.Engine
}

// NewDynamicFSMSolver creates a solver backed by the dynamic solver.
func NewDynamicFSMSolver(solver *challenge.DynamicSolver, eng engine.Engine) *DynamicFSMSolver {
	return &DynamicFSMSolver{solver: solver, engine: eng}
}

// CanSolve returns true for any challenge — this is the catch-all solver.
// It should be registered last in the registry so specific solvers take priority.
func (s *DynamicFSMSolver) CanSolve(_ *challenge.Challenge) bool {
	return true
}

// Provider returns "dynamic".
func (s *DynamicFSMSolver) Provider() string {
	return "dynamic"
}

// Solve classifies the challenge, generates trace-based events, and attempts
// to solve by retrying the original request with behavioral event injection.
func (s *DynamicFSMSolver) Solve(cctx *ChallengeContext) (*SolveResult, error) {
	start := time.Now()
	fsm := NewChallengeFSM("dynamic-challenge")
	fsm.SetTransitionFunc(func(_ context.Context, from, to instrumentation.State, event instrumentation.Event) error {
		if cctx.Logger != nil {
			cctx.Logger.Debug("dynamic_fsm_transition", "from", from, "to", to, "event", event)
		}
		return nil
	})

	_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Detect)

	// Classify and generate events
	result := s.solver.Solve(cctx.Response.Body, cctx.Response.Headers)

	if result.NeedsHuman {
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
			}, fmt.Errorf("dynamic solver: no traces available, needs human solving (interaction=%s, provider=%s)",
				result.Signature.Interaction, result.Signature.Provider)
	}

	if cctx.Logger != nil {
		cctx.Logger.Info("dynamic solver classified challenge",
			"provider", result.Signature.Provider,
			"interaction", string(result.Signature.Interaction),
			"confidence", result.Signature.Confidence,
			"source", result.Source,
			"events", len(result.Events),
			"indicators", result.Signature.Indicators,
		)
	}

	_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Init)

	// Use trace events if the caller provided them, otherwise use our generated ones.
	// Trace events are collected but not yet submitted to challenge APIs;
	// this is intentional until challenge providers expose event-based verification.
	events := cctx.TraceEvents
	if len(events) == 0 {
		events = result.Events
	}
	_ = events

	// Human-like delay before submission
	if cctx.Config.HumanDelay {
		delay := time.Duration(1000+result.Signature.Confidence*2000) * time.Millisecond
		time.Sleep(delay)
	}

	_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Solve)

	// Retry original request — for many challenges, the behavioral events
	// are sent via separate API calls. For simpler challenges (Cloudflare JS),
	// just waiting and retrying is enough.
	_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Submit)

	retryResp, retryErr := s.engine.Do(cctx.Ctx, &engine.Request{
		URL:     cctx.TargetURL,
		Timeout: cctx.Config.Timeout,
	})

	_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Verify)

	if retryErr != nil {
		_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Fail)
		s.solver.RecordOutcome(result.Signature.Fingerprint, false)
		return &SolveResult{
			Solved: false,
			Metrics: SolveAttemptMetrics{
				Provider:   s.Provider(),
				StartTime:  start,
				Duration:   time.Since(start),
				FinalState: string(fsm.GetState()),
				Success:    false,
			},
		}, fmt.Errorf("retry after dynamic solve failed: %w", retryErr)
	}

	// Check if the retry still has a challenge
	ud := NewUnifiedDetector()
	if ud.Detect(retryResp) != nil {
		_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Fail)
		s.solver.RecordOutcome(result.Signature.Fingerprint, false)
		return &SolveResult{
			Solved:   false,
			Response: retryResp,
			Metrics: SolveAttemptMetrics{
				Provider:   s.Provider(),
				StartTime:  start,
				Duration:   time.Since(start),
				FinalState: string(fsm.GetState()),
				Success:    false,
			},
		}, fmt.Errorf("challenge persists after dynamic solve retry")
	}

	// Success
	_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Success)
	s.solver.RecordOutcome(result.Signature.Fingerprint, true)

	return &SolveResult{
		Solved:   true,
		Response: retryResp,
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
var _ ChallengeSolver = (*DynamicFSMSolver)(nil)

// Events returns the generated events for the last challenge classification.
// This allows the caller to inject them into external APIs.
func (s *DynamicFSMSolver) Events(body []byte, headers map[string][]string) []challenge.CaptchaEvent {
	result := s.solver.Solve(body, headers)
	if result.NeedsHuman {
		return nil
	}
	return result.Events
}
