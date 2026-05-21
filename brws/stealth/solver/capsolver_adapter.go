package solver

import (
	"fmt"

	"github.com/skunkworq/stealth/brws/stealth/captcha/external_service"
	"github.com/skunkworq/stealth/brws/stealth/challenge"
	challengefsm "github.com/skunkworq/stealth/brws/stealth/challenge/fsm"
)

// CapSolverAdapter bridges external_service.Solver to the fsm.ChallengeSolver
// interface so CapSolver can be registered in SolverRegistry.
type CapSolverAdapter struct {
	solver external_service.Solver
}

func NewCapSolverAdapter(s external_service.Solver) *CapSolverAdapter {
	return &CapSolverAdapter{solver: s}
}

func (a *CapSolverAdapter) Provider() string { return "capsolver" }

func (a *CapSolverAdapter) CanSolve(ch *challenge.Challenge) bool {
	switch ch.Type {
	case challenge.ChallengeRecaptchaV2, challenge.ChallengeRecaptchaV3,
		challenge.ChallengeHCaptcha, challenge.ChallengeTurnstile:
		return true
	default:
		return false
	}
}

func (a *CapSolverAdapter) Solve(cctx *challengefsm.ChallengeContext) (*challengefsm.SolveResult, error) {
	ch := cctx.Challenge
	ctx := cctx.Ctx
	url := cctx.TargetURL

	var token string
	var err error

	switch ch.Type {
	case challenge.ChallengeRecaptchaV2:
		token, err = a.solver.SolveRecaptchaV2(ctx, ch.SiteKey, url)
	case challenge.ChallengeRecaptchaV3:
		token, err = a.solver.SolveRecaptchaV3(ctx, ch.SiteKey, url, 0.5)
	case challenge.ChallengeHCaptcha:
		token, err = a.solver.SolveHcaptcha(ctx, ch.SiteKey, url)
	case challenge.ChallengeTurnstile:
		token, err = a.solver.SolveTurnstile(ctx, ch.SiteKey, url)
	default:
		return nil, fmt.Errorf("capsolver: unsupported challenge type %q", ch.Type)
	}

	if err != nil {
		return &challengefsm.SolveResult{Solved: false}, err
	}
	return &challengefsm.SolveResult{Solved: true, Token: token}, nil
}

// compile-time interface check
var _ challengefsm.ChallengeSolver = (*CapSolverAdapter)(nil)
