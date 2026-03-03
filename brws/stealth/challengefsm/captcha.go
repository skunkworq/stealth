package challengefsm

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/stealth/brwslab/brws/adversarial"
	"github.com/stealth/brwslab/brws/challenge"
	"github.com/stealth/brwslab/brws/engine"
	"github.com/stealth/brwslab/brws/instrumentation"
)

// CaptchaSolverClient is the interface for the existing captcha solver we wrap.
type CaptchaSolverClient interface {
	DetectCaptchaResponse(body []byte, headers map[string][]string) *CaptchaDetection
	SolveFromResponse(body []byte, headers map[string][]string) (*CaptchaSolveOutput, *CaptchaDetection, error)
	SolveReCaptchaV2(baseURL string) (*ReCaptchaV2Output, error)
	SubmitSolution(verifyURL, challengeID, solution string, events []adversarial.CaptchaEvent) (bool, error)
	GenerateHumanEvents(solveTimeMs int64, opts ...HumanEventOption) []adversarial.CaptchaEvent
	LastToken() string
}

// CaptchaDetection mirrors stealth.CaptchaResponse for the interface.
type CaptchaDetection struct {
	ChallengeID   string
	Type          string
	CaptchaID     string
	ImageBase64   string
	ChallengeData map[string]interface{}
}

// CaptchaSolveOutput mirrors stealth.SolveResult for the interface.
type CaptchaSolveOutput struct {
	Solution    string
	Confidence  float64
	SolveTimeMs int64
	Token       string
}

// ReCaptchaV2Output mirrors stealth.ReCaptchaV2Result for the interface.
type ReCaptchaV2Output struct {
	Token           string
	BehavioralScore float64
	Passed          bool
	NeedChallenge   bool
	SolveAttempts   int
	RefreshCount    int
	TotalTimeMs     int64
}

// HumanEventOption mirrors stealth.HumanEventOpts for the interface.
type HumanEventOption struct {
	Solution string
}

// CaptchaDetectFunc detects a captcha challenge from a response.
type CaptchaDetectFunc func(body []byte, headers map[string][]string) *CaptchaDetection

// CaptchaSolveInlineFunc solves an inline captcha from response body.
type CaptchaSolveInlineFunc func(body []byte, headers map[string][]string) (*CaptchaSolveOutput, *CaptchaDetection, error)

// CaptchaSolveV2Func solves a reCAPTCHA v2 challenge.
type CaptchaSolveV2Func func(baseURL string) (*ReCaptchaV2Output, error)

// CaptchaSubmitFunc submits a captcha solution.
type CaptchaSubmitFunc func(verifyURL, challengeID, solution string, events []adversarial.CaptchaEvent) (bool, error)

// CaptchaEventsFunc generates human-like events.
type CaptchaEventsFunc func(solveTimeMs int64, solution string) []adversarial.CaptchaEvent

// CaptchaLastTokenFunc returns the last solve token.
type CaptchaLastTokenFunc func() string

// CaptchaFSMSolver wraps the existing CaptchaSolver behind the ChallengeSolver
// interface, driving a per-solve FSM.
type CaptchaFSMSolver struct {
	detectCaptcha CaptchaDetectFunc
	solveInline   CaptchaSolveInlineFunc
	solveV2       CaptchaSolveV2Func
	submitSol     CaptchaSubmitFunc
	genEvents     CaptchaEventsFunc
	lastToken     CaptchaLastTokenFunc
	engine        engine.Engine
}

// NewCaptchaFSMSolver creates a new CaptchaFSMSolver.
func NewCaptchaFSMSolver(
	detectCaptcha CaptchaDetectFunc,
	solveInline CaptchaSolveInlineFunc,
	solveV2 CaptchaSolveV2Func,
	submitSol CaptchaSubmitFunc,
	genEvents CaptchaEventsFunc,
	lastToken CaptchaLastTokenFunc,
	eng engine.Engine,
) *CaptchaFSMSolver {
	return &CaptchaFSMSolver{
		detectCaptcha: detectCaptcha,
		solveInline:   solveInline,
		solveV2:       solveV2,
		submitSol:     submitSol,
		genEvents:     genEvents,
		lastToken:     lastToken,
		engine:        eng,
	}
}

// CanSolve returns true for reCAPTCHA and hCaptcha challenge types,
// as well as generic challenges that might contain inline captchas.
func (s *CaptchaFSMSolver) CanSolve(ch *challenge.Challenge) bool {
	switch ch.Type {
	case challenge.ChallengeRecaptchaV2, challenge.ChallengeRecaptchaV3,
		challenge.ChallengeHCaptcha, challenge.ChallengeGeneric:
		return true
	default:
		return false
	}
}

// Provider returns "captcha".
func (s *CaptchaFSMSolver) Provider() string {
	return "captcha"
}

// Solve drives the captcha FSM through detection → solving → submission.
func (s *CaptchaFSMSolver) Solve(cctx *ChallengeContext) (*SolveResult, error) {
	start := time.Now()
	fsm := NewChallengeFSM("captcha-challenge")
	fsm.SetTransitionFunc(func(_ context.Context, from, to instrumentation.State, event instrumentation.Event) error {
		if cctx.Logger != nil {
			cctx.Logger.Debug("captcha_fsm_transition", "from", from, "to", to, "event", event)
		}
		return nil
	})

	// Detect
	_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Detect)

	cr := s.detectCaptcha(cctx.Response.Body, cctx.Response.Headers)
	if cr == nil {
		_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Fail)
		return &SolveResult{Solved: false}, fmt.Errorf("no captcha detected in response")
	}

	_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Init)

	if cr.Type == "recaptcha-v2" {
		return s.solveRecaptchaV2(cctx, fsm, start)
	}

	return s.solveInlineCaptcha(cctx, cr, fsm, start)
}

func (s *CaptchaFSMSolver) solveRecaptchaV2(cctx *ChallengeContext, fsm *instrumentation.FSM, start time.Time) (*SolveResult, error) {
	_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Solve)

	baseURL := deriveBaseURL(cctx.TargetURL)
	v2Result, err := s.solveV2(baseURL)
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
		}, fmt.Errorf("reCAPTCHA v2 solve failed: %w", err)
	}

	if !v2Result.Passed || v2Result.Token == "" {
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
		}, fmt.Errorf("reCAPTCHA v2 not passed")
	}

	// Submit — retry original request with token
	_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Submit)

	retryReq := &engine.Request{
		URL:     cctx.TargetURL,
		Timeout: cctx.Config.Timeout,
		Headers: map[string][]string{"X-Captcha-Token": {v2Result.Token}},
	}
	retryResp, retryErr := s.engine.Do(cctx.Ctx, retryReq)

	_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Verify)

	if retryErr != nil {
		_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Fail)
		return &SolveResult{
			Solved: false,
			Token:  v2Result.Token,
			Metrics: SolveAttemptMetrics{
				Provider:   s.Provider(),
				StartTime:  start,
				Duration:   time.Since(start),
				FinalState: string(fsm.GetState()),
				Success:    false,
			},
		}, fmt.Errorf("retry after reCAPTCHA v2 failed: %w", retryErr)
	}

	_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Success)

	return &SolveResult{
		Solved:   true,
		Response: retryResp,
		Token:    v2Result.Token,
		Metrics: SolveAttemptMetrics{
			Provider:   s.Provider(),
			StartTime:  start,
			Duration:   time.Since(start),
			Attempts:   v2Result.SolveAttempts,
			FinalState: string(fsm.GetState()),
			Success:    true,
		},
	}, nil
}

func (s *CaptchaFSMSolver) solveInlineCaptcha(cctx *ChallengeContext, cr *CaptchaDetection, fsm *instrumentation.FSM, start time.Time) (*SolveResult, error) {
	_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Solve)

	solveResult, _, err := s.solveInline(cctx.Response.Body, cctx.Response.Headers)
	if err != nil || solveResult == nil {
		_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Fail)
		errMsg := "inline captcha solve returned nil"
		if err != nil {
			errMsg = err.Error()
		}
		return &SolveResult{
			Solved: false,
			Metrics: SolveAttemptMetrics{
				Provider:   s.Provider(),
				StartTime:  start,
				Duration:   time.Since(start),
				FinalState: string(fsm.GetState()),
				Success:    false,
			},
		}, fmt.Errorf("inline captcha solve failed: %s", errMsg)
	}

	// Human-like delay
	if cctx.Config.HumanDelay {
		//nolint:gosec
		delay := time.Duration(2000+rand.Intn(6000)) * time.Millisecond
		time.Sleep(delay)
	}

	events := s.genEvents(solveResult.SolveTimeMs, solveResult.Solution)

	verifyURL := cctx.Config.VerifyURL
	if verifyURL == "" {
		verifyURL = deriveVerifyURL(cctx.TargetURL)
	}

	maxRetries := cctx.Config.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 1
	}

	_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Submit)

	for attempt := 0; attempt < maxRetries; attempt++ {
		solved, submitErr := s.submitSol(verifyURL, cr.ChallengeID, solveResult.Solution, events)
		if submitErr != nil {
			break
		}
		if solved {
			_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Verify)

			// Retry original request
			retryReq := &engine.Request{
				URL:     cctx.TargetURL,
				Timeout: cctx.Config.Timeout,
			}
			if token := s.lastToken(); token != "" {
				retryReq.Headers = map[string][]string{"X-Captcha-Token": {token}}
			}

			retryResp, retryErr := s.engine.Do(cctx.Ctx, retryReq)
			if retryErr != nil {
				_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Fail)
				return &SolveResult{
					Solved: false,
					Metrics: SolveAttemptMetrics{
						Provider:   s.Provider(),
						StartTime:  start,
						Duration:   time.Since(start),
						Attempts:   attempt + 1,
						FinalState: string(fsm.GetState()),
						Success:    false,
					},
				}, fmt.Errorf("retry after captcha solve failed: %w", retryErr)
			}

			_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Success)

			return &SolveResult{
				Solved:   true,
				Response: retryResp,
				Metrics: SolveAttemptMetrics{
					Provider:   s.Provider(),
					StartTime:  start,
					Duration:   time.Since(start),
					Attempts:   attempt + 1,
					FinalState: string(fsm.GetState()),
					Success:    true,
				},
			}, nil
		}
	}

	_ = fsm.Transition(cctx.Ctx, ChallengeEvents.Retry)
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
	}, fmt.Errorf("captcha solve exhausted retries")
}

// ensure compile-time interface satisfaction
var _ ChallengeSolver = (*CaptchaFSMSolver)(nil)
