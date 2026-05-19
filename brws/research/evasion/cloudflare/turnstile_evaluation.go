package cloudflare

import (
	"fmt"
	"strings"
	"time"

	"github.com/skunkworq/stealth/brws/stealth/challenge"
)

// CloudflareChallenger wraps challenge.CloudflareChallenger to expose evaluation methods
// from this research package.
type CloudflareChallenger struct {
	*challenge.CloudflareChallenger
}

// NewCloudflareChallenger creates a research CloudflareChallenger backed by the production type.
// The tracer argument is accepted for API compatibility but the underlying challenger uses its own.
func NewCloudflareChallenger(_ interface{}, powConfig *challenge.PoWDifficultyConfig) *CloudflareChallenger {
	return &CloudflareChallenger{challenge.NewCloudflareChallenger(nil, powConfig)}
}

// SolvePoW is a convenience wrapper over challenge.SolvePoW.
func SolvePoW(prefix string, difficulty int, maxIterations int64) (*PoWSolution, error) {
	return challenge.SolvePoW(prefix, difficulty, maxIterations)
}

// TurnstileEvaluationCase defines a repeatable local harness evaluation scenario.
type TurnstileEvaluationCase struct {
	Name                  string
	DetectionScore        float64
	ExpectPass            bool
	PresentWidget         bool
	LifecycleCallbacks    []string
	VerifyToken           bool
	BuildEvents           func() []challenge.CaptchaEvent
	BuildSnapshot         func() *TurnstileClientSnapshot
	BuildInteractionProof func() *TurnstileInteractionProof
	MutateSession         func(*CloudflareChallengeSession)
}

// TurnstileEvaluationSample summarizes the outcome of one scenario.
type TurnstileEvaluationSample struct {
	Name                 string         `json:"name"`
	Trials               int            `json:"trials"`
	ExpectedPass         bool           `json:"expected_pass"`
	Passes               int            `json:"passes"`
	Failures             int            `json:"failures"`
	TrueAccepts          int            `json:"true_accepts"`
	FalseRejects         int            `json:"false_rejects"`
	TrueRejects          int            `json:"true_rejects"`
	FalseAccepts         int            `json:"false_accepts"`
	VerificationPasses   int            `json:"verification_passes"`
	VerificationFailures int            `json:"verification_failures"`
	RejectionReasons     map[string]int `json:"rejection_reasons,omitempty"`
	PassRate             float64        `json:"pass_rate"`
	RejectRate           float64        `json:"reject_rate"`
	Accuracy             float64        `json:"accuracy"`
	AverageScore         float64        `json:"average_score"`
}

// TurnstileEvaluationReport captures the defensive effectiveness of the local harness.
type TurnstileEvaluationReport struct {
	GeneratedAt  time.Time                   `json:"generated_at"`
	Samples      []TurnstileEvaluationSample `json:"samples"`
	TotalTrials  int                         `json:"total_trials"`
	TrueAccepts  int                         `json:"true_accepts"`
	FalseRejects int                         `json:"false_rejects"`
	TrueRejects  int                         `json:"true_rejects"`
	FalseAccepts int                         `json:"false_accepts"`
	Accuracy     float64                     `json:"accuracy"`
}

// EvaluateTurnstileDefense executes the provided scenarios against the local Turnstile harness.
func (cc *CloudflareChallenger) EvaluateTurnstileDefense(cases []TurnstileEvaluationCase, trials int) (*TurnstileEvaluationReport, error) { //nolint:cyclop
	if trials <= 0 {
		return nil, fmt.Errorf("trials must be > 0")
	}

	report := &TurnstileEvaluationReport{
		GeneratedAt: time.Now(),
		Samples:     make([]TurnstileEvaluationSample, 0, len(cases)),
	}

	for _, tc := range cases {
		if tc.Name == "" {
			return nil, fmt.Errorf("evaluation case requires a name")
		}
		if tc.BuildEvents == nil {
			return nil, fmt.Errorf("evaluation case %q missing event builder", tc.Name)
		}

		sample := TurnstileEvaluationSample{
			Name:             tc.Name,
			Trials:           trials,
			ExpectedPass:     tc.ExpectPass,
			RejectionReasons: make(map[string]int),
		}
		totalScore := 0.0

		for trial := 0; trial < trials; trial++ {
			sessionID := fmt.Sprintf("turnstile_eval_%s_%d", sanitizeTurnstileData(tc.Name, 24), trial)
			session := cc.CreateTurnstileChallengeWithRisk(sessionID, "1x00000000000000000000AA", tc.DetectionScore)
			session.Hostname = "localhost"
			if tc.PresentWidget {
				cc.PresentTurnstileWidget(session.ID, "localhost")
			}
			if tc.BuildSnapshot != nil {
				cc.RecordTurnstileClientSnapshot(session.ID, tc.BuildSnapshot())
			}
			if tc.BuildInteractionProof != nil {
				cc.RecordTurnstileInteractionProof(session.ID, tc.BuildInteractionProof())
			}
			for _, callback := range tc.LifecycleCallbacks {
				cc.RecordTurnstileCallback(session.ID, callback)
			}
			if tc.MutateSession != nil {
				tc.MutateSession(session)
			}

			events := tc.BuildEvents()
			solution, err := SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, session.PoW.MaxIterations)
			if err != nil {
				return nil, fmt.Errorf("solve PoW for %q trial %d: %w", tc.Name, trial, err)
			}

			result, err := cc.CompleteTurnstile(session.ID, solution, events)
			if s, ok := cc.GetSession(session.ID); ok {
				totalScore += s.Score
			}

			if err != nil {
				sample.Failures++
				sample.RejectionReasons[classifyTurnstileRejection(err)]++
				if tc.ExpectPass {
					sample.FalseRejects++
				} else {
					sample.TrueRejects++
				}
				continue
			}
			sample.Passes++
			if tc.ExpectPass {
				sample.TrueAccepts++
			} else {
				sample.FalseAccepts++
			}

			if tc.VerifyToken && result != nil {
				verifyResult := cc.VerifyTurnstileToken(cc.TurnstileSecretKey(), result.TurnstileToken, "localhost")
				if verifyResult.Success {
					sample.VerificationPasses++
				} else {
					sample.VerificationFailures++
				}
			}
		}

		sample.PassRate = float64(sample.Passes) / float64(trials)
		sample.RejectRate = float64(sample.Failures) / float64(trials)
		sample.Accuracy = float64(sample.TrueAccepts+sample.TrueRejects) / float64(trials)
		sample.AverageScore = totalScore / float64(trials)
		report.Samples = append(report.Samples, sample)
		report.TotalTrials += sample.Trials
		report.TrueAccepts += sample.TrueAccepts
		report.FalseRejects += sample.FalseRejects
		report.TrueRejects += sample.TrueRejects
		report.FalseAccepts += sample.FalseAccepts
	}

	if report.TotalTrials > 0 {
		report.Accuracy = float64(report.TrueAccepts+report.TrueRejects) / float64(report.TotalTrials)
	}

	return report, nil
}

func classifyTurnstileRejection(err error) string {
	if err == nil {
		return ""
	}

	msg := err.Error()
	switch {
	case msg == "":
		return "unknown"
	case containsAllParts(msg, "widget", "error"):
		return "widget_error"
	case containsAllParts(msg, "widget", "timeout"):
		return "widget_timeout"
	case containsAllParts(msg, "composite", "threshold"):
		return "composite_threshold"
	case containsAllParts(msg, "PoW", "validation"):
		return "pow_validation"
	default:
		return "other"
	}
}

func containsAllParts(msg string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(msg, part) {
			return false
		}
	}
	return true
}
