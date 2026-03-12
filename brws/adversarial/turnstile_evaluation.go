package adversarial

import (
	"fmt"
	"time"
)

// TurnstileEvaluationCase defines a repeatable local harness evaluation scenario.
type TurnstileEvaluationCase struct {
	Name        string
	BuildEvents func() []CaptchaEvent
}

// TurnstileEvaluationSample summarizes the outcome of one scenario.
type TurnstileEvaluationSample struct {
	Name         string  `json:"name"`
	Trials       int     `json:"trials"`
	Passes       int     `json:"passes"`
	Failures     int     `json:"failures"`
	PassRate     float64 `json:"pass_rate"`
	RejectRate   float64 `json:"reject_rate"`
	AverageScore float64 `json:"average_score"`
}

// TurnstileEvaluationReport captures the defensive effectiveness of the local harness.
type TurnstileEvaluationReport struct {
	GeneratedAt time.Time                   `json:"generated_at"`
	Samples     []TurnstileEvaluationSample `json:"samples"`
}

// EvaluateTurnstileDefense executes the provided scenarios against the local Turnstile harness.
func (cc *CloudflareChallenger) EvaluateTurnstileDefense(cases []TurnstileEvaluationCase, trials int) (*TurnstileEvaluationReport, error) {
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

		sample := TurnstileEvaluationSample{Name: tc.Name, Trials: trials}
		totalScore := 0.0

		for trial := 0; trial < trials; trial++ {
			sessionID := fmt.Sprintf("turnstile_eval_%s_%d", sanitizeTurnstileData(tc.Name, 24), trial)
			session := cc.CreateTurnstileChallenge(sessionID, "1x00000000000000000000AA")
			events := tc.BuildEvents()
			solution, err := SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, session.PoW.MaxIterations)
			if err != nil {
				return nil, fmt.Errorf("solve PoW for %q trial %d: %w", tc.Name, trial, err)
			}

			_, err = cc.CompleteTurnstile(session.ID, solution, events)
			cc.mu.RLock()
			score := cc.sessions[session.ID].Score
			cc.mu.RUnlock()
			totalScore += score

			if err != nil {
				sample.Failures++
				continue
			}
			sample.Passes++
		}

		sample.PassRate = float64(sample.Passes) / float64(trials)
		sample.RejectRate = float64(sample.Failures) / float64(trials)
		sample.AverageScore = totalScore / float64(trials)
		report.Samples = append(report.Samples, sample)
	}

	return report, nil
}
