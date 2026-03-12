package adversarial

import "fmt"

// CheckReport provides per-check trace data with expected/actual values for feedback.
// The sword's AdaptiveRequestGenerator consumes these to learn what to fix.
type CheckReport struct {
	Name        string  `json:"name"`
	Fired       bool    `json:"fired"`
	Weight      float64 `json:"weight"`
	Score       float64 `json:"score"`
	Field       string  `json:"field"`
	Actual      string  `json:"actual"`
	Expected    string  `json:"expected"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
}

// VectorReport is a per-vector summary with its constituent CheckReports.
type VectorReport struct {
	Name        string        `json:"name"`
	Category    string        `json:"category"`
	Score       float64       `json:"score"`
	Weight      float64       `json:"weight"`
	Detected    bool          `json:"detected"`
	Description string        `json:"description"`
	Checks      []CheckReport `json:"checks"`
}

// DetectionReport is the full structured output of a shield analysis,
// suitable for consumption by the sword's adaptive feedback loop.
type DetectionReport struct {
	RequestID   string         `json:"request_id"`
	TotalScore  float64        `json:"total_score"`
	IsBot       bool           `json:"is_bot"`
	IsStealth   bool           `json:"is_stealth"`
	Vectors     []VectorReport `json:"vectors"`
	FiredChecks int            `json:"fired_checks"`
	TotalChecks int            `json:"total_checks"`
}

// ToDetectionReport converts a StealthDetection into a structured DetectionReport
// with per-check expected/actual values. Falls back to string Indicators for legacy
// checks that don't have CheckReports yet.
func (sd *StealthDetection) ToDetectionReport() *DetectionReport {
	report := &DetectionReport{
		RequestID:  sd.RequestID,
		TotalScore: sd.Score,
		IsBot:      sd.IsBot,
		IsStealth:  sd.IsStealth,
		Vectors:    make([]VectorReport, 0, len(sd.Vectors)),
	}

	for _, vec := range sd.Vectors {
		vr := VectorReport{
			Name:        vec.Name,
			Category:    vec.Category,
			Score:       vec.Score,
			Weight:      vec.Weight,
			Detected:    vec.Detected,
			Description: vec.Description,
			Checks:      make([]CheckReport, 0),
		}

		// Use structured CheckReports if available
		if len(vec.CheckReports) > 0 {
			for _, cr := range vec.CheckReports {
				vr.Checks = append(vr.Checks, cr)
				report.TotalChecks++
				if cr.Fired {
					report.FiredChecks++
				}
			}
		} else {
			// Fall back to string indicators for legacy checks
			for _, ind := range vec.Indicators {
				cr := CheckReport{
					Name:        ind,
					Fired:       true,
					Weight:      vec.Weight,
					Score:       vec.Score,
					Field:       "",
					Actual:      "",
					Expected:    "",
					Severity:    severityFromScore(vec.Score),
					Description: fmt.Sprintf("Legacy indicator: %s", ind),
				}
				vr.Checks = append(vr.Checks, cr)
				report.TotalChecks++
				report.FiredChecks++
			}
		}

		report.Vectors = append(report.Vectors, vr)
	}

	return report
}

// FiredCheckNames returns the names of all checks that fired.
func (dr *DetectionReport) FiredCheckNames() []string {
	names := make([]string, 0, dr.FiredChecks)
	for _, vec := range dr.Vectors {
		for _, check := range vec.Checks {
			if check.Fired {
				names = append(names, check.Name)
			}
		}
	}
	return names
}

func severityFromScore(score float64) string {
	switch {
	case score >= 0.7:
		return "critical"
	case score >= 0.5:
		return "high"
	case score >= 0.3:
		return "medium"
	default:
		return "low"
	}
}
