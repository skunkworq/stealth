package recaptcha

import (
	"time"

	"github.com/skunkworq/stealth/brws/core/detection"
)

// DetectionVector re-exports the canonical type from core/detection.
type DetectionVector = detection.DetectionVector

// StealthIndicator re-exports the canonical type from core/detection.
type StealthIndicator = detection.StealthIndicator

// BehavioralCheckResult captures one behavioral analysis check outcome.
type BehavioralCheckResult struct {
	Check   string  `json:"check"`
	Message string  `json:"message"`
	Weight  float64 `json:"weight"`
	Field   string  `json:"field"`
	Value   string  `json:"value"`
}

// V3AssessmentRecord captures the full analysis data from a v3 assessment.
type V3AssessmentRecord struct {
	ID                       string                  `json:"id"`
	Timestamp                time.Time               `json:"timestamp"`
	Action                   string                  `json:"action"`
	V3Score                  float64                 `json:"v3_score"`
	DetectionScore           float64                 `json:"detection_score"`
	BehavioralScore          float64                 `json:"behavioral_score"`
	CombinedBotScore         float64                 `json:"combined_bot_score"`
	EventCount               int                     `json:"event_count"`
	Hostname                 string                  `json:"hostname"`
	Vectors                  []DetectionVector       `json:"vectors"`
	Indicators               []StealthIndicator      `json:"indicators"`
	BehavioralChecks         []BehavioralCheckResult `json:"behavioral_checks"`
	BehavioralEventBreakdown map[string]int          `json:"behavioral_event_breakdown"`
}

// ReCaptchaV3Response mirrors Google's reCAPTCHA v3 siteverify response.
type ReCaptchaV3Response struct {
	Success     bool    `json:"success"`
	Score       float64 `json:"score"`        // 0.0 (bot) – 1.0 (human)
	Action      string  `json:"action"`       // action name from the client
	ChallengeTS string  `json:"challenge_ts"` // ISO timestamp
	Hostname    string  `json:"hostname"`
}
