package challenge

import "time"

// CaptchaEvent represents a user interaction event during CAPTCHA solving.
type CaptchaEvent struct {
	Type      string  `json:"type"`
	Timestamp int64   `json:"timestamp"`
	ElapsedMs int64   `json:"elapsed_ms"`
	X         float64 `json:"x,omitempty"`
	Y         float64 `json:"y,omitempty"`
	Key       string  `json:"key,omitempty"`
	Delta     float64 `json:"delta,omitempty"`
}

// ChallengeMetrics holds metrics for a CAPTCHA challenge.
type ChallengeMetrics struct {
	LoadTimeMs         int64
	SolveTimeMs        int64
	AttemptCount       int
	EventCount         int
	MouseMovementCount int
	KeystrokeCount     int
	ScrollCount        int
	ClickCount         int
	CorrectAttempts    int
	WrongAttempts      int
	AvgTimePerAttempt  int64
}

// DetectionTrace is a simplified trace stored with CAPTCHA challenge data.
type DetectionTrace struct {
	Timestamp  time.Time `json:"timestamp"`
	FinalScore float64   `json:"final_score"`
	IsBot      bool      `json:"is_bot"`
}

// CaptchaChallenge represents an active CAPTCHA challenge.
type CaptchaChallenge struct {
	ID             string
	Type           string
	CaptchaID      string
	SessionID      string
	CreatedAt      time.Time
	StartedAt      time.Time
	CompletedAt    time.Time
	ExpiresAt      time.Time
	Solved         bool
	Solution       string
	Events         []CaptchaEvent
	DetectionTrace *DetectionTrace
	Metrics        *ChallengeMetrics
	Challenge      map[string]interface{} `json:"challenge"`
}
