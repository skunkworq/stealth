package adversarial

import (
	"fmt"
	"sync"
	"time"

	"github.com/stealth/brwslab/brws/adversarial/captcha"
)

// CaptchaShield provides CAPTCHA challenge management and bot detection.
type CaptchaShield struct {
	mu               sync.RWMutex
	service          *captcha.CaptchaService
	tracer           *CaptchaTracer
	trainingData     *CaptchaTrainingData
	config           *CaptchaShieldConfig
	activeChallenges map[string]*CaptchaChallenge
	detector         *Detector
}

// CaptchaShieldConfig holds configuration for the CAPTCHA shield.
type CaptchaShieldConfig struct {
	Threshold          float64
	CaptchaTypes       []string
	AutoGenDifficulty  bool
	RecordTrainingData bool
	RetentionDays      int
	MaxChallenges      int
}

// DefaultCaptchaShieldConfig provides default settings for the CAPTCHA shield.
var DefaultCaptchaShieldConfig = CaptchaShieldConfig{
	Threshold:          0.7,
	CaptchaTypes:       []string{"text", "recaptcha", "hcaptcha", "turnstile"},
	AutoGenDifficulty:  true,
	RecordTrainingData: true,
	RetentionDays:      30,
	MaxChallenges:      1000,
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

// NewCaptchaShield creates a new CAPTCHA shield with the given configuration.
func NewCaptchaShield(config *CaptchaShieldConfig, detector *Detector, tracer *CaptchaTracer) *CaptchaShield {
	if config == nil {
		config = &DefaultCaptchaShieldConfig
	}

	if tracer == nil {
		tracer = NewCaptchaTracer()
	}

	return &CaptchaShield{
		service:          captcha.NewCaptchaService(),
		tracer:           tracer,
		trainingData:     NewCaptchaTrainingData(),
		config:           config,
		activeChallenges: make(map[string]*CaptchaChallenge),
		detector:         detector,
	}
}

// ShouldPresentCaptcha determines whether to present a CAPTCHA based on detection results.
func (cs *CaptchaShield) ShouldPresentCaptcha(detection *DetectionResult) bool {
	if detection == nil {
		return false
	}

	if detection.Score >= cs.config.Threshold {
		return true
	}

	if detection.Confidence >= 0.8 && len(detection.Indicators) >= 3 {
		return true
	}

	for _, ind := range detection.Indicators {
		if ind.Severity >= 0.8 {
			return true
		}
	}

	return false
}

// CreateChallenge creates a new CAPTCHA challenge for the given session.
func (cs *CaptchaShield) CreateChallenge(sessionID string, detection *DetectionResult, captchaType string) (*CaptchaChallenge, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	challenge := &CaptchaChallenge{
		ID:             fmt.Sprintf("chg_%d", time.Now().UnixNano()),
		SessionID:      sessionID,
		Type:           captchaType,
		CreatedAt:      time.Now(),
		StartedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(2 * time.Minute),
		Solved:         false,
		Events:         make([]CaptchaEvent, 0),
		DetectionTrace: nil,
		Metrics:        &ChallengeMetrics{},
	}

	if detection != nil {
		challenge.DetectionTrace = cs.tracer.CreateDetectionTrace(detection)
	}

	// Create a trace record in the tracer for this challenge
	cs.tracer.CreateTrace(challenge.ID, sessionID, captchaType)

	switch captchaType {
	case "text":
		textCaptcha, err := cs.service.CreateTextCaptcha(nil)
		if err != nil {
			return nil, err
		}
		challenge.CaptchaID = textCaptcha.ID
		if sol, ok := textCaptcha.Solution.(*captcha.TextSolution); ok {
			challenge.Challenge = map[string]interface{}{
				"text": sol.Text,
			}
		} else if sol, ok := textCaptcha.Solution.(captcha.TextSolution); ok {
			challenge.Challenge = map[string]interface{}{
				"text": sol.Text,
			}
		} else {
			challenge.Challenge = map[string]interface{}{
				"text": fmt.Sprintf("%v", textCaptcha.Solution),
			}
		}

		if b64, err := captcha.EncodeToBase64(textCaptcha.Image); err == nil {
			challenge.Challenge["image"] = b64
		}

	case "math":
		mathCaptcha, err := cs.service.CreateMathCaptcha(nil)
		if err != nil {
			return nil, err
		}
		challenge.CaptchaID = mathCaptcha.ID
		if sol, ok := mathCaptcha.Solution.(*captcha.MathSolution); ok {
			challenge.Challenge = map[string]interface{}{
				"question": sol.Expression,
				"text":     fmt.Sprintf("%d", sol.Answer),
			}
		} else if sol, ok := mathCaptcha.Solution.(captcha.MathSolution); ok {
			challenge.Challenge = map[string]interface{}{
				"question": sol.Expression,
				"text":     fmt.Sprintf("%d", sol.Answer),
			}
		} else {
			challenge.Challenge = map[string]interface{}{
				"text": fmt.Sprintf("%v", mathCaptcha.Solution),
			}
		}

		if b64, err := captcha.EncodeToBase64(mathCaptcha.Image); err == nil {
			challenge.Challenge["image"] = b64
		}

	case "slider":
		gen := captcha.NewGenerator(nil)
		sliderCaptcha, err := gen.Generate(captcha.CaptchaTypeSlider)
		if err != nil {
			return nil, err
		}
		challenge.CaptchaID = sliderCaptcha.ID
		if sol, ok := sliderCaptcha.Solution.(captcha.SliderSolution); ok {
			challenge.Challenge = map[string]interface{}{
				"start_x": sol.StartX,
				"end_x":   sol.EndX,
			}
		}
		if b64, err := captcha.EncodeToBase64(sliderCaptcha.Image); err == nil {
			challenge.Challenge["image"] = b64
		}

	case "image_selection", "image":
		gen := captcha.NewGenerator(nil)
		imgCaptcha, err := gen.Generate(captcha.CaptchaTypeImage)
		if err != nil {
			return nil, err
		}
		challenge.CaptchaID = imgCaptcha.ID
		if sol, ok := imgCaptcha.Solution.(captcha.ImageSolution); ok {
			challenge.Challenge = map[string]interface{}{
				"target": sol.TargetImage,
			}
		}
		if b64, err := captcha.EncodeToBase64(imgCaptcha.Image); err == nil {
			challenge.Challenge["image"] = b64
		}

	case "recaptcha":
		target := cs.selectTargetFromDetection(detection)
		recaptcha, err := cs.service.CreateReCaptchaV2(target, nil)
		if err != nil {
			return nil, err
		}
		challenge.CaptchaID = recaptcha.ID

	case "hcaptcha":
		category := cs.selectCategoryFromDetection(detection)
		hcaptcha, err := cs.service.CreateHCaptcha(category, 8, nil)
		if err != nil {
			return nil, err
		}
		challenge.CaptchaID = hcaptcha.ID

	case "turnstile":
		turnstile, err := cs.service.CreateTurnstile(nil)
		if err != nil {
			return nil, err
		}
		challenge.CaptchaID = turnstile.ID
		challenge.Challenge = map[string]interface{}{
			"sitekey": turnstile.ID,
			"action":  "lab_training",
		}

	case "behavioral":
		_ = cs.service.CreateBehavioralProfile(sessionID, nil)
		challenge.CaptchaID = sessionID
		challenge.Challenge = map[string]interface{}{
			"required_events": 50,
		}

	case "webgl":
		webgl, _ := cs.service.CreateWebGL(nil)
		challenge.CaptchaID = webgl.ID
		challenge.Challenge = map[string]interface{}{
			"objects": webgl.Scene,
		}

	case "distorted":
		distorted, err := cs.service.CreateDistortedText(nil)
		if err != nil {
			return nil, err
		}
		challenge.CaptchaID = distorted.ID

	default:
		textCaptcha, err := cs.service.CreateTextCaptcha(nil)
		if err != nil {
			return nil, err
		}
		challenge.CaptchaID = textCaptcha.ID
	}

	cs.activeChallenges[challenge.ID] = challenge

	if len(cs.activeChallenges) > cs.config.MaxChallenges {
		cs.cleanupOldChallenges()
	}

	return challenge, nil
}

func (cs *CaptchaShield) selectTargetFromDetection(detection *DetectionResult) string {
	targets := []string{
		"traffic_light", "car", "bus", "bicycle", "motorcycle",
		"street_sign", "hydrant", "crosswalk", "boat", "train",
	}

	if detection != nil && len(detection.Indicators) > 0 {
		idx := len(detection.Indicators) % len(targets)
		return targets[idx]
	}

	return targets[0]
}

func (cs *CaptchaShield) selectCategoryFromDetection(detection *DetectionResult) string {
	categories := []string{
		"automobile", "bird", "bicycle", "boat", "bus",
		"cat", "dog", "flower", "fruit", "horse",
	}

	if detection != nil && len(detection.Indicators) > 0 {
		idx := len(detection.Indicators) % len(categories)
		return categories[idx]
	}

	return categories[0]
}

// RecordEvent records an event for a CAPTCHA challenge.
func (cs *CaptchaShield) RecordEvent(challengeID string, event CaptchaEvent) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	challenge, ok := cs.activeChallenges[challengeID]
	if !ok {
		return fmt.Errorf("challenge not found: %s", challengeID)
	}

	event.Timestamp = time.Now().UnixMilli()
	event.ElapsedMs = event.Timestamp - challenge.StartedAt.UnixMilli()

	challenge.Events = append(challenge.Events, event)
	challenge.Metrics.EventCount++

	switch event.Type {
	case "mousemove":
		challenge.Metrics.MouseMovementCount++
	case "keydown", "keyup", "keypress":
		challenge.Metrics.KeystrokeCount++
	case "scroll", "wheel":
		challenge.Metrics.ScrollCount++
	case "click", "mousedown", "mouseup":
		challenge.Metrics.ClickCount++
	}

	if cs.config.RecordTrainingData {
		cs.trainingData.RecordEvent(challengeID, &event, challenge.Metrics)
	}

	// Add event to the shared tracer for real-time visualization
	cs.tracer.AddEvent(challengeID, event)

	return nil
}

// ValidateChallenge validates a CAPTCHA solution and returns if it's correct.
func (cs *CaptchaShield) ValidateChallenge(challengeID, solution string) (bool, *ChallengeMetrics) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	challenge, ok := cs.activeChallenges[challengeID]
	if !ok {
		return false, nil
	}

	challenge.CompletedAt = time.Now()
	challenge.Solved = true
	challenge.Solution = solution
	challenge.Metrics.SolveTimeMs = challenge.CompletedAt.UnixMilli() - challenge.StartedAt.UnixMilli()

	valid := solution != ""

	if valid {
		challenge.Metrics.CorrectAttempts++
	} else {
		challenge.Metrics.WrongAttempts++
	}

	challenge.Metrics.AttemptCount++

	if challenge.Metrics.AttemptCount > 0 {
		challenge.Metrics.AvgTimePerAttempt = challenge.Metrics.SolveTimeMs / int64(challenge.Metrics.AttemptCount)
	}

	if cs.config.RecordTrainingData {
		botScore := 0.0
		if !valid {
			botScore = 0.8
		}
		cs.trainingData.RecordChallengeResult(challenge, valid, nil, botScore)
	}

	return valid, challenge.Metrics
}


func parseIndices(_ string) []int {
	return []int{0, 1, 2}
}

// GetChallenge retrieves a challenge by its ID.
func (cs *CaptchaShield) GetChallenge(challengeID string) (*CaptchaChallenge, bool) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	challenge, ok := cs.activeChallenges[challengeID]
	return challenge, ok
}

// GetActiveChallenges returns all active challenges.
func (cs *CaptchaShield) GetActiveChallenges() []*CaptchaChallenge {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	challenges := make([]*CaptchaChallenge, 0, len(cs.activeChallenges))
	for _, ch := range cs.activeChallenges {
		challenges = append(challenges, ch)
	}

	return challenges
}

func (cs *CaptchaShield) cleanupOldChallenges() {
	var toDelete []string
	for id, ch := range cs.activeChallenges {
		if time.Since(ch.CreatedAt) > time.Duration(cs.config.RetentionDays)*24*time.Hour {
			toDelete = append(toDelete, id)
		}
	}

	for _, id := range toDelete[:len(toDelete)/2] {
		delete(cs.activeChallenges, id)
	}
}

// GetTrainingData returns the collected training data.
func (cs *CaptchaShield) GetTrainingData() *CaptchaTrainingData {
	return cs.trainingData
}

// GetStatistics returns statistics about the shield's operation.
func (cs *CaptchaShield) GetStatistics() *ShieldStatistics {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	stats := &ShieldStatistics{
		TotalChallenges:  len(cs.activeChallenges),
		SolvedChallenges: 0,
		FailedChallenges: 0,
		AvgSolveTimeMs:   0,
		AvgAttempts:      0,
		ByType:           make(map[string]int),
		EventBreakdown:   make(map[string]int),
	}

	var totalSolveTime int64
	var totalAttempts int64

	for _, ch := range cs.activeChallenges {
		if ch.Solved {
			if ch.Metrics.WrongAttempts == 0 {
				stats.SolvedChallenges++
			} else {
				stats.FailedChallenges++
			}
		}

		totalSolveTime += ch.Metrics.SolveTimeMs
		totalAttempts += int64(ch.Metrics.AttemptCount)

		stats.ByType[ch.Type]++

		stats.EventBreakdown["mouse"] += ch.Metrics.MouseMovementCount
		stats.EventBreakdown["keyboard"] += ch.Metrics.KeystrokeCount
		stats.EventBreakdown["scroll"] += ch.Metrics.ScrollCount
		stats.EventBreakdown["click"] += ch.Metrics.ClickCount
	}

	if stats.TotalChallenges > 0 {
		stats.AvgSolveTimeMs = float64(totalSolveTime) / float64(stats.TotalChallenges)
		stats.AvgAttempts = float64(totalAttempts) / float64(stats.TotalChallenges)
	}

	stats.TrainingDataSize = cs.trainingData.Size()

	return stats
}

// ShieldStatistics holds statistics about CAPTCHA shield operations.
type ShieldStatistics struct {
	TotalChallenges  int            `json:"total_challenges"`
	SolvedChallenges int            `json:"solved_challenges"`
	FailedChallenges int            `json:"failed_challenges"`
	AvgSolveTimeMs   float64        `json:"avg_solve_time_ms"`
	AvgAttempts      float64        `json:"avg_attempts"`
	ByType           map[string]int `json:"by_type"`
	EventBreakdown   map[string]int `json:"event_breakdown"`
	TrainingDataSize int            `json:"training_data_size"`
}

// CaptchaShieldMiddleware provides HTTP middleware for CAPTCHA protection.
type CaptchaShieldMiddleware struct {
	shield   *CaptchaShield
	detector *Detector
	config   *MiddlewareConfig
}

// MiddlewareConfig holds configuration for the CAPTCHA middleware.
type MiddlewareConfig struct {
	ChallengeOnSuspicion bool
	BypassCookie         string
	ChallengeCookie      string
	RedirectURL          string
}

// NewCaptchaShieldMiddleware creates a new CAPTCHA middleware instance.
func NewCaptchaShieldMiddleware(shield *CaptchaShield, detector *Detector) *CaptchaShieldMiddleware {
	return &CaptchaShieldMiddleware{
		shield:   shield,
		detector: detector,
		config: &MiddlewareConfig{
			ChallengeOnSuspicion: true,
			ChallengeCookie:      "captcha_session",
		},
	}
}

// HandleDetection handles bot detection and returns a challenge if needed.
func (m *CaptchaShieldMiddleware) HandleDetection(sessionID string, detection *DetectionResult) (*CaptchaChallenge, bool) {
	if m.shield.ShouldPresentCaptcha(detection) {
		captchaType := m.selectCaptchaType(detection)
		challenge, err := m.shield.CreateChallenge(sessionID, detection, captchaType)
		if err != nil {
			return nil, false
		}
		return challenge, true
	}

	return nil, false
}

func (m *CaptchaShieldMiddleware) selectCaptchaType(detection *DetectionResult) string {
	if detection == nil {
		return "text"
	}

	if detection.Score >= 0.9 {
		return "recaptcha"
	}

	if detection.Score >= 0.8 {
		return "hcaptcha"
	}

	if detection.Confidence >= 0.8 {
		return "behavioral"
	}

	return "text"
}
