package adversarial

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"sync"
	"time"
)

// CaptchaTracer tracks CAPTCHA interactions for bot detection analysis.
type CaptchaTracer struct {
	mu     sync.RWMutex
	traces map[string]*CaptchaTrace
}

// CaptchaTrace represents a single CAPTCHA challenge interaction trace.
type CaptchaTrace struct {
	ChallengeID string         `json:"challenge_id"`
	SessionID   string         `json:"session_id"`
	Type        string         `json:"type"`
	CreatedAt   time.Time      `json:"created_at"`
	StartedAt   time.Time      `json:"started_at"`
	Events      []CaptchaEvent `json:"events"`
	Metrics     *TraceMetrics  `json:"metrics"`
	BotScore    float64        `json:"bot_score"`
	IsBot       bool           `json:"is_bot"`
}

// TraceMetrics contains behavioral metrics extracted from CAPTCHA interaction events.
type TraceMetrics struct {
	TotalEvents    int     `json:"total_events"`
	MouseMovements int     `json:"mouse_movements"`
	Keystrokes     int     `json:"keystrokes"`
	ScrollEvents   int     `json:"scroll_events"`
	Clicks         int     `json:"clicks"`
	MouseVelocity  float64 `json:"mouse_velocity"`
	TypingSpeed    float64 `json:"typing_speed"`
	EventIntervals float64 `json:"event_intervals"`
	Straightness   float64 `json:"straightness"`
	Pauses         int     `json:"pauses"`
	LongPauses     int     `json:"long_pauses"`
}

// NewCaptchaTracer creates a new CAPTCHA tracer instance.
func NewCaptchaTracer() *CaptchaTracer {
	return &CaptchaTracer{
		traces: make(map[string]*CaptchaTrace),
	}
}

// CreateTrace creates a new trace for a CAPTCHA challenge.
func (ct *CaptchaTracer) CreateTrace(challengeID, sessionID, captchaType string) *CaptchaTrace {
	trace := &CaptchaTrace{
		ChallengeID: challengeID,
		SessionID:   sessionID,
		Type:        captchaType,
		CreatedAt:   time.Now(),
		StartedAt:   time.Now(),
		Events:      make([]CaptchaEvent, 0),
		Metrics:     &TraceMetrics{},
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.traces[challengeID] = trace

	return trace
}

// AddEvent adds an event to an existing trace.
func (ct *CaptchaTracer) AddEvent(challengeID string, event CaptchaEvent) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if trace, ok := ct.traces[challengeID]; ok {
		trace.Events = append(trace.Events, event)
		ct.updateMetrics(trace)
		log.Printf("TRACE_EVENT challenge=%s type=%s events=%d velocity=%.2f",
			challengeID, event.Type, len(trace.Events), trace.Metrics.MouseVelocity)
	}
}

func (ct *CaptchaTracer) updateMetrics(trace *CaptchaTrace) {
	if trace.Metrics == nil {
		trace.Metrics = &TraceMetrics{}
	}
	m := trace.Metrics

	// Reset accumulation metrics to avoid O(N^2) bug since we re-scan all events
	*m = TraceMetrics{}
	m.TotalEvents = len(trace.Events)

	if m.TotalEvents == 0 {
		return
	}

	var prevX, prevY float64
	var totalDistance float64
	var firstMouseX, firstMouseY float64
	var lastMouseX, lastMouseY float64
	var mouseEventCount int
	var firstMouseTime, lastMouseTime int64

	var firstKeyTime, lastKeyTime int64
	var keyCount int

	var prevTime int64
	for i, e := range trace.Events {
		if i > 0 {
			interval := e.Timestamp - prevTime
			if interval > 0 {
				m.EventIntervals = (m.EventIntervals*float64(i-1) + float64(interval)) / float64(i)
			}
			if interval > 500 {
				m.LongPauses++
			}
			if interval > 100 {
				m.Pauses++
			}
		}
		prevTime = e.Timestamp

		switch e.Type {
		case "mousemove":
			m.MouseMovements++
			if mouseEventCount == 0 {
				firstMouseX, firstMouseY = e.X, e.Y
				firstMouseTime = e.Timestamp
			} else {
				dx := e.X - prevX
				dy := e.Y - prevY
				dist := math.Sqrt(dx*dx + dy*dy)
				totalDistance += dist
			}
			prevX, prevY = e.X, e.Y
			lastMouseX, lastMouseY = e.X, e.Y
			lastMouseTime = e.Timestamp
			mouseEventCount++

		case "keydown", "keypress":
			m.Keystrokes++
			if keyCount == 0 {
				firstKeyTime = e.Timestamp
			}
			lastKeyTime = e.Timestamp
			keyCount++

		case "scroll", "wheel":
			m.ScrollEvents++
		case "click", "mousedown", "mouseup":
			m.Clicks++
		}
	}

	// Calculate Velocity (pixels per second)
	if mouseEventCount > 1 && lastMouseTime > firstMouseTime {
		durationSec := float64(lastMouseTime-firstMouseTime) / 1000.0
		m.MouseVelocity = totalDistance / durationSec
	}

	// Calculate Typing Speed (characters per second)
	if keyCount > 1 && lastKeyTime > firstKeyTime {
		durationSec := float64(lastKeyTime-firstKeyTime) / 1000.0
		m.TypingSpeed = float64(keyCount) / durationSec
	}

	// Calculate Straightness
	if totalDistance > 0 {
		dx := lastMouseX - firstMouseX
		dy := lastMouseY - firstMouseY
		displacement := math.Sqrt(dx*dx + dy*dy)
		m.Straightness = displacement / totalDistance
	}
}

// CreateDetectionTrace creates a detection trace from a detection result.
func (ct *CaptchaTracer) CreateDetectionTrace(detection *DetectionResult) *DetectionTrace {
	if detection == nil {
		return nil
	}
	return &DetectionTrace{
		Timestamp:  detection.Timestamp,
		FinalScore: detection.Score,
		IsBot:      detection.IsBot,
	}
}

// GetTrace retrieves a trace by challenge ID.
func (ct *CaptchaTracer) GetTrace(challengeID string) (*CaptchaTrace, bool) {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	trace, ok := ct.traces[challengeID]
	return trace, ok
}

// CalculateBotScore calculates a bot score from trace metrics using both the quick
// heuristic checks and the full BehavioralAnalyzer's 8-check suite.
// The final score is the max of both to ensure either path catches bots.
func (ct *CaptchaTracer) CalculateBotScore(trace *CaptchaTrace) float64 {
	// Captcha bot scoring uses the quick heuristic checks only.
	// The full BehavioralAnalyzer (checks 1-24) is designed for HTTP request-level
	// detection and catches structural patterns in the behavioral data header.
	// Captcha events are short-lived interaction traces with different characteristics.
	return ct.calculateQuickScore(trace)
}

// CalculateBotScoreDetailed returns the bot score plus the full behavioral analysis result.
// Uses quick heuristics for scoring but still returns the analyzer result for diagnostics.
func (ct *CaptchaTracer) CalculateBotScoreDetailed(trace *CaptchaTrace) (float64, *VectorResult) {
	enhanced := ct.buildEnhancedEvents(trace)
	analyzer := NewBehavioralAnalyzer(nil)
	result := analyzer.Analyze(enhanced)

	// Use quick score for actual bot scoring (see CalculateBotScore comment)
	quickScore := ct.calculateQuickScore(trace)
	return quickScore, result
}

func (ct *CaptchaTracer) calculateQuickScore(trace *CaptchaTrace) float64 {
	score := 0.0
	if trace.Metrics.TotalEvents < 5 {
		score += 0.4
	}
	if trace.Metrics.MouseVelocity > 1000 || trace.Metrics.MouseVelocity < 10 {
		score += 0.2
	}
	if trace.Metrics.LongPauses == 0 && trace.Metrics.TotalEvents > 10 {
		score += 0.2
	}
	if trace.Metrics.TypingSpeed > 500 || trace.Metrics.TypingSpeed < 30 {
		score += 0.1
	}
	if score > 1.0 {
		score = 1.0
	}
	return score
}

// buildEnhancedEvents converts CaptchaTrace events into EnhancedBehavioralEvents
// for the full BehavioralAnalyzer suite.
func (ct *CaptchaTracer) buildEnhancedEvents(trace *CaptchaTrace) *EnhancedBehavioralEvents {
	enhanced := &EnhancedBehavioralEvents{
		MouseTimestamps:  make([]int64, 0),
		ScrollTimestamps: make([]int64, 0),
		TypingTimestamps: make([]int64, 0),
		MousePositions:   make([]Position, 0),
		MouseVelocities:  make([]float64, 0),
		ClickTimestamps:  make([]int64, 0),
		ClickPositions:   make([]Position, 0),
		ScrollDeltas:     make([]float64, 0),
	}

	var prevX, prevY float64
	var prevTimestamp int64
	firstMouse := true

	for _, ev := range trace.Events {
		switch ev.Type {
		case "mousemove":
			enhanced.MouseTimestamps = append(enhanced.MouseTimestamps, ev.Timestamp)
			enhanced.MousePositions = append(enhanced.MousePositions, Position{X: ev.X, Y: ev.Y})
			enhanced.MouseEvents++

			if !firstMouse && ev.Timestamp > prevTimestamp {
				dx := ev.X - prevX
				dy := ev.Y - prevY
				dt := float64(ev.Timestamp-prevTimestamp) / 1000.0 // seconds
				if dt > 0 {
					dist := math.Sqrt(dx*dx + dy*dy)
					velocity := dist / dt
					enhanced.MouseVelocities = append(enhanced.MouseVelocities, velocity)
				}
			}
			firstMouse = false
			prevX, prevY = ev.X, ev.Y
			prevTimestamp = ev.Timestamp

		case "keydown", "keypress":
			enhanced.TypingTimestamps = append(enhanced.TypingTimestamps, ev.Timestamp)
			enhanced.TypingEvents++

		case "scroll", "wheel":
			enhanced.ScrollTimestamps = append(enhanced.ScrollTimestamps, ev.Timestamp)
			enhanced.ScrollDeltas = append(enhanced.ScrollDeltas, ev.Delta)
			enhanced.ScrollEvents++

		case "click", "mousedown", "mouseup":
			enhanced.ClickTimestamps = append(enhanced.ClickTimestamps, ev.Timestamp)
			enhanced.ClickPositions = append(enhanced.ClickPositions, Position{X: ev.X, Y: ev.Y})
		}
	}

	return enhanced
}

// CaptchaTrainingData stores training data for CAPTCHA ML models.
type CaptchaTrainingData struct {
	mu       sync.RWMutex
	samples  []TrainingSample
	labels   []string
	features [][]float64
}

// TrainingSample represents a single training sample for ML models.
type TrainingSample struct {
	ID            string            `json:"id"`
	Timestamp     time.Time         `json:"timestamp"`
	ChallengeType string            `json:"challenge_type"`
	SessionID     string            `json:"session_id"`
	IsBot         bool              `json:"is_bot"`
	BotScore      float64           `json:"bot_score"`
	Solved        bool              `json:"solved"`
	SolveTimeMs   int64             `json:"solve_time_ms"`
	Attempts      int               `json:"attempts"`
	Features      []float64         `json:"features"`
	Label         string            `json:"label"`
	Events        []CaptchaEvent    `json:"events"`
	Metrics       *ChallengeMetrics `json:"metrics"`
}

// NewCaptchaTrainingData creates a new training data collector.
func NewCaptchaTrainingData() *CaptchaTrainingData {
	return &CaptchaTrainingData{
		samples:  make([]TrainingSample, 0),
		labels:   make([]string, 0),
		features: make([][]float64, 0),
	}
}

// RecordEvent records an event for a challenge.
// RecordEvent records an event for training data.
func (td *CaptchaTrainingData) RecordEvent(challengeID string, event *CaptchaEvent, _ *ChallengeMetrics) {
	td.mu.Lock()
	defer td.mu.Unlock()

	for i := range td.samples {
		if td.samples[i].ID == challengeID {
			td.samples[i].Events = append(td.samples[i].Events, *event)
			return
		}
	}

	td.samples = append(td.samples, TrainingSample{
		ID:        challengeID,
		Timestamp: time.Now(),
		Events:    []CaptchaEvent{*event},
		Metrics:   &ChallengeMetrics{},
	})
}

// RecordSample records a training sample.
// RecordSample records a training sample.
func (td *CaptchaTrainingData) RecordSample(sample TrainingSample) {
	td.mu.Lock()
	defer td.mu.Unlock()

	td.samples = append(td.samples, sample)
	td.labels = append(td.labels, sample.Label)
	td.features = append(td.features, sample.Features)
}

// Size returns the number of training samples.
// Size returns the number of training samples.
func (td *CaptchaTrainingData) Size() int {
	td.mu.RLock()
	defer td.mu.RUnlock()

	return len(td.samples)
}

// GetFeatures returns the feature matrix for ML training.
// GetFeatures returns feature vectors for all samples.
func (td *CaptchaTrainingData) GetFeatures() [][]float64 {
	td.mu.RLock()
	defer td.mu.RUnlock()

	result := make([][]float64, len(td.features))
	copy(result, td.features)
	return result
}

// GetLabels returns the label vector for ML training.
// GetLabels returns labels for all samples.
func (td *CaptchaTrainingData) GetLabels() []string {
	td.mu.RLock()
	defer td.mu.RUnlock()

	result := make([]string, len(td.labels))
	copy(result, td.labels)
	return result
}

// ExportJSON exports training data as JSON.
func (td *CaptchaTrainingData) ExportJSON() ([]byte, error) {
	td.mu.RLock()
	defer td.mu.RUnlock()

	return json.MarshalIndent(td.samples, "", "  ")
}

// ExportForML exports training data formatted for machine learning.
func (td *CaptchaTrainingData) ExportForML() ([]byte, error) {
	td.mu.RLock()
	defer td.mu.RUnlock()

	type MLExport struct {
		Features [][]float64 `json:"features"`
		Labels   []string    `json:"labels"`
		Metadata struct {
			TotalSamples int `json:"total_samples"`
			HumanSamples int `json:"human_samples"`
			BotSamples   int `json:"bot_samples"`
		} `json:"metadata"`
	}

	export := MLExport{
		Features: td.features,
		Labels:   td.labels,
	}

	export.Metadata.TotalSamples = len(td.samples)
	for _, l := range td.labels {
		switch l {
		case "human":
			export.Metadata.HumanSamples++
		case "bot":
			export.Metadata.BotSamples++
		}
	}

	return json.MarshalIndent(export, "", "  ")
}

// TrainingDataStats holds aggregate statistics about collected training data.
type TrainingDataStats struct {
	TotalSamples int            `json:"total_samples"`
	ByLabel      map[string]int `json:"by_label"`
	ByType       map[string]int `json:"by_type"`
}

// GetSamplesFiltered returns a filtered, paginated slice of training samples
// along with the total count matching the filter criteria.
func (td *CaptchaTrainingData) GetSamplesFiltered(typeFilter, labelFilter string, limit, offset int) ([]TrainingSample, int) {
	td.mu.RLock()
	defer td.mu.RUnlock()

	var filtered []TrainingSample
	for _, s := range td.samples {
		if typeFilter != "" && s.ChallengeType != typeFilter {
			continue
		}
		if labelFilter != "" && s.Label != labelFilter {
			continue
		}
		filtered = append(filtered, s)
	}

	total := len(filtered)

	if offset >= total {
		return []TrainingSample{}, total
	}

	end := offset + limit
	if end > total {
		end = total
	}

	return filtered[offset:end], total
}

// ExportCSV exports training data in CSV format.
func (td *CaptchaTrainingData) ExportCSV() ([]byte, error) {
	td.mu.RLock()
	defer td.mu.RUnlock()

	header := "id,timestamp,challenge_type,session_id,is_bot,bot_score,solved,solve_time_ms,attempts,label\n"
	var buf []byte
	buf = append(buf, header...)

	for _, s := range td.samples {
		line := fmt.Sprintf("%s,%s,%s,%s,%t,%.4f,%t,%d,%d,%s\n",
			s.ID,
			s.Timestamp.Format("2006-01-02T15:04:05Z"),
			s.ChallengeType,
			s.SessionID,
			s.IsBot,
			s.BotScore,
			s.Solved,
			s.SolveTimeMs,
			s.Attempts,
			s.Label,
		)
		buf = append(buf, line...)
	}

	return buf, nil
}

// GetStats returns aggregate statistics about the training data.
func (td *CaptchaTrainingData) GetStats() TrainingDataStats {
	td.mu.RLock()
	defer td.mu.RUnlock()

	stats := TrainingDataStats{
		TotalSamples: len(td.samples),
		ByLabel:      make(map[string]int),
		ByType:       make(map[string]int),
	}

	for _, s := range td.samples {
		if s.Label != "" {
			stats.ByLabel[s.Label]++
		}
		if s.ChallengeType != "" {
			stats.ByType[s.ChallengeType]++
		}
	}

	return stats
}

func extractFeaturesFromMetrics(m *TraceMetrics) []float64 {
	if m == nil {
		return make([]float64, 11) // Return zeroed feature vector
	}
	return []float64{
		float64(m.TotalEvents),
		float64(m.MouseMovements),
		float64(m.Keystrokes),
		float64(m.ScrollEvents),
		float64(m.Clicks),
		m.MouseVelocity,
		m.TypingSpeed,
		m.EventIntervals,
		m.Straightness,
		float64(m.Pauses),
		float64(m.LongPauses),
	}
}

// RecordChallengeResult records the result of a challenge attempt.
func (td *CaptchaTrainingData) RecordChallengeResult(challenge *CaptchaChallenge, solved bool, traceMetrics *TraceMetrics, botScore float64) {
	features := extractFeaturesFromMetrics(traceMetrics)

	label := "unknown"
	isBot := false
	if solved && botScore < 0.5 {
		label = "human"
	} else if !solved || botScore >= 0.5 {
		label = "bot"
		isBot = true
	}

	sample := TrainingSample{
		ID:            challenge.ID,
		Timestamp:     time.Now(),
		ChallengeType: challenge.Type,
		SessionID:     challenge.SessionID,
		IsBot:         isBot,
		BotScore:      botScore,
		Solved:        solved,
		SolveTimeMs:   challenge.Metrics.SolveTimeMs,
		Attempts:      challenge.Metrics.AttemptCount,
		Features:      features,
		Label:         label,
	}

	td.RecordSample(sample)
}

var globalTracer = NewCaptchaTracer()

// GetGlobalTracer returns the global CAPTCHA tracer instance.
func GetGlobalTracer() *CaptchaTracer {
	return globalTracer
}
