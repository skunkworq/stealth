package challenge

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// TraceSession represents a recording session where a human solves captchas.
// The user solves challenges manually while we capture every event for later replay.
type TraceSession struct {
	ID          string            `json:"id"`
	StartedAt   time.Time         `json:"started_at"`
	EndedAt     time.Time         `json:"ended_at,omitempty"`
	Operator    string            `json:"operator,omitempty"` // who solved it (e.g. "ben")
	Environment TraceEnvironment  `json:"environment"`
	Recordings  []*TraceRecording `json:"recordings"`
}

// TraceEnvironment captures the browser/system context during recording.
type TraceEnvironment struct {
	UserAgent   string  `json:"user_agent,omitempty"`
	Platform    string  `json:"platform,omitempty"`
	ScreenW     int     `json:"screen_w,omitempty"`
	ScreenH     int     `json:"screen_h,omitempty"`
	DeviceScale float64 `json:"device_scale,omitempty"`
	Timezone    string  `json:"timezone,omitempty"`
}

// TraceRecording is a single captcha solve attempt with all events captured.
type TraceRecording struct {
	ID               string                 `json:"id"`
	SessionID        string                 `json:"session_id"`
	ChallengeType    ChallengeType          `json:"challenge_type"`    // e.g. ChallengeRecaptchaV2, ChallengeTurnstile, ChallengeTypeCloudflareManaged
	ChallengeVariant string                 `json:"challenge_variant"` // image_grid, rotate, slide, checkbox, behavioral, etc.
	SiteURL          string                 `json:"site_url,omitempty"`
	SiteKey          string                 `json:"site_key,omitempty"`
	StartedAt        time.Time              `json:"started_at"`
	CompletedAt      time.Time              `json:"completed_at,omitempty"`
	DurationMs       int64                  `json:"duration_ms"`
	Solved           bool                   `json:"solved"`
	Events           []CaptchaEvent         `json:"events"`
	Phases           []TracePhase           `json:"phases,omitempty"`
	Metrics          *TraceRecordingMetrics `json:"metrics"`
	WidgetBounds     *WidgetBounds          `json:"widget_bounds,omitempty"`
	Annotations      []string               `json:"annotations,omitempty"` // human notes
}

// TracePhase marks a named segment within a recording (e.g. "approach", "interact", "submit").
type TracePhase struct {
	Name      string `json:"name"`
	StartMs   int64  `json:"start_ms"`
	EndMs     int64  `json:"end_ms"`
	EventFrom int    `json:"event_from"` // index into Events
	EventTo   int    `json:"event_to"`
}

// WidgetBounds captures the pixel coordinates of the captcha widget on screen.
type WidgetBounds struct {
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

// TraceRecordingMetrics are computed after recording completes.
type TraceRecordingMetrics struct {
	TotalEvents      int     `json:"total_events"`
	MouseMoves       int     `json:"mouse_moves"`
	Clicks           int     `json:"clicks"`
	Keystrokes       int     `json:"keystrokes"`
	Scrolls          int     `json:"scrolls"`
	AvgMouseVelocity float64 `json:"avg_mouse_velocity"` // px/s
	MaxMouseVelocity float64 `json:"max_mouse_velocity"`
	AvgEventInterval float64 `json:"avg_event_interval_ms"`
	Pauses           int     `json:"pauses"`       // >200ms gaps
	Hesitations      int     `json:"hesitations"`  // >500ms gaps
	Straightness     float64 `json:"straightness"` // displacement/distance
	DirectionChanges int     `json:"direction_changes"`
	YVariance        float64 `json:"y_variance"`
}

// TraceRecorder manages recording sessions.
type TraceRecorder struct {
	mu       sync.Mutex
	sessions map[string]*TraceSession
	baseDir  string // where traces are saved
}

// NewTraceRecorder creates a recorder that persists to the given directory.
func NewTraceRecorder(baseDir string) *TraceRecorder {
	return &TraceRecorder{
		sessions: make(map[string]*TraceSession),
		baseDir:  baseDir,
	}
}

// StartSession begins a new recording session.
func (tr *TraceRecorder) StartSession(operator string, env TraceEnvironment) *TraceSession {
	tr.mu.Lock()
	defer tr.mu.Unlock()

	id := fmt.Sprintf("sess_%s_%d", sanitizeOperator(operator), time.Now().UnixMilli())
	session := &TraceSession{
		ID:          id,
		StartedAt:   time.Now().UTC(),
		Operator:    operator,
		Environment: env,
		Recordings:  make([]*TraceRecording, 0),
	}
	tr.sessions[id] = session
	return session
}

// StartRecording begins recording a single captcha solve within a session.
func (tr *TraceRecorder) StartRecording(sessionID string, challengeType ChallengeType, challengeVariant, siteURL string) (*TraceRecording, error) {
	tr.mu.Lock()
	defer tr.mu.Unlock()

	session, ok := tr.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}

	recID := fmt.Sprintf("rec_%s_%d", challengeType, len(session.Recordings)+1)
	rec := &TraceRecording{
		ID:               recID,
		SessionID:        sessionID,
		ChallengeType:    challengeType,
		ChallengeVariant: challengeVariant,
		SiteURL:          siteURL,
		StartedAt:        time.Now().UTC(),
		Events:           make([]CaptchaEvent, 0, 256),
		Metrics:          &TraceRecordingMetrics{},
	}
	session.Recordings = append(session.Recordings, rec)
	return rec, nil
}

// RecordEvent adds an event to the active recording.
func (tr *TraceRecorder) RecordEvent(sessionID, recordingID string, event CaptchaEvent) error {
	tr.mu.Lock()
	defer tr.mu.Unlock()

	session, ok := tr.sessions[sessionID]
	if !ok {
		return fmt.Errorf("session %s not found", sessionID)
	}

	for _, rec := range session.Recordings {
		if rec.ID == recordingID {
			// Normalize elapsed time relative to recording start
			if event.ElapsedMs == 0 && !rec.StartedAt.IsZero() {
				event.ElapsedMs = time.Since(rec.StartedAt).Milliseconds()
			}
			rec.Events = append(rec.Events, event)
			return nil
		}
	}
	return fmt.Errorf("recording %s not found in session %s", recordingID, sessionID)
}

// RecordEvents adds a batch of events (e.g. from a JS event buffer flush).
func (tr *TraceRecorder) RecordEvents(sessionID, recordingID string, events []CaptchaEvent) error {
	tr.mu.Lock()
	defer tr.mu.Unlock()

	session, ok := tr.sessions[sessionID]
	if !ok {
		return fmt.Errorf("session %s not found", sessionID)
	}

	for _, rec := range session.Recordings {
		if rec.ID == recordingID {
			rec.Events = append(rec.Events, events...)
			return nil
		}
	}
	return fmt.Errorf("recording %s not found", recordingID)
}

// CompleteRecording finalizes a recording, computes metrics, and marks it solved/unsolved.
func (tr *TraceRecorder) CompleteRecording(sessionID, recordingID string, solved bool) (*TraceRecording, error) {
	tr.mu.Lock()
	defer tr.mu.Unlock()

	session, ok := tr.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}

	for _, rec := range session.Recordings {
		if rec.ID == recordingID {
			rec.CompletedAt = time.Now().UTC()
			rec.DurationMs = rec.CompletedAt.Sub(rec.StartedAt).Milliseconds()
			rec.Solved = solved
			rec.Metrics = computeRecordingMetrics(rec.Events)
			return rec, nil
		}
	}
	return nil, fmt.Errorf("recording %s not found", recordingID)
}

// EndSession finalizes a session and saves it to disk.
func (tr *TraceRecorder) EndSession(sessionID string) (*TraceSession, error) {
	tr.mu.Lock()
	defer tr.mu.Unlock()

	session, ok := tr.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}

	session.EndedAt = time.Now().UTC()

	if err := tr.saveSession(session); err != nil {
		return session, fmt.Errorf("save session: %w", err)
	}

	return session, nil
}

// GetSession returns a session by ID.
func (tr *TraceRecorder) GetSession(sessionID string) (*TraceSession, bool) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	s, ok := tr.sessions[sessionID]
	return s, ok
}

func (tr *TraceRecorder) saveSession(session *TraceSession) error {
	dir := filepath.Join(tr.baseDir, "traces", session.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	// Save session metadata
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "session.json"), data, 0o644); err != nil {
		return err
	}

	// Save each recording separately for easier loading
	for _, rec := range session.Recordings {
		recData, err := json.MarshalIndent(rec, "", "  ")
		if err != nil {
			return err
		}
		fname := fmt.Sprintf("%s_%s.json", rec.ChallengeType, rec.ID)
		if err := os.WriteFile(filepath.Join(dir, fname), recData, 0o644); err != nil {
			return err
		}
	}

	return nil
}

// LoadSession loads a previously saved session from disk.
func (tr *TraceRecorder) LoadSession(sessionID string) (*TraceSession, error) {
	path := filepath.Join(tr.baseDir, "traces", sessionID, "session.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var session TraceSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}

	tr.mu.Lock()
	tr.sessions[session.ID] = &session
	tr.mu.Unlock()

	return &session, nil
}

// computeRecordingMetrics analyzes the event stream to extract behavioral metrics.
func computeRecordingMetrics(events []CaptchaEvent) *TraceRecordingMetrics {
	m := &TraceRecordingMetrics{TotalEvents: len(events)}
	if len(events) == 0 {
		return m
	}

	var prevX, prevY float64
	var prevTime int64
	var totalDist float64
	var firstX, firstY, lastX, lastY float64
	var mouseCount int
	var prevDx, prevDy float64
	var velocities []float64
	var yValues []float64

	for i, e := range events {
		switch e.Type {
		case "mousemove":
			m.MouseMoves++
			if mouseCount > 0 {
				dx := e.X - prevX
				dy := e.Y - prevY
				dist := dx*dx + dy*dy
				if dist > 0 {
					dist = sqrtf64(dist)
					totalDist += dist
				}
				// Direction change: dot product with previous direction
				if mouseCount > 1 {
					dot := dx*prevDx + dy*prevDy
					if dot < 0 {
						m.DirectionChanges++
					}
				}
				prevDx, prevDy = dx, dy

				// Velocity
				if e.ElapsedMs > prevTime {
					dt := float64(e.ElapsedMs-prevTime) / 1000.0
					if dt > 0 {
						v := dist / dt
						velocities = append(velocities, v)
						if v > m.MaxMouseVelocity {
							m.MaxMouseVelocity = v
						}
					}
				}
			} else {
				firstX, firstY = e.X, e.Y
			}
			prevX, prevY = e.X, e.Y
			lastX, lastY = e.X, e.Y
			yValues = append(yValues, e.Y)
			mouseCount++

		case "click", "mousedown", "mouseup":
			m.Clicks++
		case "keydown", "keypress":
			m.Keystrokes++
		case "scroll", "wheel":
			m.Scrolls++
		}

		// Intervals/pauses
		if i > 0 && e.ElapsedMs > prevTime {
			gap := e.ElapsedMs - prevTime
			if gap > 500 {
				m.Hesitations++
			} else if gap > 200 {
				m.Pauses++
			}
		}
		prevTime = e.ElapsedMs
	}

	// Average velocity
	if len(velocities) > 0 {
		sum := 0.0
		for _, v := range velocities {
			sum += v
		}
		m.AvgMouseVelocity = sum / float64(len(velocities))
	}

	// Average event interval
	if len(events) > 1 {
		span := events[len(events)-1].ElapsedMs - events[0].ElapsedMs
		m.AvgEventInterval = float64(span) / float64(len(events)-1)
	}

	// Straightness
	if totalDist > 0 {
		dx := lastX - firstX
		dy := lastY - firstY
		displacement := sqrtf64(dx*dx + dy*dy)
		m.Straightness = displacement / totalDist
	}

	// Y variance
	if len(yValues) > 1 {
		m.YVariance = calculateVariance(yValues)
	}

	return m
}

func sqrtf64(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// Newton's method (4 iterations, good enough for pixel distances)
	r := x
	for range 4 {
		r = (r + x/r) / 2
	}
	return r
}

func sanitizeOperator(name string) string {
	var out []byte
	for _, b := range []byte(name) {
		if (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_' {
			out = append(out, b)
		} else if b >= 'A' && b <= 'Z' {
			out = append(out, b+32) // lowercase
		}
	}
	if len(out) == 0 {
		return "anon"
	}
	return string(out)
}

func calculateVariance(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}
	mean := 0.0
	for _, v := range values {
		mean += v
	}
	mean /= float64(len(values))
	variance := 0.0
	for _, v := range values {
		diff := v - mean
		variance += diff * diff
	}
	return variance / float64(len(values)-1)
}

// TraceFingerprint produces a short hash of a recording's event pattern,
// useful for deduplicating similar traces.
func TraceFingerprint(rec *TraceRecording) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s:%s:%d:", rec.ChallengeType, rec.ChallengeVariant, len(rec.Events))
	for _, e := range rec.Events {
		fmt.Fprintf(h, "%s:%.0f:%.0f:%d|", e.Type, e.X, e.Y, e.ElapsedMs)
	}
	return fmt.Sprintf("%x", h.Sum(nil)[:8])
}
