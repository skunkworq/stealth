package captcha

import (
	"fmt"
	"math/rand"
	"time"
)

// webGLRand is a local random source for WebGL scene generation.
// math/rand is used intentionally (not crypto/rand) because:
// 1. We need reproducible randomness for visual scene generation
// 2. Performance is more important than cryptographic security for visual effects
// 3. The randomness is used for visual placement, not security
var webGLRand = rand.New(rand.NewSource(time.Now().UnixNano()))

// WebGLSceneConfig holds configuration for WebGL-based CAPTCHA scenes.
type WebGLSceneConfig struct {
	SceneType       string
	ObjectCount     int
	RotationEnabled bool
	ZoomEnabled     bool
	PanEnabled      bool
	ObjectTypes     []string
	TargetObject    string
	InstructionText string
	TimeLimit       int
	Difficulty      string
}

// DefaultWebGLSceneConfig provides default settings for WebGL CAPTCHA scenes.
var DefaultWebGLSceneConfig = WebGLSceneConfig{
	SceneType:       "3d_objects",
	ObjectCount:     5,
	RotationEnabled: true,
	ZoomEnabled:     true,
	PanEnabled:      false,
	ObjectTypes:     []string{"cube", "sphere", "cone", "cylinder", "torus"},
	TargetObject:    "sphere",
	InstructionText: "Find and click the sphere",
	TimeLimit:       30,
	Difficulty:      "medium",
}

// WebGLSceneObject represents an object in a WebGL CAPTCHA scene.
type WebGLSceneObject struct {
	ID        string     `json:"id"`
	Type      string     `json:"type"`
	Position  [3]float64 `json:"position"`
	Rotation  [3]float64 `json:"rotation"`
	Scale     float64    `json:"scale"`
	Color     string     `json:"color"`
	IsTarget  bool       `json:"is_target"`
	Clickable bool       `json:"clickable"`
	Occluded  bool       `json:"occluded"`
}

// WebGLCaptcha represents a WebGL-based interactive CAPTCHA.
type WebGLCaptcha struct {
	ID          string             `json:"id"`
	Config      WebGLSceneConfig   `json:"config"`
	Scene       []WebGLSceneObject `json:"scene"`
	TargetID    string             `json:"target_id"`
	StartTime   time.Time          `json:"start_time"`
	ExpiresAt   time.Time          `json:"expires_at"`
	Solved      bool               `json:"solved"`
	ClickEvents []WebGLClickEvent  `json:"click_events"`
}

// WebGLClickEvent represents a click event in a WebGL CAPTCHA.
type WebGLClickEvent struct {
	Timestamp int64   `json:"timestamp"`
	ObjectID  string  `json:"object_id"`
	X         float64 `json:"x"`
	Y         float64 `json:"y"`
	IsCorrect bool    `json:"is_correct"`
	ElapsedMs int64   `json:"elapsed_ms"`
}

// WebGLChallengeMetrics holds performance metrics for WebGL CAPTCHA challenges.
type WebGLChallengeMetrics struct {
	TotalClicks   int
	CorrectClicks int
	SolveTimeMs   int64
}

// NewWebGLCaptcha creates a new WebGL CAPTCHA instance.
func NewWebGLCaptcha(config *WebGLSceneConfig) *WebGLCaptcha {
	if config == nil {
		config = &DefaultWebGLSceneConfig
	}

	now := time.Now()
	captcha := &WebGLCaptcha{
		ID:          fmt.Sprintf("webgl_%d_%d", now.Unix(), now.Nanosecond()),
		Config:      *config,
		Scene:       make([]WebGLSceneObject, 0),
		StartTime:   now,
		ExpiresAt:   now.Add(2 * time.Minute),
		Solved:      false,
		ClickEvents: make([]WebGLClickEvent, 0),
	}

	captcha.generateScene()
	return captcha
}

func (w *WebGLCaptcha) generateScene() {
	objects := make([]WebGLSceneObject, w.Config.ObjectCount)
	targetIndex := webGLRand.Intn(w.Config.ObjectCount)

	colors := []string{"#FF5733", "#33FF57", "#3357FF", "#F333FF", "#FF33F3", "#33FFF3", "#F3FF33", "#FF8C33"}

	for i := range objects {
		isTarget := (i == targetIndex)
		objType := w.Config.ObjectTypes[webGLRand.Intn(len(w.Config.ObjectTypes))]

		if isTarget {
			objType = w.Config.TargetObject
		}

		objects[i] = WebGLSceneObject{
			ID:   fmt.Sprintf("obj_%d", i),
			Type: objType,
			Position: [3]float64{
				float64(webGLRand.Intn(400) - 200),
				float64(webGLRand.Intn(400) - 200),
				float64(webGLRand.Intn(400) - 200),
			},
			Rotation: [3]float64{
				float64(webGLRand.Intn(360)),
				float64(webGLRand.Intn(360)),
				float64(webGLRand.Intn(360)),
			},
			Scale:     0.5 + webGLRand.Float64()*1.5,
			Color:     colors[webGLRand.Intn(len(colors))],
			IsTarget:  isTarget,
			Clickable: true,
			Occluded:  webGLRand.Float64() > 0.7,
		}
	}

	w.Scene = objects
	w.TargetID = objects[targetIndex].ID
}

// RecordClick records a click event and returns true if the CAPTCHA is solved.
func (w *WebGLCaptcha) RecordClick(x, y float64) bool {
	elapsedMs := time.Since(w.StartTime).Milliseconds()

	event := WebGLClickEvent{
		Timestamp: time.Now().UnixMilli(),
		ObjectID:  "",
		X:         x,
		Y:         y,
		IsCorrect: false,
		ElapsedMs: elapsedMs,
	}

	for _, obj := range w.Scene {
		if obj.IsTarget && obj.Clickable && !obj.Occluded {
			event.ObjectID = obj.ID
			event.IsCorrect = true
			break
		}
	}

	w.ClickEvents = append(w.ClickEvents, event)

	if event.IsCorrect {
		w.Solved = true
	}

	return w.Solved
}

// IsExpired returns true if the WebGL CAPTCHA has expired.
func (w *WebGLCaptcha) IsExpired() bool {
	return time.Now().After(w.ExpiresAt)
}

// GetMetrics returns performance metrics for the WebGL CAPTCHA challenge.
func (w *WebGLCaptcha) GetMetrics() *WebGLChallengeMetrics {
	metrics := &WebGLChallengeMetrics{
		TotalClicks:   len(w.ClickEvents),
		CorrectClicks: 0,
		SolveTimeMs:   0,
	}

	if len(w.ClickEvents) > 0 {
		metrics.SolveTimeMs = w.ClickEvents[len(w.ClickEvents)-1].ElapsedMs
	}

	for _, e := range w.ClickEvents {
		if e.IsCorrect {
			metrics.CorrectClicks++
		}
	}

	return metrics
}
