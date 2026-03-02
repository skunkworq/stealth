package stealth

import (
	"math"
	"sync"
	"time"

	"github.com/stealth/brwslab/brws/behavior"
)

// BehavioralTracker accumulates mouse, keyboard, and scroll events during a
// browsing session. The tracked data can be exported as a BehavioralSnapshot
// for training data collection or self-evaluation against the shield.
type BehavioralTracker struct {
	mu sync.Mutex

	startTime   time.Time
	lastMouseX  float64
	lastMouseY  float64
	hasLastPos  bool

	mouseTimestamps  []int64
	typingTimestamps []int64
	mousePositionsX  []float64
	mousePositionsY  []float64
	mouseVelocities  []float64
}

// NewBehavioralTracker creates a new tracker starting from now.
func NewBehavioralTracker() *BehavioralTracker {
	return &BehavioralTracker{
		startTime:        time.Now(),
		mouseTimestamps:  make([]int64, 0, 64),
		typingTimestamps: make([]int64, 0, 32),
		mousePositionsX:  make([]float64, 0, 64),
		mousePositionsY:  make([]float64, 0, 64),
		mouseVelocities:  make([]float64, 0, 64),
	}
}

// RecordMouseMove records a mouse movement event with position and velocity.
func (bt *BehavioralTracker) RecordMouseMove(x, y float64) {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	now := time.Since(bt.startTime).Milliseconds()
	bt.mouseTimestamps = append(bt.mouseTimestamps, now)
	bt.mousePositionsX = append(bt.mousePositionsX, x)
	bt.mousePositionsY = append(bt.mousePositionsY, y)

	// Calculate velocity from previous position
	if bt.hasLastPos && len(bt.mouseTimestamps) >= 2 {
		prevTs := bt.mouseTimestamps[len(bt.mouseTimestamps)-2]
		dt := float64(now-prevTs) / 1000.0 // seconds
		if dt > 0 {
			dx := x - bt.lastMouseX
			dy := y - bt.lastMouseY
			dist := math.Sqrt(dx*dx + dy*dy)
			bt.mouseVelocities = append(bt.mouseVelocities, dist/dt)
		}
	}

	bt.lastMouseX = x
	bt.lastMouseY = y
	bt.hasLastPos = true
}

// RecordKeystroke records a keyboard event timestamp.
func (bt *BehavioralTracker) RecordKeystroke() {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	now := time.Since(bt.startTime).Milliseconds()
	bt.typingTimestamps = append(bt.typingTimestamps, now)
}

// Snapshot exports the accumulated behavioral data as EventData suitable
// for the X-Behavioral-Data header or training data collection.
func (bt *BehavioralTracker) Snapshot() *behavior.EventData {
	bt.mu.Lock()
	defer bt.mu.Unlock()

	positions := make([]map[string]float64, len(bt.mousePositionsX))
	for i := range bt.mousePositionsX {
		positions[i] = map[string]float64{"x": bt.mousePositionsX[i], "y": bt.mousePositionsY[i]}
	}

	return &behavior.EventData{
		MouseTimestamps:  append([]int64{}, bt.mouseTimestamps...),
		TypingTimestamps: append([]int64{}, bt.typingTimestamps...),
		MousePositions:   positions,
		MouseVelocities:  append([]float64{}, bt.mouseVelocities...),
	}
}
