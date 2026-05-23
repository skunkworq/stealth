package captcha

// BehaviorSimConfig holds configuration for behavioral analysis.
type BehaviorSimConfig struct {
	MouseMovements   bool
	Keystrokes       bool
	ScrollPatterns   bool
	TouchGestures    bool
	SessionDuration  int
	MinEvents        int
	MaxPauseMs       int
	PatternThreshold float64
}

// DefaultBehaviorSimConfig provides default settings for behavioral analysis.
var DefaultBehaviorSimConfig = BehaviorSimConfig{
	MouseMovements:   true,
	Keystrokes:       true,
	ScrollPatterns:   true,
	TouchGestures:    false,
	SessionDuration:  30,
	MinEvents:        10,
	MaxPauseMs:       500,
	PatternThreshold: 0.7,
}

// BehavioralEvent represents a single behavioral event.
type BehavioralEvent struct {
	Type        string
	Timestamp   int64
	X           float64
	Y           float64
	Duration    int64
	Key         string
	ScrollDelta float64
}

// BehavioralProfile holds behavioral analysis data for a session.
type BehavioralProfile struct {
	Events        []BehavioralEvent
	TotalDuration int64
	EventCount    int
	MouseSpeed    float64
	TypingSpeed   float64
	ScrollPattern string
	IsHuman       bool
	Confidence    float64
}

// NewBehavioralProfile creates a new behavioral profile for analysis.
func NewBehavioralProfile(_ *BehaviorSimConfig) *BehavioralProfile {
	return &BehavioralProfile{
		Events: make([]BehavioralEvent, 0),
	}
}

// AddEvent adds a behavioral event to the profile.
func (b *BehavioralProfile) AddEvent(event BehavioralEvent) {
	b.Events = append(b.Events, event)
	b.EventCount = len(b.Events)
	if len(b.Events) > 1 {
		b.TotalDuration = event.Timestamp - b.Events[0].Timestamp
	}
}

// Analyze evaluates the behavioral profile and returns a human-likeness score.
func (b *BehavioralProfile) Analyze() float64 {
	if len(b.Events) < 5 {
		b.IsHuman = false
		b.Confidence = 0.0
		return 0.0
	}

	var mouseMovements int
	var keystrokes int
	var scrolls int

	for _, e := range b.Events {
		switch e.Type {
		case "mousemove", "mousedown", "mouseup", "click":
			mouseMovements++
		case "keydown", "keyup", "keypress":
			keystrokes++
		case "scroll", "wheel":
			scrolls++
		}
	}

	humanScore := 0.0

	if mouseMovements > 0 {
		avgSpeed := calculateAvgMouseSpeed(b.Events)
		if avgSpeed > 50 && avgSpeed < 500 {
			humanScore += 0.3
		}
	}

	if keystrokes > 0 {
		typingRhythm := analyzeTypingRhythm(b.Events)
		if typingRhythm > 0.3 {
			humanScore += 0.3
		}
	}

	if scrolls > 0 {
		humanScore += 0.2
	}

	if b.TotalDuration > 5000 {
		humanScore += 0.2
	}

	b.IsHuman = humanScore >= 0.5
	b.Confidence = humanScore

	return humanScore
}

func calculateAvgMouseSpeed(events []BehavioralEvent) float64 {
	var totalSpeed float64
	var count int

	for i := 1; i < len(events); i++ {
		if events[i].Type == "mousemove" && events[i-1].Type == "mousemove" {
			dx := events[i].X - events[i-1].X
			dy := events[i].Y - events[i-1].Y
			dt := float64(events[i].Timestamp - events[i-1].Timestamp)
			if dt > 0 {
				distance := dx*dx + dy*dy
				speed := distance / dt
				totalSpeed += speed
				count++
			}
		}
	}

	if count == 0 {
		return 0
	}
	return totalSpeed / float64(count)
}

func analyzeTypingRhythm(events []BehavioralEvent) float64 {
	var keydowns []int64

	for _, e := range events {
		if e.Type == "keydown" {
			keydowns = append(keydowns, e.Timestamp)
		}
	}

	if len(keydowns) < 2 {
		return 0.0
	}

	var totalVariance float64
	for i := 1; i < len(keydowns); i++ {
		interval := keydowns[i] - keydowns[i-1]
		totalVariance += float64(interval)
	}

	avgInterval := totalVariance / float64(len(keydowns)-1)

	if avgInterval > 50 && avgInterval < 300 {
		return 0.6
	}

	return 0.3
}
