package challenge

// Position represents an x,y coordinate.
type Position struct {
	X, Y float64
}

// EnhancedBehavioralEvents extends BehavioralEvents with raw data for analysis.
type EnhancedBehavioralEvents struct {
	BehavioralEvents

	// Raw event timestamps (ms since epoch)
	MouseTimestamps  []int64
	ScrollTimestamps []int64
	TypingTimestamps []int64

	// Mouse positions for path analysis
	MousePositions []Position

	// Mouse velocities
	MouseVelocities []float64

	// Click data for precision analysis
	ClickTimestamps []int64
	ClickPositions  []Position
	ClickDwellTimes []int64

	// Scroll data for uniformity analysis
	ScrollDeltas []float64

	// Phase 10: Keystroke hold times (ms) — duration of keydown→keyup per keystroke
	KeystrokeHoldTimes []float64
	// Phase 10: Scroll directions — positive=down, negative=up
	ScrollDirections []float64

	// Phase 46: Error stack trace
	ErrorStack string

	// Metrics from header (fallback)
	EventTimingStdDev float64
	MouseStraightness float64
}

// NewEnhancedBehavioralEventsFromMap populates EnhancedBehavioralEvents from a map.
func NewEnhancedBehavioralEventsFromMap(behav map[string]interface{}) *EnhancedBehavioralEvents {
	events := &EnhancedBehavioralEvents{}

	// Extract mouse timestamps
	if ts, ok := behav["mouseTimestamps"].([]interface{}); ok {
		for _, t := range ts {
			if v, ok := t.(float64); ok {
				events.MouseTimestamps = append(events.MouseTimestamps, int64(v))
			}
		}
	}

	// Extract typing timestamps
	if ts, ok := behav["typingTimestamps"].([]interface{}); ok {
		for _, t := range ts {
			if v, ok := t.(float64); ok {
				events.TypingTimestamps = append(events.TypingTimestamps, int64(v))
			}
		}
	}

	// Extract mouse positions
	if pos, ok := behav["mousePositions"].([]interface{}); ok {
		for _, p := range pos {
			if pt, ok := p.(map[string]interface{}); ok {
				x, _ := pt["x"].(float64)
				y, _ := pt["y"].(float64)
				events.MousePositions = append(events.MousePositions, Position{X: x, Y: y})
			}
		}
	}

	// Extract mouse velocities
	if vel, ok := behav["mouseVelocities"].([]interface{}); ok {
		for _, v := range vel {
			if f, ok := v.(float64); ok {
				events.MouseVelocities = append(events.MouseVelocities, f)
			}
		}
	}

	// Extract click timestamps
	if ts, ok := behav["clickTimestamps"].([]interface{}); ok {
		for _, t := range ts {
			if v, ok := t.(float64); ok {
				events.ClickTimestamps = append(events.ClickTimestamps, int64(v))
			}
		}
	}

	// Extract click positions
	if pos, ok := behav["clickPositions"].([]interface{}); ok {
		for _, p := range pos {
			if pt, ok := p.(map[string]interface{}); ok {
				x, _ := pt["x"].(float64)
				y, _ := pt["y"].(float64)
				events.ClickPositions = append(events.ClickPositions, Position{X: x, Y: y})
			}
		}
	}

	// Extract click dwell times
	if dwells, ok := behav["clickDwellTimes"].([]interface{}); ok {
		for _, d := range dwells {
			if v, ok := d.(float64); ok {
				events.ClickDwellTimes = append(events.ClickDwellTimes, int64(v))
			}
		}
	}

	// Extract keystroke hold times
	if holds, ok := behav["keystrokeHoldTimes"].([]interface{}); ok {
		for _, h := range holds {
			if v, ok := h.(float64); ok {
				events.KeystrokeHoldTimes = append(events.KeystrokeHoldTimes, v)
			}
		}
	}

	// Extract scroll directions
	if dirs, ok := behav["scrollDirections"].([]interface{}); ok {
		for _, d := range dirs {
			if v, ok := d.(float64); ok {
				events.ScrollDirections = append(events.ScrollDirections, v)
			}
		}
	}

	// Extract scroll deltas
	if deltas, ok := behav["scrollDeltas"].([]interface{}); ok {
		for _, d := range deltas {
			if v, ok := d.(float64); ok {
				events.ScrollDeltas = append(events.ScrollDeltas, v)
			}
		}
	}

	// Extract scroll timestamps
	if ts, ok := behav["scrollTimestamps"].([]interface{}); ok {
		for _, t := range ts {
			if v, ok := t.(float64); ok {
				events.ScrollTimestamps = append(events.ScrollTimestamps, int64(v))
			}
		}
	}

	// Extract summary metrics
	if v, ok := behav["mouseEvents"].(float64); ok {
		events.MouseEvents = int(v)
	}
	if v, ok := behav["scrollEvents"].(float64); ok {
		events.ScrollEvents = int(v)
	}
	if v, ok := behav["typingEvents"].(float64); ok {
		events.TypingEvents = int(v)
	}
	if v, ok := behav["mouseStdDev"].(float64); ok {
		events.MouseStdDev = v
	}
	if v, ok := behav["typingStdDev"].(float64); ok {
		events.TypingStdDev = v
	}
	if v, ok := behav["eventTimingStdDev"].(float64); ok {
		events.EventTimingStdDev = v
	}
	if v, ok := behav["mouseStraightness"].(float64); ok {
		events.MouseStraightness = v
	}
	if v, ok := behav["errorStack"].(string); ok {
		events.ErrorStack = v
	}

	return events
}
