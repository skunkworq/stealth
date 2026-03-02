package behavior

import (
	"encoding/json"
	"math"
	"math/rand"
	"sort"
	"time"
)

// EventData represents behavioral event data suitable for the X-Behavioral-Data header.
// This format is consumed by the shield's BehavioralAnalyzer for bot detection.
type EventData struct {
	MouseTimestamps  []int64                  `json:"mouseTimestamps"`
	TypingTimestamps []int64                  `json:"typingTimestamps"`
	MousePositions   []map[string]float64     `json:"mousePositions"`
	MouseVelocities  []float64                `json:"mouseVelocities"`
	ScrollTimestamps []int64                  `json:"scrollTimestamps"`
	ScrollDeltas     []float64                `json:"scrollDeltas"`
	ClickTimestamps  []int64                  `json:"clickTimestamps,omitempty"`
	ClickPositions   []map[string]float64     `json:"clickPositions,omitempty"`
}

// GeneratorConfig controls the behavioral data generation parameters.
type GeneratorConfig struct {
	// Mouse movement
	MouseEventsMin   int     // Minimum mouse events (default: 15)
	MouseEventsMax   int     // Maximum mouse events (default: 30)
	MouseSpeedMin    float64 // Min velocity px/s (default: 20)
	MouseSpeedMax    float64 // Max velocity px/s (default: 400)
	MicroTremorRatio float64 // Fraction of movements with micro-tremors (default: 0.2)

	// Typing
	TypingEventsMin  int     // Minimum typing events (default: 6)
	TypingEventsMax  int     // Maximum typing events (default: 15)
	TypingSpeedMin   float64 // Min inter-key interval ms (default: 50)
	TypingSpeedMax   float64 // Max inter-key interval ms (default: 250)

	// General
	SessionDurationMs int64 // Total session duration in ms (default: 3000)
}

// DefaultGeneratorConfig returns sensible defaults for human-like behavior.
func DefaultGeneratorConfig() *GeneratorConfig {
	return &GeneratorConfig{
		MouseEventsMin:    15,
		MouseEventsMax:    30,
		MouseSpeedMin:     20,
		MouseSpeedMax:     400,
		MicroTremorRatio:  0.3, // 30% of movements have micro-tremors (hand jitter)
		TypingEventsMin:   6,
		TypingEventsMax:   15,
		TypingSpeedMin:    50,
		TypingSpeedMax:    250,
		SessionDurationMs: 3000,
	}
}

// EventGenerator creates human-like behavioral event data.
type EventGenerator struct {
	config *GeneratorConfig
	rng    *rand.Rand
}

// NewEventGenerator creates a new EventGenerator.
func NewEventGenerator(config *GeneratorConfig) *EventGenerator {
	if config == nil {
		config = DefaultGeneratorConfig()
	}
	//nolint:gosec // G404: math/rand is intentional for non-cryptographic use
	return &EventGenerator{
		config: config,
		rng:    rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Generate creates a complete set of human-like behavioral events.
func (g *EventGenerator) Generate() *EventData {
	data := &EventData{}

	// Generate mouse movement path with Bezier curves and micro-tremors
	g.generateMousePath(data)

	// Generate typing timestamps interleaved with mouse activity
	g.generateTypingTimestamps(data)

	// Generate scroll events interleaved with mouse activity
	g.generateScrollEvents(data)

	// Generate click events at mouse positions
	g.generateClickEvents(data)

	return data
}

// ToJSON serializes EventData for the X-Behavioral-Data header.
func (g *EventGenerator) ToJSON(data *EventData) (string, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// generateMousePath creates a human-like mouse movement path as a single
// unified stream. Each event is either a "major" movement (advancing along a
// Bezier curve) or a "micro-tremor" (small jitter from the previous position).
// All timestamps are drawn from one wide distribution to ensure high Shannon
// entropy in the intervals — the shield flags entropy < 1.5 as bot-like.
func (g *EventGenerator) generateMousePath(data *EventData) {
	numEvents := g.config.MouseEventsMin + g.rng.Intn(g.config.MouseEventsMax-g.config.MouseEventsMin+1)

	// Multi-segment Bezier path setup: 2-3 segments with varying curvature
	// ensures path_efficiency_consistency CV > 0.15 (defeats Check 11).
	startX, startY := 100.0+g.rng.Float64()*400, 100.0+g.rng.Float64()*300
	endX, endY := startX+g.rng.Float64()*300-150, startY+g.rng.Float64()*200-100

	numSegments := 2 + g.rng.Intn(2) // 2 or 3 segments

	// Create waypoints (start, intermediates, end)
	waypoints := make([][2]float64, numSegments+1)
	waypoints[0] = [2]float64{startX, startY}
	waypoints[numSegments] = [2]float64{endX, endY}

	for wi := 1; wi < numSegments; wi++ {
		frac := float64(wi) / float64(numSegments)
		wx := startX + (endX-startX)*frac + (g.rng.Float64()*160 - 80)
		wy := startY + (endY-startY)*frac + (g.rng.Float64()*120 - 60)
		// Clamp to screen bounds (assume 1920x1080)
		wx = math.Max(0, math.Min(wx, 1920))
		wy = math.Max(0, math.Min(wy, 1080))
		waypoints[wi] = [2]float64{wx, wy}
	}

	// Per-segment control points with contrasting curvature scales.
	// Force min/max ratio > 2.5 for high CV in path efficiency.
	type bezierSegment struct {
		sx, sy, cx, cy, ex, ey float64
	}
	curvatureScales := make([]float64, numSegments)
	curvatureScales[0] = 0.2 + g.rng.Float64()*0.3 // Low: 0.2-0.5
	if numSegments >= 2 {
		curvatureScales[1] = 1.4 + g.rng.Float64()*0.4 // High: 1.4-1.8
	}
	if numSegments >= 3 {
		curvatureScales[2] = 0.6 + g.rng.Float64()*0.5 // Mid: 0.6-1.1
	}
	segments := make([]bezierSegment, numSegments)
	for si := 0; si < numSegments; si++ {
		sx, sy := waypoints[si][0], waypoints[si][1]
		ex, ey := waypoints[si+1][0], waypoints[si+1][1]
		cx := (sx+ex)/2 + (g.rng.Float64()*200-100)*curvatureScales[si]
		cy := (sy+ey)/2 + (g.rng.Float64()*200-100)*curvatureScales[si]
		segments[si] = bezierSegment{sx, sy, cx, cy, ex, ey}
	}

	positions := make([]map[string]float64, 0, numEvents)
	timestamps := make([]int64, 0, numEvents)
	velocities := make([]float64, 0, numEvents)

	// Preferred tremor direction (simulates wrist anatomy bias).
	// Real hand tremor clusters around a dominant angle due to arm mechanics.
	// Using wrapped normal distribution gives Rayleigh R ≈ 0.49 (well above 0.15 threshold).
	preferredAngle := g.rng.Float64() * 2 * math.Pi

	var prevX, prevY float64
	var ts int64

	// Pre-decide which events are micro-tremors vs major moves.
	majorCount := 0
	isMajor := make([]bool, numEvents)
	for i := 0; i < numEvents; i++ {
		if i == 0 || g.rng.Float64() >= g.config.MicroTremorRatio {
			isMajor[i] = true
			majorCount++
		}
	}
	if majorCount < 2 {
		isMajor[0] = true
		isMajor[numEvents-1] = true
		majorCount = 2
	}

	// Pre-assign interval modes to guarantee diversity across all 4 modes.
	// This ensures high Shannon entropy (>1.5) even with small event counts.
	forcedModes := make([]int, numEvents-1) // one less than events (first event has no interval)
	// Assign one of each mode first
	for m := 0; m < 4 && m < len(forcedModes); m++ {
		forcedModes[m] = m
	}
	// Fill remaining slots randomly with weighted distribution
	for m := 4; m < len(forcedModes); m++ {
		r := g.rng.Float64()
		switch {
		case r < 0.25:
			forcedModes[m] = 0
		case r < 0.55:
			forcedModes[m] = 1
		case r < 0.80:
			forcedModes[m] = 2
		default:
			forcedModes[m] = 3
		}
	}
	// Shuffle to avoid deterministic ordering of forced modes
	g.rng.Shuffle(len(forcedModes), func(i, j int) {
		forcedModes[i], forcedModes[j] = forcedModes[j], forcedModes[i]
	})

	majorIdx := 0
	for i := 0; i < numEvents; i++ {
		var x, y float64

		if isMajor[i] {
			// Determine which segment this major move belongs to
			globalT := float64(majorIdx) / float64(majorCount-1) // 0..1 across full path
			segFloat := globalT * float64(numSegments)
			segIdx := int(segFloat)
			if segIdx >= numSegments {
				segIdx = numSegments - 1
			}
			localT := segFloat - float64(segIdx) // 0..1 within segment

			seg := segments[segIdx]
			x = (1-localT)*(1-localT)*seg.sx + 2*(1-localT)*localT*seg.cx + localT*localT*seg.ex
			y = (1-localT)*(1-localT)*seg.sy + 2*(1-localT)*localT*seg.cy + localT*localT*seg.ey

			// Add general movement noise
			jitter := math.Max(0.3, (1-globalT)*2)
			x += (g.rng.Float64()*2 - 1) * jitter
			y += (g.rng.Float64()*2 - 1) * jitter
			majorIdx++
		} else {
			// Micro-tremor: radial jitter from previous position (0.5-3.0 px)
			// Uses directionally biased angles (wrapped normal around preferred direction)
			// to mimic real wrist anatomy. Rayleigh R ≈ 0.49 with σ=1.2.
			angle := preferredAngle + g.rng.NormFloat64()*1.2
			radius := 0.5 + g.rng.Float64()*2.5
			x = prevX + radius*math.Cos(angle)
			y = prevY + radius*math.Sin(angle)
		}

		// Generate timestamp with a multi-modal mixture for high entropy.
		// Human mouse events span 5-300ms: quick corrections, steady tracking,
		// hover pauses, and reading pauses. We sample from distinct modes and
		// pre-assign slots to guarantee mode diversity (shield requires H > 1.5).
		if i == 0 {
			ts = time.Now().UnixMilli()
		} else {
			var baseInterval float64
			mode := forcedModes[i-1]
			switch mode {
			case 0:
				// Fast movement (corrections, tracking) — 5-20ms
				baseInterval = 5 + g.rng.Float64()*15
			case 1:
				// Normal movement — 20-60ms
				baseInterval = 20 + g.rng.Float64()*40
			case 2:
				// Deliberate/slow movement — 60-150ms
				baseInterval = 60 + g.rng.Float64()*90
			default:
				// Pause (hover, read, think) — 150-400ms
				baseInterval = 150 + g.rng.Float64()*250
			}
			ts += int64(baseInterval)
		}

		// Clamp to non-negative (screen bounds) to avoid mouse_outside_viewport
		x = math.Max(0, x)
		y = math.Max(0, y)
		x = math.Round(x*100) / 100
		y = math.Round(y*100) / 100

		positions = append(positions, map[string]float64{"x": x, "y": y})
		timestamps = append(timestamps, ts)

		// Calculate velocity
		if i > 0 {
			dx := x - prevX
			dy := y - prevY
			prevTs := timestamps[i-1]
			dt := float64(ts-prevTs) / 1000.0
			if dt > 0 {
				dist := math.Sqrt(dx*dx + dy*dy)
				v := dist / dt
				// Soft clamp — floor uses exponential distribution to avoid
				// density clustering in any narrow band.
				// Floor: prevent impossible_velocity_low (shield threshold: 5.0)
				if v < 5.0 {
					v = 5.0 + g.rng.ExpFloat64()*80 // Exponential from 5.0, mean ~85
				}
				// Ceiling: prevent impossible_velocity_high (shield threshold: 3000)
				if v > 2500 {
					v = 2500 + g.rng.Float64()*400 // 2500-2900 px/s (fast flick band)
				}
				velocities = append(velocities, math.Round(v*10)/10)
			}
		}

		prevX, prevY = x, y
	}

	data.MousePositions = positions
	data.MouseTimestamps = timestamps
	data.MouseVelocities = velocities
}

// generateTypingTimestamps creates human-like keystroke timing patterns.
// Human typing has variable inter-key intervals with occasional pauses
// for thinking, and faster bursts for common words. The coefficient of
// variation should be well above 0.15 to avoid the shield's uniformity check.
func (g *EventGenerator) generateTypingTimestamps(data *EventData) {
	numKeys := g.config.TypingEventsMin + g.rng.Intn(g.config.TypingEventsMax-g.config.TypingEventsMin+1)

	timestamps := make([]int64, 0, numKeys)
	var ts int64

	for i := 0; i < numKeys; i++ {
		if i == 0 {
			if len(data.MouseTimestamps) > 2 {
				// Start typing during mouse activity (30-60% through the mouse timeline).
				// Real users type while moving the mouse — event types interleave.
				startFrac := 0.3 + g.rng.Float64()*0.3
				startIdx := int(float64(len(data.MouseTimestamps)) * startFrac)
				if startIdx >= len(data.MouseTimestamps) {
					startIdx = len(data.MouseTimestamps) - 1
				}
				ts = data.MouseTimestamps[startIdx] + int64(g.rng.Intn(100))
			} else if len(data.MouseTimestamps) > 0 {
				ts = data.MouseTimestamps[len(data.MouseTimestamps)-1] + 500 + int64(g.rng.Intn(2000))
			} else {
				ts = time.Now().UnixMilli()
			}
		} else {
			// Log-normal distribution for natural typing rhythm
			// Use exp(normal) to ensure high variance — human typing is naturally bursty
			logMean := math.Log(g.config.TypingSpeedMin + (g.config.TypingSpeedMax-g.config.TypingSpeedMin)*0.4)
			logStd := 0.5 // This produces CV well above 0.15
			interval := math.Exp(logMean + g.rng.NormFloat64()*logStd)

			// Occasional longer pauses (thinking, word boundaries) — ~20% of keystrokes
			if g.rng.Float64() < 0.2 {
				interval += 100 + g.rng.Float64()*400 // 100-500ms extra pause
			}

			// Occasional fast bursts (common letter combos) — ~15% of keystrokes
			if g.rng.Float64() < 0.15 {
				interval = g.config.TypingSpeedMin * (0.5 + g.rng.Float64()*0.3)
			}

			// Clamp to reasonable range
			interval = math.Max(25, math.Min(interval, 1200))
			ts += int64(interval)
		}
		timestamps = append(timestamps, ts)
	}

	data.TypingTimestamps = timestamps
}

// generateScrollEvents creates human-like scroll events with bimodal timing
// and irregular delta patterns. Real users alternate between fast inertial
// scrolling (<100ms) and reading pauses (>600ms), producing high CV (>0.60).
// Scroll deltas vary irregularly — users speed up, slow down, and re-accelerate
// rather than following a smooth deceleration curve.
func (g *EventGenerator) generateScrollEvents(data *EventData) {
	numScrolls := 3 + g.rng.Intn(8) // 3-10 events

	timestamps := make([]int64, 0, numScrolls)
	deltas := make([]float64, 0, numScrolls)

	// Start scrolls during mouse activity (20-50% through the mouse timeline).
	var ts int64
	if len(data.MouseTimestamps) > 2 {
		startFrac := 0.2 + g.rng.Float64()*0.3
		startIdx := int(float64(len(data.MouseTimestamps)) * startFrac)
		if startIdx >= len(data.MouseTimestamps) {
			startIdx = len(data.MouseTimestamps) - 1
		}
		ts = data.MouseTimestamps[startIdx] + int64(g.rng.Intn(50))
	} else if len(data.MouseTimestamps) > 0 {
		ts = data.MouseTimestamps[len(data.MouseTimestamps)-1] + 200 + int64(g.rng.Intn(300))
	} else {
		ts = time.Now().UnixMilli() + 500 + int64(g.rng.Intn(1000))
	}

	for i := 0; i < numScrolls; i++ {
		timestamps = append(timestamps, ts)

		// Irregular scroll deltas: alternate between fast flicks (200-400px),
		// gentle scrolls (40-120px), and moderate scrolls (120-250px).
		// This produces ratio stddev > 0.15 (defeats Check 19).
		var delta float64
		r := g.rng.Float64()
		switch {
		case r < 0.30:
			// Fast flick — large delta
			delta = 200 + g.rng.Float64()*200
		case r < 0.55:
			// Gentle scroll — small delta
			delta = 40 + g.rng.Float64()*80
		default:
			// Moderate scroll
			delta = 120 + g.rng.Float64()*130
		}
		// Add noise ±20%
		delta *= (0.80 + g.rng.Float64()*0.40)
		delta = math.Round(delta*10) / 10
		deltas = append(deltas, delta)

		// Bimodal scroll intervals (defeats Check 18: CV > 0.50).
		// Real scrolling: fast inertial bursts followed by reading pauses.
		var interval int
		if g.rng.Float64() < 0.40 {
			// Reading pause: 500-1500ms
			interval = 500 + g.rng.Intn(1001)
		} else {
			// Fast inertial scroll: 30-120ms
			interval = 30 + g.rng.Intn(91)
		}
		ts += int64(interval)
	}

	data.ScrollTimestamps = timestamps
	data.ScrollDeltas = deltas
}

// generateClickEvents creates click events near mouse positions.
// Real browsers fire click events 1-5ms after the nearest mousemove, not at the
// exact same timestamp. Click positions have varied offsets — some precise (2-5px),
// some approximate (5-15px), mimicking real targeting imprecision.
func (g *EventGenerator) generateClickEvents(data *EventData) {
	if len(data.MouseTimestamps) < 3 {
		return
	}

	numClicks := 2 + g.rng.Intn(5) // 2-6 clicks
	if numClicks > len(data.MouseTimestamps)/2 {
		numClicks = len(data.MouseTimestamps) / 2
	}
	if numClicks < 2 {
		numClicks = 2
	}

	// Pick random mouse event indices for clicks
	indices := make([]int, 0, numClicks)
	used := make(map[int]bool)
	for len(indices) < numClicks {
		idx := g.rng.Intn(len(data.MouseTimestamps))
		if !used[idx] {
			used[idx] = true
			indices = append(indices, idx)
		}
	}
	sort.Ints(indices)

	clickTimestamps := make([]int64, 0, numClicks)
	clickPositions := make([]map[string]float64, 0, numClicks)

	for _, idx := range indices {
		// Add 1-5ms offset from the mouse timestamp (defeats Check 16).
		// Real browsers have event dispatch delay between mousemove and click.
		offset := int64(1 + g.rng.Intn(5))
		clickTimestamps = append(clickTimestamps, data.MouseTimestamps[idx]+offset)

		pos := data.MousePositions[idx]
		// Varied click offset distribution (defeats Check 17):
		// - 30% precise clicks: 2-5px offset (user clicking carefully)
		// - 40% moderate clicks: 5-12px offset (normal targeting)
		// - 30% approximate clicks: 8-18px offset (hasty clicks / misclicks)
		var jitterRadius float64
		r := g.rng.Float64()
		switch {
		case r < 0.30:
			jitterRadius = 2.0 + g.rng.Float64()*3.0 // 2-5px
		case r < 0.70:
			jitterRadius = 5.0 + g.rng.Float64()*7.0 // 5-12px
		default:
			jitterRadius = 8.0 + g.rng.Float64()*10.0 // 8-18px
		}
		angle := g.rng.Float64() * 2 * math.Pi

		clickPositions = append(clickPositions, map[string]float64{
			"x": math.Round((pos["x"]+jitterRadius*math.Cos(angle))*100) / 100,
			"y": math.Round((pos["y"]+jitterRadius*math.Sin(angle))*100) / 100,
		})
	}

	data.ClickTimestamps = clickTimestamps
	data.ClickPositions = clickPositions
}

func sign(x float64) float64 {
	if x >= 0 {
		return 1
	}
	return -1
}
