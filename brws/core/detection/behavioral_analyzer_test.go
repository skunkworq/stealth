package detection

import (
	"testing"
)

func TestBehavioralAnalyzer_UniformIntervals(t *testing.T) {
	ba := NewBehavioralAnalyzer(nil)

	// Bot-like: perfectly uniform 100ms intervals
	events := &EnhancedBehavioralEvents{
		MouseTimestamps: []int64{0, 100, 200, 300, 400, 500, 600, 700, 800, 900},
	}

	result := ba.Analyze(events)
	if !result.Detected {
		t.Error("expected uniform intervals to be detected as bot-like")
	}
	if result.Score < 0.3 {
		t.Errorf("expected score > 0.3 for uniform intervals, got %.4f", result.Score)
	}

	found := false
	for _, ind := range result.Indicators {
		if ind.Check == "interval_entropy_low" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'interval_entropy_low' indicator")
	}
}

func TestBehavioralAnalyzer_NaturalIntervals(t *testing.T) {
	ba := NewBehavioralAnalyzer(nil)

	// Human-like: variable intervals
	events := &EnhancedBehavioralEvents{
		MouseTimestamps: []int64{0, 45, 120, 180, 350, 400, 520, 680, 710, 900, 1050, 1200, 1380, 1500, 1620, 1800, 1950, 2100, 2350, 2500},
	}

	result := ba.Analyze(events)
	// Natural intervals should have higher entropy and not trigger the low-entropy check
	for _, ind := range result.Indicators {
		if ind.Check == "interval_entropy_low" {
			t.Errorf("natural intervals should not trigger low entropy check, got entropy=%s", ind.Value)
		}
	}
}

func TestBehavioralAnalyzer_StraightLineMovement(t *testing.T) {
	ba := NewBehavioralAnalyzer(nil)

	// Bot-like: perfectly straight line
	events := &EnhancedBehavioralEvents{
		MousePositions: []Position{
			{0, 0},
			{10, 10},
			{20, 20},
			{30, 30},
			{40, 40},
			{50, 50},
			{60, 60},
			{70, 70},
			{80, 80},
			{90, 90},
		},
	}

	result := ba.Analyze(events)

	found := false
	for _, ind := range result.Indicators {
		if ind.Check == "zero_curvature_variance" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'zero_curvature_variance' indicator for straight-line movement")
	}
}

func TestBehavioralAnalyzer_NaturalCurvedMovement(t *testing.T) {
	ba := NewBehavioralAnalyzer(nil)

	// Human-like: curved path with significant variation (Bezier-like)
	events := &EnhancedBehavioralEvents{
		MousePositions: []Position{
			{0, 0},
			{15, 30},
			{40, 55},
			{70, 45},
			{90, 20},
			{120, 50},
			{140, 90},
			{170, 70},
			{200, 40},
			{230, 80},
		},
	}

	result := ba.Analyze(events)

	for _, ind := range result.Indicators {
		if ind.Check == "zero_curvature_variance" {
			t.Error("curved natural movement should not trigger zero curvature variance")
		}
	}
}

func TestBehavioralAnalyzer_ImpossibleVelocity(t *testing.T) {
	ba := NewBehavioralAnalyzer(nil)

	// Bot-like: impossibly high velocity
	events := &EnhancedBehavioralEvents{
		MouseVelocities: []float64{500.0, 800.0, 3500.0, 600.0},
	}

	result := ba.Analyze(events)

	found := false
	for _, ind := range result.Indicators {
		if ind.Check == "impossible_velocity_high" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'impossible_velocity_high' indicator for v > 3000 px/s")
	}
}

func TestBehavioralAnalyzer_MicroTremors(t *testing.T) {
	ba := NewBehavioralAnalyzer(nil)

	// Bot-like: no micro-tremors, all large moves
	positions := make([]Position, 20)
	for i := range positions {
		positions[i] = Position{X: float64(i * 50), Y: float64(i * 50)}
	}

	events := &EnhancedBehavioralEvents{
		MousePositions: positions,
	}

	result := ba.Analyze(events)

	found := false
	for _, ind := range result.Indicators {
		if ind.Check == "no_micro_tremors" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'no_micro_tremors' indicator for large uniform movements")
	}
}

func TestBehavioralAnalyzer_UniformKeystroke(t *testing.T) {
	ba := NewBehavioralAnalyzer(nil)

	// Bot-like: perfectly uniform keystroke intervals (exactly 100ms apart)
	events := &EnhancedBehavioralEvents{
		TypingTimestamps: []int64{0, 100, 200, 300, 400, 500, 600, 700},
	}

	result := ba.Analyze(events)

	found := false
	for _, ind := range result.Indicators {
		if ind.Check == "uniform_keystroke_intervals" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'uniform_keystroke_intervals' indicator for mechanical typing")
	}
}

func TestBehavioralAnalyzer_NilEvents(t *testing.T) {
	ba := NewBehavioralAnalyzer(nil)

	result := ba.Analyze(nil)
	if result.Detected {
		t.Error("nil events should not be detected")
	}
	if result.Score != 0 {
		t.Errorf("nil events should have score 0, got %.4f", result.Score)
	}
}

// --- Phase 10 Shield Tests ---

func TestBehavioralAnalyzer_KeystrokeHoldTimeCV_Uniform(t *testing.T) {
	ba := NewBehavioralAnalyzer(nil)

	// Bot-like: all keys held for exactly 100ms (CV ≈ 0)
	events := &EnhancedBehavioralEvents{
		KeystrokeHoldTimes: []float64{100, 100, 100, 100, 100, 100, 100, 100},
	}

	result := ba.Analyze(events)

	found := false
	for _, ind := range result.Indicators {
		if ind.Check == "keystroke_hold_time_cv" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'keystroke_hold_time_cv' indicator for uniform hold times")
	}
}

func TestBehavioralAnalyzer_KeystrokeHoldTimeCV_Natural(t *testing.T) {
	ba := NewBehavioralAnalyzer(nil)

	// Human-like: varied hold times (taps, moderate, long holds)
	events := &EnhancedBehavioralEvents{
		KeystrokeHoldTimes: []float64{65, 90, 180, 70, 110, 250, 85, 130},
	}

	result := ba.Analyze(events)

	for _, ind := range result.Indicators {
		if ind.Check == "keystroke_hold_time_cv" {
			t.Errorf("natural hold times should not trigger hold time CV check, got CV=%s", ind.Value)
		}
	}
}

func TestBehavioralAnalyzer_DigraphTiming_Uniform(t *testing.T) {
	ba := NewBehavioralAnalyzer(nil)

	// Bot-like: perfectly uniform typing intervals (no digraph variation)
	events := &EnhancedBehavioralEvents{
		TypingTimestamps: []int64{0, 100, 200, 300, 400, 500, 600, 700, 800},
	}

	result := ba.Analyze(events)

	found := false
	for _, ind := range result.Indicators {
		if ind.Check == "digraph_timing_anomaly" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'digraph_timing_anomaly' indicator for uniform intervals")
	}
}

func TestBehavioralAnalyzer_DigraphTiming_Natural(t *testing.T) {
	ba := NewBehavioralAnalyzer(nil)

	// Human-like: varied typing intervals with digraph effects
	events := &EnhancedBehavioralEvents{
		TypingTimestamps: []int64{0, 65, 180, 220, 420, 510, 700, 850, 1200},
	}

	result := ba.Analyze(events)

	for _, ind := range result.Indicators {
		if ind.Check == "digraph_timing_anomaly" {
			t.Errorf("natural typing should not trigger digraph anomaly check, got CV=%s", ind.Value)
		}
	}
}

func TestBehavioralAnalyzer_ScrollDirectionMonotonic(t *testing.T) {
	ba := NewBehavioralAnalyzer(nil)

	// Bot-like: all scrolls in same direction (100% down)
	events := &EnhancedBehavioralEvents{
		ScrollDirections: []float64{100, 200, 150, 180, 120, 160},
	}

	result := ba.Analyze(events)

	found := false
	for _, ind := range result.Indicators {
		if ind.Check == "scroll_direction_monotonic" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'scroll_direction_monotonic' indicator for all-down scrolls")
	}
}

func TestBehavioralAnalyzer_ScrollDirectionAlternating(t *testing.T) {
	ba := NewBehavioralAnalyzer(nil)

	// Bot-like: perfect up-down alternation
	events := &EnhancedBehavioralEvents{
		ScrollDirections: []float64{100, -100, 100, -100, 100, -100},
	}

	result := ba.Analyze(events)

	found := false
	for _, ind := range result.Indicators {
		if ind.Check == "scroll_direction_alternating" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'scroll_direction_alternating' indicator for perfect alternation")
	}
}

func TestBehavioralAnalyzer_ScrollDirectionNatural(t *testing.T) {
	ba := NewBehavioralAnalyzer(nil)

	// Human-like: mostly down, occasional up-scrolls clustered together
	events := &EnhancedBehavioralEvents{
		ScrollDirections: []float64{200, 150, 180, -80, -60, 120, 200, 150},
	}

	result := ba.Analyze(events)

	for _, ind := range result.Indicators {
		if ind.Check == "scroll_direction_monotonic" || ind.Check == "scroll_direction_alternating" {
			t.Errorf("natural scroll directions should not trigger %s", ind.Check)
		}
	}
}

func TestBehavioralAnalyzer_ScrollAbruptDirectionChange(t *testing.T) {
	ba := NewBehavioralAnalyzer(nil)

	// Bot-like: direction changes at full velocity (no deceleration)
	events := &EnhancedBehavioralEvents{
		ScrollDirections: []float64{300, -250, 280, -200, 260, -230},
		ScrollDeltas:     []float64{300, 250, 280, 200, 260, 230},
	}

	result := ba.Analyze(events)

	found := false
	for _, ind := range result.Indicators {
		if ind.Check == "scroll_direction_change_abrupt" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'scroll_direction_change_abrupt' indicator for high-velocity direction changes")
	}
}

func TestBehavioralAnalyzer_VelocityLag2Anomaly(t *testing.T) {
	ba := NewBehavioralAnalyzer(nil)

	// Bot-like: i.i.d. random velocities with no temporal structure (lag-2 ≈ 0)
	events := &EnhancedBehavioralEvents{
		MouseVelocities: []float64{300, 50, 450, 20, 280, 100, 350, 60, 400},
	}

	result := ba.Analyze(events)

	found := false
	for _, ind := range result.Indicators {
		if ind.Check == "mouse_velocity_lag2_anomaly" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'mouse_velocity_lag2_anomaly' for random velocity sequence")
	}
}

func TestBehavioralAnalyzer_VelocityLag_HumanLike(t *testing.T) {
	ba := NewBehavioralAnalyzer(nil)

	// Human-like: gradual rise then gentle decline (asymmetric arc)
	// Asymmetry ensures positive lag-3 autocorrelation unlike symmetric arcs.
	events := &EnhancedBehavioralEvents{
		MouseVelocities: []float64{40, 60, 90, 130, 175, 230, 270, 250, 230, 200, 180, 170},
	}

	result := ba.Analyze(events)

	for _, ind := range result.Indicators {
		if ind.Check == "mouse_velocity_lag2_anomaly" || ind.Check == "mouse_velocity_lag3_anomaly" {
			t.Errorf("smooth velocity curve should not trigger %s, value=%s", ind.Check, ind.Value)
		}
	}
}

func TestBehavioralAnalyzer_FittsLawViolation(t *testing.T) {
	ba := NewBehavioralAnalyzer(nil)

	// Bot-like: click timing has no correlation with distance (random times)
	events := &EnhancedBehavioralEvents{
		ClickTimestamps: []int64{0, 500, 1000, 1500},
		ClickPositions: []Position{
			{100, 100}, // → 50px to next
			{150, 100}, // → 300px to next
			{450, 100}, // → 80px to next
			{530, 100},
		},
		// Uniform intervals (500ms each) regardless of distance = violates Fitts'
	}

	result := ba.Analyze(events)

	found := false
	for _, ind := range result.Indicators {
		if ind.Check == "fitts_law_violation" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'fitts_law_violation' for distance-independent click timing")
	}
}

func TestIntervalEntropy(t *testing.T) {
	ba := NewBehavioralAnalyzer(nil)

	// All identical timestamps → zero entropy
	entropy := ba.CalculateIntervalEntropy([]int64{100, 200, 300, 400})
	if entropy != 0 {
		t.Errorf("identical intervals should have zero entropy, got %.4f", entropy)
	}

	// Varied timestamps → positive entropy
	entropy = ba.CalculateIntervalEntropy([]int64{100, 150, 400, 420, 800, 850, 1200, 1800})
	if entropy <= 0 {
		t.Errorf("varied intervals should have positive entropy, got %.4f", entropy)
	}
}
