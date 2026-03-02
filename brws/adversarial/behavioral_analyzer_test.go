package adversarial

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
			{0, 0}, {10, 10}, {20, 20}, {30, 30}, {40, 40},
			{50, 50}, {60, 60}, {70, 70}, {80, 80}, {90, 90},
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
			{0, 0}, {15, 30}, {40, 55}, {70, 45}, {90, 20},
			{120, 50}, {140, 90}, {170, 70}, {200, 40}, {230, 80},
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

func TestIntervalEntropy(t *testing.T) {
	ba := NewBehavioralAnalyzer(nil)

	// All identical timestamps → zero entropy
	entropy := ba.calculateIntervalEntropy([]int64{100, 200, 300, 400})
	if entropy != 0 {
		t.Errorf("identical intervals should have zero entropy, got %.4f", entropy)
	}

	// Varied timestamps → positive entropy
	entropy = ba.calculateIntervalEntropy([]int64{100, 150, 400, 420, 800, 850, 1200, 1800})
	if entropy <= 0 {
		t.Errorf("varied intervals should have positive entropy, got %.4f", entropy)
	}
}
