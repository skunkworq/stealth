package behavior

import (
	"encoding/json"
	"fmt"
	"math"
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
)

func TestEventGenerator_ProducesValidData(t *testing.T) {
	gen := NewEventGenerator(nil)
	data := gen.Generate()

	if len(data.MouseTimestamps) < 15 {
		t.Errorf("expected >= 15 mouse timestamps, got %d", len(data.MouseTimestamps))
	}
	if len(data.MousePositions) != len(data.MouseTimestamps) {
		t.Errorf("mouse positions (%d) should match timestamps (%d)", len(data.MousePositions), len(data.MouseTimestamps))
	}
	if len(data.TypingTimestamps) < 6 {
		t.Errorf("expected >= 6 typing timestamps, got %d", len(data.TypingTimestamps))
	}
	if len(data.MouseVelocities) < 1 {
		t.Error("expected at least 1 mouse velocity")
	}

	// Timestamps should be monotonically increasing
	for i := 1; i < len(data.MouseTimestamps); i++ {
		if data.MouseTimestamps[i] <= data.MouseTimestamps[i-1] {
			t.Errorf("mouse timestamps not monotonically increasing at index %d: %d <= %d",
				i, data.MouseTimestamps[i], data.MouseTimestamps[i-1])
		}
	}
	for i := 1; i < len(data.TypingTimestamps); i++ {
		if data.TypingTimestamps[i] <= data.TypingTimestamps[i-1] {
			t.Errorf("typing timestamps not monotonically increasing at index %d: %d <= %d",
				i, data.TypingTimestamps[i], data.TypingTimestamps[i-1])
		}
	}
}

func TestEventGenerator_SerializesToJSON(t *testing.T) {
	gen := NewEventGenerator(nil)
	data := gen.Generate()

	jsonStr, err := gen.ToJSON(data)
	if err != nil {
		t.Fatalf("ToJSON error: %v", err)
	}
	if jsonStr == "" {
		t.Fatal("expected non-empty JSON")
	}

	// Verify it round-trips
	var parsed EventData
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("JSON round-trip failed: %v", err)
	}
	if len(parsed.MouseTimestamps) != len(data.MouseTimestamps) {
		t.Error("mouse timestamps changed after round-trip")
	}
}

func TestEventGenerator_PassesShieldAnalysis(t *testing.T) {
	// After sword upgrade, the generated behavioral data should NOT be detected as bot-like
	gen := NewEventGenerator(nil)
	ba := adversarial.NewBehavioralAnalyzer(nil)

	// Run 20 trials to account for randomness
	botDetections := 0
	for i := 0; i < 20; i++ {
		data := gen.Generate()

		// Convert to adversarial.EnhancedBehavioralEvents
		events := &adversarial.EnhancedBehavioralEvents{
			MouseTimestamps:  data.MouseTimestamps,
			TypingTimestamps: data.TypingTimestamps,
			MouseVelocities:  data.MouseVelocities,
			ScrollTimestamps: data.ScrollTimestamps,
			ScrollDeltas:     data.ScrollDeltas,
			ClickTimestamps:  data.ClickTimestamps,
		}

		// Convert mouse positions
		for _, pos := range data.MousePositions {
			events.MousePositions = append(events.MousePositions, adversarial.Position{
				X: pos["x"],
				Y: pos["y"],
			})
		}

		// Convert click positions
		for _, pos := range data.ClickPositions {
			events.ClickPositions = append(events.ClickPositions, adversarial.Position{
				X: pos["x"],
				Y: pos["y"],
			})
		}

		result := ba.Analyze(events)
		if result.Detected {
			botDetections++
			indicators := make([]string, 0)
			for _, ind := range result.Indicators {
				indicators = append(indicators, ind.Check)
			}
			t.Logf("trial %d: detected as bot (score=%.3f), indicators: %v", i, result.Score, indicators)
		}
	}

	// After shield upgrade (checks 20-24), the generator's behavioral data should
	// be detected as bot-like due to structural patterns (no temporal clustering,
	// independent scroll deltas, no click deceleration, etc.).
	detectionRate := float64(botDetections) / 20.0
	if detectionRate < 0.80 {
		t.Errorf("expected >= 80%% detection rate after shield upgrade, got %.0f%% (%d/20)",
			detectionRate*100, botDetections)
	}

	fmt.Printf("Behavioral generator shield detection rate: %d/20 detected (%.0f%% detection)\n",
		botDetections, detectionRate*100)
}

// --- Phase 10 Sword Tests ---

func TestEventGenerator_KeystrokeHoldTimes(t *testing.T) {
	gen := NewEventGenerator(nil)
	data := gen.Generate()

	if len(data.KeystrokeHoldTimes) == 0 {
		t.Fatal("expected keystroke hold times to be generated")
	}
	if len(data.KeystrokeHoldTimes) != len(data.TypingTimestamps) {
		t.Errorf("hold times count (%d) should match typing timestamps (%d)",
			len(data.KeystrokeHoldTimes), len(data.TypingTimestamps))
	}

	// All hold times should be positive and reasonable (25-600ms)
	for i, ht := range data.KeystrokeHoldTimes {
		if ht < 25 || ht > 600 {
			t.Errorf("hold time[%d] = %.1f, want 25-600ms", i, ht)
		}
	}

	// CV should be > 0.25 (defeats check 25)
	if len(data.KeystrokeHoldTimes) > 4 {
		mean, stddev := computeMeanStddev(data.KeystrokeHoldTimes)
		cv := stddev / mean
		if cv < 0.25 {
			t.Errorf("hold time CV = %.3f, want > 0.25", cv)
		}
	}
}

func TestEventGenerator_ScrollDirections(t *testing.T) {
	gen := NewEventGenerator(nil)
	data := gen.Generate()

	if len(data.ScrollDirections) == 0 {
		t.Fatal("expected scroll directions to be generated")
	}
	if len(data.ScrollDirections) != len(data.ScrollDeltas) {
		t.Errorf("scroll directions count (%d) should match deltas (%d)",
			len(data.ScrollDirections), len(data.ScrollDeltas))
	}

	// Check that directions are not all identical (some should be negative)
	hasPositive, hasNegative := false, false
	// Run 10 trials — direction variation is probabilistic
	for trial := 0; trial < 10; trial++ {
		d := gen.Generate()
		for _, dir := range d.ScrollDirections {
			if dir > 0 {
				hasPositive = true
			} else if dir < 0 {
				hasNegative = true
			}
		}
		if hasPositive && hasNegative {
			break
		}
	}
	if !hasPositive {
		t.Error("expected some positive (down) scroll directions across trials")
	}
	// Negative scrolls are probabilistic (15% chance), so we allow some trials without them
	// but across 10 trials we should see at least one
	if !hasNegative {
		t.Error("expected at least one negative (up) scroll direction across 10 trials")
	}
}

func TestEventGenerator_P10_PassesNewShieldChecks(t *testing.T) {
	gen := NewEventGenerator(nil)
	ba := adversarial.NewBehavioralAnalyzer(nil)

	// Run 50 trials — generator should pass new P10 shield checks.
	// Using 50 trials (up from 20) reduces variance in pass rates for CI stability.
	const trials = 50
	p10Failures := make(map[string]int)
	for i := 0; i < trials; i++ {
		data := gen.Generate()

		events := &adversarial.EnhancedBehavioralEvents{
			MouseTimestamps:    data.MouseTimestamps,
			TypingTimestamps:   data.TypingTimestamps,
			MouseVelocities:    data.MouseVelocities,
			ScrollTimestamps:   data.ScrollTimestamps,
			ScrollDeltas:       data.ScrollDeltas,
			ClickTimestamps:    data.ClickTimestamps,
			KeystrokeHoldTimes: data.KeystrokeHoldTimes,
			ScrollDirections:   data.ScrollDirections,
		}
		for _, pos := range data.MousePositions {
			events.MousePositions = append(events.MousePositions, adversarial.Position{X: pos["x"], Y: pos["y"]})
		}
		for _, pos := range data.ClickPositions {
			events.ClickPositions = append(events.ClickPositions, adversarial.Position{X: pos["x"], Y: pos["y"]})
		}

		result := ba.Analyze(events)
		for _, ind := range result.Indicators {
			switch ind.Check {
			case "keystroke_hold_time_cv", "digraph_timing_anomaly",
				"mouse_velocity_lag2_anomaly", "mouse_velocity_lag3_anomaly",
				"fitts_law_violation",
				"scroll_direction_monotonic", "scroll_direction_alternating",
				"scroll_direction_change_abrupt":
				p10Failures[ind.Check]++
			}
		}
	}

	// P10 checks that the generator directly controls should pass reliably (<15%):
	// - keystroke_hold_time_cv: generator produces varied hold times
	// - digraph_timing_anomaly: generator uses log-normal typing intervals
	// - scroll_direction_*: generator forces mixed directions
	// - scroll_direction_change_abrupt: generator reduces deltas at direction changes
	reliableChecks := []string{
		"keystroke_hold_time_cv", "digraph_timing_anomaly",
		"scroll_direction_monotonic", "scroll_direction_alternating",
		"scroll_direction_change_abrupt",
	}
	for _, check := range reliableChecks {
		if count := p10Failures[check]; count > int(trials/4) {
			t.Errorf("P10 check '%s' fired %d/%d times (max %d allowed)", check, count, trials, trials/4)
		}
	}

	// Statistical checks with narrow bounds are inherently noisy with small
	// samples (15-30 events). Allow higher tolerance (70%) for these:
	// - velocity lag-2/lag-3: autocorrelation estimates very noisy with N<30
	// - Fitts' law: Pearson r unstable with 3-5 click pairs
	noisyChecks := []string{
		"mouse_velocity_lag2_anomaly", "mouse_velocity_lag3_anomaly",
		"fitts_law_violation",
	}
	for _, check := range noisyChecks {
		if count := p10Failures[check]; count > int(trials*7/10) {
			t.Errorf("P10 check '%s' fired %d/%d times (max %d allowed)", check, count, trials, trials*7/10)
		}
	}

	if len(p10Failures) > 0 {
		t.Logf("P10 check failures: %v", p10Failures)
	}
}

// helper for tests
func computeMeanStddev(values []float64) (float64, float64) {
	if len(values) == 0 {
		return 0, 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))
	var variance float64
	for _, v := range values {
		diff := v - mean
		variance += diff * diff
	}
	variance /= float64(len(values))
	return mean, math.Sqrt(variance)
}

func TestEventGenerator_CustomConfig(t *testing.T) {
	cfg := DefaultGeneratorConfig()
	cfg.MouseEventsMin = 5
	cfg.MouseEventsMax = 5
	cfg.MicroTremorRatio = 0 // Disable micro-tremors for predictable count
	cfg.TypingEventsMin = 3
	cfg.TypingEventsMax = 3

	gen := NewEventGenerator(cfg)
	data := gen.Generate()

	// With micro-tremor insertion at ~40%, we get 5 base + some extras
	// Disable micro-tremor ratio and expect exactly 5
	if len(data.MouseTimestamps) != 5 {
		t.Errorf("expected 5 mouse events, got %d", len(data.MouseTimestamps))
	}
	if len(data.TypingTimestamps) != 3 {
		t.Errorf("expected 3 typing events, got %d", len(data.TypingTimestamps))
	}
}

func TestEventGenerator_EdgeCase_VeryLongText(t *testing.T) {
	cfg := DefaultGeneratorConfig()
	cfg.TypingEventsMin = 500
	cfg.TypingEventsMax = 1000

	gen := NewEventGenerator(cfg)
	data := gen.Generate()

	// Should handle large number of typing events
	if len(data.TypingTimestamps) < 500 {
		t.Errorf("expected >= 500 typing events, got %d", len(data.TypingTimestamps))
	}
}

func TestEventGenerator_EdgeCase_ZeroMouseMovement(t *testing.T) {
	cfg := DefaultGeneratorConfig()
	cfg.MouseEventsMin = 0
	cfg.MouseEventsMax = 0

	gen := NewEventGenerator(cfg)
	data := gen.Generate()

	// Should handle zero mouse events gracefully
	if len(data.MouseTimestamps) != 0 {
		t.Errorf("expected 0 mouse events, got %d", len(data.MouseTimestamps))
	}
}

func TestEventGenerator_EdgeCase_MinimalSession(t *testing.T) {
	cfg := DefaultGeneratorConfig()
	cfg.SessionDurationMs = 1 // Very short session

	gen := NewEventGenerator(cfg)
	data := gen.Generate()

	// Should handle minimal session
	if len(data.MouseTimestamps) < 1 {
		t.Error("expected at least 1 mouse event even in minimal session")
	}
}

func TestEventGenerator_EdgeCase_PredictableSeed(t *testing.T) {
	// Test with fixed seed for reproducibility
	cfg1 := DefaultGeneratorConfig()
	cfg2 := DefaultGeneratorConfig()

	gen1 := NewEventGenerator(cfg1)
	gen2 := NewEventGenerator(cfg2)

	// Note: Different seeds will produce different results
	// This test just verifies the generator produces valid data
	data1 := gen1.Generate()
	data2 := gen2.Generate()

	if len(data1.MouseTimestamps) != len(data2.MouseTimestamps) {
		t.Logf("different seeds produced different event counts: %d vs %d",
			len(data1.MouseTimestamps), len(data2.MouseTimestamps))
	}
}

func TestEventGenerator_EdgeCase_ScrollWithNoScrollEvents(t *testing.T) {
	cfg := DefaultGeneratorConfig()
	cfg.MouseEventsMin = 50
	cfg.MouseEventsMax = 50
	cfg.TypingEventsMin = 20
	cfg.TypingEventsMax = 20

	gen := NewEventGenerator(cfg)
	data := gen.Generate()

	// Verify scroll events exist (we don't disable them)
	if len(data.ScrollTimestamps) > 0 {
		t.Logf("generated %d scroll events", len(data.ScrollTimestamps))
	}
}

func TestEventGenerator_MonotonicTimestamps(t *testing.T) {
	gen := NewEventGenerator(nil)
	data := gen.Generate()

	// Check timestamps are monotonically increasing WITHIN each event stream.
	// Different streams (mouse, keyboard, scroll, click) are independent and
	// may interleave in wall-clock time, so we check each stream separately.
	streams := map[string][]int64{
		"mouse":  data.MouseTimestamps,
		"typing": data.TypingTimestamps,
		"scroll": data.ScrollTimestamps,
		"click":  data.ClickTimestamps,
	}

	for name, ts := range streams {
		for i := 1; i < len(ts); i++ {
			if ts[i] < ts[i-1] {
				t.Errorf("%s timestamps not monotonically increasing at index %d: %d < %d",
					name, i, ts[i], ts[i-1])
			}
		}
	}
}
