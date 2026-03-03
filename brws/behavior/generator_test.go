package behavior

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stealth/brwslab/brws/adversarial"
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
