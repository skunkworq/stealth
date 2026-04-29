package challenge

import (
	"math/rand"
	"testing"
)

func TestTraceLibrary_AddAndFind(t *testing.T) {
	lib := NewTraceLibrary(t.TempDir())

	lib.Add(&TraceRecording{
		ID: "r1", ChallengeType: "turnstile", ChallengeVariant: "rotate",
		Solved: true, DurationMs: 1500, Events: make([]CaptchaEvent, 20),
	})
	lib.Add(&TraceRecording{
		ID: "r2", ChallengeType: "turnstile", ChallengeVariant: "slide",
		Solved: true, DurationMs: 1200, Events: make([]CaptchaEvent, 15),
	})
	lib.Add(&TraceRecording{
		ID: "r3", ChallengeType: "recaptcha_v2", ChallengeVariant: "image_grid",
		Solved: true, DurationMs: 3000, Events: make([]CaptchaEvent, 40),
	})

	if lib.Count() != 3 {
		t.Fatalf("count = %d, want 3", lib.Count())
	}

	// Find by type
	turnstile := lib.FindByType("turnstile")
	if len(turnstile) != 2 {
		t.Errorf("turnstile count = %d, want 2", len(turnstile))
	}

	// Find by variant
	rotate := lib.FindByVariant("turnstile", "rotate")
	if len(rotate) != 1 {
		t.Errorf("rotate count = %d, want 1", len(rotate))
	}

	// Best match
	best := lib.FindBestMatch("turnstile", "rotate", 1400)
	if best == nil || best.ID != "r1" {
		t.Error("expected r1 as best match for turnstile:rotate near 1400ms")
	}
}

func TestTraceLibrary_Summary(t *testing.T) {
	lib := NewTraceLibrary(t.TempDir())

	lib.Add(&TraceRecording{
		ChallengeType: "turnstile", ChallengeVariant: "rotate",
		Solved: true, DurationMs: 1500, Events: make([]CaptchaEvent, 20),
	})
	lib.Add(&TraceRecording{
		ChallengeType: "turnstile", ChallengeVariant: "rotate",
		Solved: false, DurationMs: 500, Events: make([]CaptchaEvent, 5),
	})

	s := lib.Summary()
	if s.TotalRecordings != 2 {
		t.Errorf("total = %d, want 2", s.TotalRecordings)
	}
	if s.SolvedCount != 1 {
		t.Errorf("solved = %d, want 1", s.SolvedCount)
	}
	if s.AvgDurationMs != 1000 {
		t.Errorf("avg duration = %d, want 1000", s.AvgDurationMs)
	}
}

func TestReplay_PreservesEventCount(t *testing.T) {
	rec := &TraceRecording{
		Events: []CaptchaEvent{
			{Type: "mousemove", ElapsedMs: 0, X: 100, Y: 200},
			{Type: "mousemove", ElapsedMs: 100, X: 150, Y: 220},
			{Type: "mousemove", ElapsedMs: 200, X: 200, Y: 250},
			{Type: "click", ElapsedMs: 300, X: 200, Y: 250},
		},
	}

	rng := rand.New(rand.NewSource(42))
	events := Replay(rec, DefaultReplayParams(), rng.Float64)

	if len(events) != len(rec.Events) {
		t.Fatalf("replay event count = %d, want %d", len(events), len(rec.Events))
	}

	// Timing should be monotonic
	for i := 1; i < len(events); i++ {
		if events[i].ElapsedMs <= events[i-1].ElapsedMs {
			t.Errorf("event %d timing not monotonic: %d <= %d", i, events[i].ElapsedMs, events[i-1].ElapsedMs)
		}
	}
}

func TestReplay_TimeScale(t *testing.T) {
	rec := &TraceRecording{
		Events: []CaptchaEvent{
			{Type: "mousemove", ElapsedMs: 0, X: 100, Y: 200},
			{Type: "mousemove", ElapsedMs: 1000, X: 200, Y: 300},
		},
	}

	rng := rand.New(rand.NewSource(42))

	// 2x speed
	params := ReplayParams{TimeScale: 2.0, TimingJitter: 0}
	events := Replay(rec, params, rng.Float64)

	// Last event should be roughly 2000ms
	if events[1].ElapsedMs < 1500 || events[1].ElapsedMs > 2500 {
		t.Errorf("2x scale: last event at %dms, expected ~2000ms", events[1].ElapsedMs)
	}
}

func TestInterpolate_BlendEvents(t *testing.T) {
	a := &TraceRecording{
		Events: []CaptchaEvent{
			{Type: "mousemove", ElapsedMs: 0, X: 0, Y: 0},
			{Type: "mousemove", ElapsedMs: 100, X: 100, Y: 0},
			{Type: "mousemove", ElapsedMs: 200, X: 200, Y: 0},
		},
	}
	b := &TraceRecording{
		Events: []CaptchaEvent{
			{Type: "mousemove", ElapsedMs: 0, X: 0, Y: 100},
			{Type: "mousemove", ElapsedMs: 100, X: 100, Y: 100},
			{Type: "mousemove", ElapsedMs: 200, X: 200, Y: 100},
		},
	}

	rng := rand.New(rand.NewSource(42))

	// 50% blend: positions should be midway on Y axis
	events := Interpolate(a, b, 0.5, rng.Float64)
	if len(events) != 3 {
		t.Fatalf("interpolated events = %d, want 3", len(events))
	}

	// Middle event should have Y around 50 (±jitter)
	midY := events[1].Y
	if midY < 40 || midY > 60 {
		t.Errorf("mid Y = %.1f, expected ~50", midY)
	}
}

func TestGenerateFromTrace_ErrorOnEmpty(t *testing.T) {
	lib := NewTraceLibrary(t.TempDir())
	rng := rand.New(rand.NewSource(42))

	_, err := lib.GenerateFromTrace("nonexistent", "variant", rng.Float64)
	if err == nil {
		t.Error("expected error when no traces available")
	}
}
