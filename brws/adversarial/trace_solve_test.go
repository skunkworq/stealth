package adversarial

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"os"
	"testing"
	"time"
)

const labBaseURL = "http://localhost:9080"

func traceDataDir() string {
	// Use the project's training-data directory
	wd, _ := os.Getwd()
	// We're in brws/adversarial, go up two levels
	return wd + "/../../training-data"
}

func skipIfNoTraces(t *testing.T, lib *TraceLibrary) {
	t.Helper()
	if lib.Count() == 0 {
		t.Skip("no saved traces available — run the lab and solve challenges first")
	}
}

func skipIfLabDown(t *testing.T) {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(labBaseURL + "/api/trace/status")
	if err != nil || resp.StatusCode != 200 {
		t.Skip("lab server not running on " + labBaseURL)
	}
	resp.Body.Close()
}

// --- Trace Replay Validation Tests ---

func TestTraceReplay_LoadAndReplayAllVariants(t *testing.T) {
	lib := NewTraceLibrary(traceDataDir())
	if err := lib.LoadAll(); err != nil {
		t.Fatal("failed to load traces:", err)
	}
	skipIfNoTraces(t, lib)

	t.Logf("Loaded %d traces", lib.Count())
	for typ, recs := range lib.byType {
		t.Logf("  %s: %d recordings", typ, len(recs))
	}

	rng := rand.New(rand.NewSource(42))

	for _, rec := range lib.recordings {
		t.Run(fmt.Sprintf("%s_%s", rec.ChallengeType, rec.ChallengeVariant), func(t *testing.T) {
			if len(rec.Events) == 0 {
				t.Skip("empty recording")
			}

			// Replay with default params
			events := Replay(rec, DefaultReplayParams(), rng.Float64)
			if len(events) != len(rec.Events) {
				t.Fatalf("replayed %d events, want %d", len(events), len(rec.Events))
			}

			// Timing must be monotonic
			for i := 1; i < len(events); i++ {
				if events[i].ElapsedMs <= events[i-1].ElapsedMs {
					t.Errorf("event %d timing not monotonic: %d <= %d",
						i, events[i].ElapsedMs, events[i-1].ElapsedMs)
				}
			}

			// Duration should be within 50% of original
			origDuration := rec.Events[len(rec.Events)-1].ElapsedMs
			replayDuration := events[len(events)-1].ElapsedMs
			ratio := float64(replayDuration) / float64(origDuration)
			if ratio < 0.5 || ratio > 2.0 {
				t.Errorf("duration ratio %.2f out of range [0.5, 2.0]: orig=%dms replay=%dms",
					ratio, origDuration, replayDuration)
			}

			// Compute metrics on replayed events
			metrics := computeRecordingMetrics(events)
			t.Logf("  Original: %d events, %dms", len(rec.Events), rec.DurationMs)
			t.Logf("  Replayed: %d events, %dms", len(events), replayDuration)
			t.Logf("  Metrics: moves=%d clicks=%d avgVel=%.0f straightness=%.3f yVar=%.1f",
				metrics.MouseMoves, metrics.Clicks, metrics.AvgMouseVelocity,
				metrics.Straightness, metrics.YVariance)

			// Replayed trace should have same event type counts
			origMetrics := computeRecordingMetrics(rec.Events)
			if metrics.MouseMoves != origMetrics.MouseMoves {
				t.Errorf("mouse moves: replay=%d orig=%d", metrics.MouseMoves, origMetrics.MouseMoves)
			}
			if metrics.Clicks != origMetrics.Clicks {
				t.Errorf("clicks: replay=%d orig=%d", metrics.Clicks, origMetrics.Clicks)
			}
		})
	}
}

func TestTraceReplay_MultiSeed_ProducesDifferentTraces(t *testing.T) {
	lib := NewTraceLibrary(traceDataDir())
	_ = lib.LoadAll()
	skipIfNoTraces(t, lib)

	rec := lib.recordings[0]
	params := DefaultReplayParams()

	var fingerprints []string
	for seed := int64(0); seed < 10; seed++ {
		rng := rand.New(rand.NewSource(seed))
		events := Replay(rec, params, rng.Float64)

		// Use last event timing as a simple fingerprint
		fp := fmt.Sprintf("%d_%.1f_%.1f",
			events[len(events)-1].ElapsedMs,
			events[len(events)/2].X,
			events[len(events)/2].Y)
		fingerprints = append(fingerprints, fp)
	}

	// At least 8 out of 10 should be unique (jitter makes them different)
	unique := make(map[string]bool)
	for _, fp := range fingerprints {
		unique[fp] = true
	}
	if len(unique) < 8 {
		t.Errorf("only %d unique traces out of 10 seeds — insufficient variation", len(unique))
	}
	t.Logf("Produced %d unique traces from 10 seeds", len(unique))
}

func TestTraceReplay_SpeedVariations(t *testing.T) {
	lib := NewTraceLibrary(traceDataDir())
	_ = lib.LoadAll()
	skipIfNoTraces(t, lib)

	rec := lib.recordings[0]
	rng := rand.New(rand.NewSource(42))
	origDuration := rec.Events[len(rec.Events)-1].ElapsedMs

	tests := []struct {
		name      string
		timeScale float64
		minRatio  float64
		maxRatio  float64
	}{
		{"normal", 1.0, 0.7, 1.3},
		{"fast", 0.7, 0.4, 1.0},
		{"slow", 1.5, 1.0, 2.2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			params := ReplayParams{TimeScale: tc.timeScale, PositionJitter: 2.0, TimingJitter: 0.15}
			events := Replay(rec, params, rng.Float64)
			replayDuration := events[len(events)-1].ElapsedMs
			ratio := float64(replayDuration) / float64(origDuration)

			t.Logf("scale=%.1f: orig=%dms replay=%dms ratio=%.2f",
				tc.timeScale, origDuration, replayDuration, ratio)

			if ratio < tc.minRatio || ratio > tc.maxRatio {
				t.Errorf("ratio %.2f out of expected range [%.1f, %.1f]",
					ratio, tc.minRatio, tc.maxRatio)
			}
		})
	}
}

func TestTraceReplay_MetricsPreserveHumanCharacteristics(t *testing.T) {
	lib := NewTraceLibrary(traceDataDir())
	_ = lib.LoadAll()
	skipIfNoTraces(t, lib)

	rng := rand.New(rand.NewSource(42))

	for _, rec := range lib.recordings {
		t.Run(rec.ChallengeVariant, func(t *testing.T) {
			events := Replay(rec, DefaultReplayParams(), rng.Float64)
			m := computeRecordingMetrics(events)

			// Human characteristics that should survive replay:
			// 1. Reasonable velocity (not 0, not astronomical)
			if m.AvgMouseVelocity <= 0 {
				t.Error("avg velocity should be > 0 for human trace")
			}
			if m.AvgMouseVelocity > 50000 {
				t.Errorf("avg velocity %.0f suspiciously high", m.AvgMouseVelocity)
			}

			// 2. Y variance > 0 (not a perfectly horizontal line)
			if m.YVariance <= 0 {
				t.Error("Y variance should be > 0")
			}

			// 3. Event interval should be reasonable (5-100ms typical for human mouse)
			if m.AvgEventInterval < 1 || m.AvgEventInterval > 500 {
				t.Errorf("avg event interval %.1fms outside human range", m.AvgEventInterval)
			}

			t.Logf("  vel=%.0f maxVel=%.0f interval=%.1fms straight=%.3f yVar=%.1f",
				m.AvgMouseVelocity, m.MaxMouseVelocity, m.AvgEventInterval,
				m.Straightness, m.YVariance)
		})
	}
}

// --- Live Lab Server Tests ---

func TestLabSolve_ReplayedTraceViaAPI(t *testing.T) {
	skipIfLabDown(t)

	lib := NewTraceLibrary(traceDataDir())
	_ = lib.LoadAll()
	skipIfNoTraces(t, lib)

	client := &http.Client{Timeout: 10 * time.Second}
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	variants := []string{"rotate", "slide", "drag"}
	for _, variant := range variants {
		t.Run(variant, func(t *testing.T) {
			// Find a trace for this variant
			recs := lib.FindByVariant("turnstile", variant)
			if len(recs) == 0 {
				t.Skipf("no traces for variant %s", variant)
			}

			// Replay with variation
			events := Replay(recs[0], DefaultReplayParams(), rng.Float64)
			if len(events) == 0 {
				t.Fatal("replay produced no events")
			}

			// 1. Start recording
			startBody, _ := json.Marshal(map[string]string{
				"operator":          "test",
				"challenge_type":    "turnstile",
				"challenge_variant": variant,
				"site_url":          labBaseURL + "/api/trace/lab",
			})
			startResp, err := client.Post(labBaseURL+"/api/trace/start",
				"application/json", bytes.NewReader(startBody))
			if err != nil {
				t.Fatal("start failed:", err)
			}
			var startData map[string]string
			json.NewDecoder(startResp.Body).Decode(&startData)
			startResp.Body.Close()

			sessionID := startData["session_id"]
			recordingID := startData["recording_id"]
			t.Logf("Started session=%s recording=%s", sessionID, recordingID)

			// 2. Submit events in batches (like the browser does)
			batchSize := 50
			for i := 0; i < len(events); i += batchSize {
				end := i + batchSize
				if end > len(events) {
					end = len(events)
				}
				batch := events[i:end]

				recBody, _ := json.Marshal(map[string]any{
					"session_id":   sessionID,
					"recording_id": recordingID,
					"events":       batch,
				})
				recResp, err := client.Post(labBaseURL+"/api/trace/record",
					"application/json", bytes.NewReader(recBody))
				if err != nil {
					t.Fatal("record failed:", err)
				}
				var recData map[string]int
				json.NewDecoder(recResp.Body).Decode(&recData)
				recResp.Body.Close()

				if recData["accepted"] != len(batch) {
					t.Errorf("batch %d: accepted=%d want=%d", i/batchSize, recData["accepted"], len(batch))
				}
			}

			// 3. Complete recording
			completeBody, _ := json.Marshal(map[string]any{
				"session_id":   sessionID,
				"recording_id": recordingID,
				"solved":       true,
				"end_session":  false,
			})
			completeResp, err := client.Post(labBaseURL+"/api/trace/complete",
				"application/json", bytes.NewReader(completeBody))
			if err != nil {
				t.Fatal("complete failed:", err)
			}
			var result map[string]any
			json.NewDecoder(completeResp.Body).Decode(&result)
			completeResp.Body.Close()

			// 4. Validate response
			if !result["solved"].(bool) {
				t.Error("recording should be marked solved")
			}

			metrics := result["metrics"].(map[string]any)
			totalEvents := int(metrics["total_events"].(float64))
			if totalEvents != len(events) {
				t.Errorf("total_events=%d want=%d", totalEvents, len(events))
			}

			fingerprint := result["fingerprint"].(string)
			if len(fingerprint) != 16 {
				t.Errorf("fingerprint length=%d want=16", len(fingerprint))
			}

			durationMs := int64(result["duration_ms"].(float64))
			t.Logf("  Solved: events=%d duration=%dms fingerprint=%s",
				totalEvents, durationMs, fingerprint)
			t.Logf("  Metrics: moves=%.0f clicks=%.0f vel=%.0f straight=%.3f",
				metrics["mouse_moves"], metrics["clicks"],
				metrics["avg_mouse_velocity"], metrics["straightness"])
		})
	}

	// End session to flush
	client.Post(labBaseURL+"/api/trace/end", "application/json", bytes.NewReader([]byte("{}")))
}

func TestLabSolve_InterpolatedTracesViaAPI(t *testing.T) {
	skipIfLabDown(t)

	lib := NewTraceLibrary(traceDataDir())
	_ = lib.LoadAll()
	skipIfNoTraces(t, lib)

	// Need at least 2 recordings to interpolate
	turnstile := lib.FindByType("turnstile")
	if len(turnstile) < 2 {
		t.Skip("need at least 2 turnstile traces to interpolate")
	}

	client := &http.Client{Timeout: 10 * time.Second}
	rng := rand.New(rand.NewSource(42))

	// Interpolate between first two recordings at 50% blend
	events := Interpolate(turnstile[0], turnstile[1], 0.5, rng.Float64)
	if len(events) == 0 {
		t.Fatal("interpolation produced no events")
	}

	t.Logf("Interpolated: %d events from %s(%d) + %s(%d)",
		len(events),
		turnstile[0].ChallengeVariant, len(turnstile[0].Events),
		turnstile[1].ChallengeVariant, len(turnstile[1].Events))

	// Submit to lab
	startBody, _ := json.Marshal(map[string]string{
		"operator":          "test",
		"challenge_type":    "turnstile",
		"challenge_variant": "interpolated",
		"site_url":          labBaseURL + "/api/trace/lab",
	})
	startResp, _ := client.Post(labBaseURL+"/api/trace/start", "application/json", bytes.NewReader(startBody))
	var startData map[string]string
	json.NewDecoder(startResp.Body).Decode(&startData)
	startResp.Body.Close()

	recBody, _ := json.Marshal(map[string]any{
		"session_id":   startData["session_id"],
		"recording_id": startData["recording_id"],
		"events":       events,
	})
	recResp, _ := client.Post(labBaseURL+"/api/trace/record", "application/json", bytes.NewReader(recBody))
	recResp.Body.Close()

	completeBody, _ := json.Marshal(map[string]any{
		"session_id":   startData["session_id"],
		"recording_id": startData["recording_id"],
		"solved":       true,
		"end_session":  false,
	})
	completeResp, _ := client.Post(labBaseURL+"/api/trace/complete", "application/json", bytes.NewReader(completeBody))
	var result map[string]any
	json.NewDecoder(completeResp.Body).Decode(&result)
	completeResp.Body.Close()

	if !result["solved"].(bool) {
		t.Error("interpolated trace should be marked solved")
	}

	metrics := result["metrics"].(map[string]any)
	t.Logf("  Events=%v vel=%.0f straight=%.3f yVar=%.1f",
		metrics["total_events"], metrics["avg_mouse_velocity"],
		metrics["straightness"], metrics["y_variance"])

	// Interpolated velocity should be between the two originals
	m0 := computeRecordingMetrics(turnstile[0].Events)
	m1 := computeRecordingMetrics(turnstile[1].Events)
	interpVel := metrics["avg_mouse_velocity"].(float64)
	minVel := math.Min(m0.AvgMouseVelocity, m1.AvgMouseVelocity) * 0.3
	maxVel := math.Max(m0.AvgMouseVelocity, m1.AvgMouseVelocity) * 3.0
	if interpVel < minVel || interpVel > maxVel {
		t.Errorf("interpolated velocity %.0f out of plausible range [%.0f, %.0f]",
			interpVel, minVel, maxVel)
	}

	client.Post(labBaseURL+"/api/trace/end", "application/json", bytes.NewReader([]byte("{}")))
}

func TestLabSolve_GenerateFromTrace_AllVariants(t *testing.T) {
	lib := NewTraceLibrary(traceDataDir())
	_ = lib.LoadAll()
	skipIfNoTraces(t, lib)

	rng := rand.New(rand.NewSource(42))

	variants := []string{"rotate", "slide", "drag", "orientlr"}
	for _, variant := range variants {
		t.Run(variant, func(t *testing.T) {
			events, err := lib.GenerateFromTrace("turnstile", variant, rng.Float64)
			if err != nil {
				t.Skipf("no traces for %s: %v", variant, err)
			}

			if len(events) == 0 {
				t.Fatal("GenerateFromTrace returned empty events")
			}

			m := computeRecordingMetrics(events)
			t.Logf("  Generated %d events: moves=%d clicks=%d vel=%.0f yVar=%.1f",
				len(events), m.MouseMoves, m.Clicks, m.AvgMouseVelocity, m.YVariance)

			// Should have reasonable event count
			if m.TotalEvents < 10 {
				t.Errorf("too few events: %d", m.TotalEvents)
			}

			// Should have mouse moves
			if m.MouseMoves == 0 {
				t.Error("no mouse moves in generated trace")
			}
		})
	}
}
