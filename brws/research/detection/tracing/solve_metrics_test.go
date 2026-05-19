package tracing

import (
	"testing"
)

func TestSolveMetrics_BasicTracking(t *testing.T) {
	tracker := NewSolveMetricsTracker()

	// Record some attempts
	tracker.RecordFromValidation("turnstile", "rotate", "solver", true, 1500, 20, nil, 0.9)
	tracker.RecordFromValidation("turnstile", "rotate", "solver", true, 1800, 22, nil, 0.85)
	tracker.RecordFromValidation("turnstile", "rotate", "solver", false, 200, 3,
		[]TurnstileHeuristicSignal{{Name: "rotation_too_fast", Weight: 0.5}}, 0.3)

	if tracker.Count() != 3 {
		t.Fatalf("count = %d, want 3", tracker.Count())
	}

	report := tracker.Report()
	if report.TotalAttempts != 3 {
		t.Errorf("total = %d, want 3", report.TotalAttempts)
	}

	// 2/3 passed
	if report.PassRate < 0.66 || report.PassRate > 0.67 {
		t.Errorf("pass rate = %.3f, want ~0.667", report.PassRate)
	}

	// Type metrics
	tm := report.ByType["turnstile"]
	if tm == nil {
		t.Fatal("missing turnstile type metrics")
	}
	if tm.Passed != 2 || tm.Failed != 1 {
		t.Errorf("passed=%d failed=%d, want 2/1", tm.Passed, tm.Failed)
	}

	// Source metrics
	sm := report.BySource["solver"]
	if sm == nil {
		t.Fatal("missing solver source metrics")
	}
	if sm.Attempts != 3 {
		t.Errorf("solver attempts = %d, want 3", sm.Attempts)
	}
}

func TestSolveMetrics_TimingProfile(t *testing.T) {
	tracker := NewSolveMetricsTracker()

	durations := []int64{500, 800, 1000, 1200, 1500, 2000, 3000, 5000}
	for _, d := range durations {
		tracker.Record(SolveAttempt{
			ChallengeType: "recaptcha_v2",
			Source:        "human",
			Passed:        true,
			DurationMs:    d,
		})
	}

	report := tracker.Report()
	tp := report.TimingProfile

	if tp.MinMs != 500 {
		t.Errorf("min = %d, want 500", tp.MinMs)
	}
	if tp.MaxMs != 5000 {
		t.Errorf("max = %d, want 5000", tp.MaxMs)
	}
	if tp.MeanMs < 1800 || tp.MeanMs > 1900 {
		t.Errorf("mean = %.0f, want ~1875", tp.MeanMs)
	}
	if tp.P95Ms < 3000 {
		t.Errorf("p95 = %d, want ≥3000", tp.P95Ms)
	}
}

func TestSolveMetrics_SignalTracking(t *testing.T) {
	tracker := NewSolveMetricsTracker()

	// All failures have the same signal
	for range 5 {
		tracker.RecordFromValidation("turnstile", "slide", "solver", false, 100, 3,
			[]TurnstileHeuristicSignal{
				{Name: "slide_too_fast", Weight: 0.5},
				{Name: "no_y_axis_wobble", Weight: 0.5},
			}, 0.2)
	}
	// Some passes
	for range 5 {
		tracker.RecordFromValidation("turnstile", "slide", "solver", true, 1500, 20, nil, 0.9)
	}

	report := tracker.Report()

	if len(report.TopSignals) < 2 {
		t.Fatalf("expected ≥2 signals, got %d", len(report.TopSignals))
	}

	// Check fail correlation
	for _, sig := range report.TopSignals {
		if sig.Name == "slide_too_fast" {
			if sig.Count != 5 {
				t.Errorf("slide_too_fast count = %d, want 5", sig.Count)
			}
			if sig.FailCorrelation < 0.99 {
				t.Errorf("fail correlation = %.2f, want 1.0", sig.FailCorrelation)
			}
		}
	}
}

func TestSolveMetrics_AnomalyDetection(t *testing.T) {
	tracker := NewSolveMetricsTracker()

	// Solver failing a lot
	for range 10 {
		tracker.RecordFromValidation("turnstile", "rotate", "solver", false, 150, 3,
			[]TurnstileHeuristicSignal{{Name: "rotation_too_fast", Weight: 0.5}}, 0.2)
	}

	report := tracker.Report()

	foundLowRate := false
	for _, flag := range report.AnomalyFlags {
		if flag == "solver_pass_rate_low: solver passing <50% of challenges" {
			foundLowRate = true
		}
	}
	if !foundLowRate {
		t.Error("expected solver_pass_rate_low anomaly flag")
	}
}

func TestSolveMetrics_MultiSource(t *testing.T) {
	tracker := NewSolveMetricsTracker()

	// Human traces
	tracker.RecordFromValidation("recaptcha_v2", "image_grid", "human", true, 3000, 45, nil, 0.95)
	tracker.RecordFromValidation("recaptcha_v2", "image_grid", "human", true, 2800, 40, nil, 0.92)

	// Solver attempts
	tracker.RecordFromValidation("recaptcha_v2", "image_grid", "solver", true, 1800, 25, nil, 0.80)
	tracker.RecordFromValidation("recaptcha_v2", "image_grid", "solver", false, 500, 8,
		[]TurnstileHeuristicSignal{{Name: "solve_too_fast", Weight: 0.5}}, 0.4)

	// Trace replays
	tracker.RecordFromValidation("recaptcha_v2", "image_grid", "trace_replay", true, 2500, 38, nil, 0.88)

	report := tracker.Report()

	if report.BySource["human"].PassRate != 1.0 {
		t.Error("human pass rate should be 100%")
	}
	if report.BySource["solver"].PassRate != 0.5 {
		t.Error("solver pass rate should be 50%")
	}
	if report.BySource["trace_replay"].PassRate != 1.0 {
		t.Error("trace_replay pass rate should be 100%")
	}
}

func TestSolveMetrics_ReportJSON(t *testing.T) {
	tracker := NewSolveMetricsTracker()
	tracker.RecordFromValidation("turnstile", "checkbox", "solver", true, 1000, 5, nil, 0.9)

	data, err := tracker.ReportJSON()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("JSON report should not be empty")
	}
}
