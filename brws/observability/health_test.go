package observability

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestHealthMonitor(t *testing.T) {
	monitor := NewHealthMonitor()

	// Register a healthy checker
	monitor.RegisterFunc("healthy_check", func(ctx context.Context) CheckResult {
		return Healthy("all good")
	})

	// Register an unhealthy checker
	monitor.RegisterFunc("unhealthy_check", func(ctx context.Context) CheckResult {
		return Unhealthy("something wrong", errors.New("error"))
	})

	report := monitor.Check(context.Background())

	if report.Status != StatusUnhealthy {
		t.Errorf("expected status unhealthy, got %v", report.Status)
	}
	if len(report.Checks) != 2 {
		t.Errorf("expected 2 checks, got %d", len(report.Checks))
	}
}

func TestHealthMonitorAllHealthy(t *testing.T) {
	monitor := NewHealthMonitor()

	monitor.RegisterFunc("check1", func(ctx context.Context) CheckResult {
		return Healthy("ok")
	})
	monitor.RegisterFunc("check2", func(ctx context.Context) CheckResult {
		return Healthy("ok")
	})

	report := monitor.Check(context.Background())

	if report.Status != StatusHealthy {
		t.Errorf("expected status healthy, got %v", report.Status)
	}
}

func TestHealthMonitorDegraded(t *testing.T) {
	monitor := NewHealthMonitor()

	monitor.RegisterFunc("healthy", func(ctx context.Context) CheckResult {
		return Healthy("ok")
	})
	monitor.RegisterFunc("degraded", func(ctx context.Context) CheckResult {
		return Degraded("slow but working")
	})

	report := monitor.Check(context.Background())

	if report.Status != StatusDegraded {
		t.Errorf("expected status degraded, got %v", report.Status)
	}
}

func TestReadyChecker(t *testing.T) {
	checker := NewReadyChecker("readiness")

	// Initially not ready
	result := checker.Check(context.Background())
	if result.Status != StatusUnhealthy {
		t.Errorf("expected not ready, got %v", result.Status)
	}

	// Set ready
	checker.SetReady(true)
	result = checker.Check(context.Background())
	if result.Status != StatusHealthy {
		t.Errorf("expected ready, got %v", result.Status)
	}

	// Set not ready again
	checker.SetReady(false)
	result = checker.Check(context.Background())
	if result.Status != StatusUnhealthy {
		t.Errorf("expected not ready, got %v", result.Status)
	}
}

func TestCompositeChecker(t *testing.T) {
	composite := NewCompositeChecker("composite")

	composite.Add(NewCheckerFunc("sub1", func(ctx context.Context) CheckResult {
		return Healthy("ok")
	}))
	composite.Add(NewCheckerFunc("sub2", func(ctx context.Context) CheckResult {
		return Healthy("ok")
	}))

	result := composite.Check(context.Background())
	if result.Status != StatusHealthy {
		t.Errorf("expected healthy, got %v", result.Status)
	}

	// Add failing sub-checker
	composite.Add(NewCheckerFunc("sub3", func(ctx context.Context) CheckResult {
		return Unhealthy("failed", errors.New("error"))
	}))

	result = composite.Check(context.Background())
	if result.Status != StatusUnhealthy {
		t.Errorf("expected unhealthy, got %v", result.Status)
	}
}

func TestTimeoutChecker(t *testing.T) {
	slowChecker := NewCheckerFunc("slow", func(ctx context.Context) CheckResult {
		select {
		case <-time.After(100 * time.Millisecond):
			return Healthy("done")
		case <-ctx.Done():
			return Unhealthy("cancelled", ctx.Err())
		}
	})

	timeoutChecker := TimeoutChecker(slowChecker, 50*time.Millisecond)

	start := time.Now()
	result := timeoutChecker.Check(context.Background())
	elapsed := time.Since(start)

	if result.Status != StatusUnhealthy {
		t.Errorf("expected unhealthy (timeout), got %v", result.Status)
	}
	if elapsed > 80*time.Millisecond {
		t.Errorf("expected timeout around 50ms, took %v", elapsed)
	}
}

func TestHealthReportString(t *testing.T) {
	report := HealthReport{
		Status: StatusHealthy,
		Checks: make([]CheckResult, 2),
	}

	s := report.String()
	expected := "Health[healthy, 2 checks]"
	if s != expected {
		t.Errorf("expected %q, got %q", expected, s)
	}
}

func TestStatusString(t *testing.T) {
	tests := []struct {
		status   Status
		expected string
	}{
		{StatusHealthy, "healthy"},
		{StatusDegraded, "degraded"},
		{StatusUnhealthy, "unhealthy"},
		{Status(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.status.String(); got != tt.expected {
			t.Errorf("Status(%d).String() = %s, expected %s", tt.status, got, tt.expected)
		}
	}
}

func TestResultHelpers(t *testing.T) {
	// Healthy
	h := Healthy("all good")
	if h.Status != StatusHealthy {
		t.Errorf("expected healthy status")
	}
	if h.Message != "all good" {
		t.Errorf("expected message 'all good'")
	}

	// Unhealthy
	u := Unhealthy("failed", errors.New("error"))
	if u.Status != StatusUnhealthy {
		t.Errorf("expected unhealthy status")
	}
	if u.Error == nil {
		t.Errorf("expected error")
	}

	// Degraded
	d := Degraded("slow")
	if d.Status != StatusDegraded {
		t.Errorf("expected degraded status")
	}
}

func TestHealthMonitorAsync(t *testing.T) {
	monitor := NewHealthMonitor()

	monitor.RegisterFunc("fast", func(ctx context.Context) CheckResult {
		return Healthy("fast")
	})
	monitor.RegisterFunc("slow", func(ctx context.Context) CheckResult {
		time.Sleep(50 * time.Millisecond)
		return Healthy("slow")
	})

	start := time.Now()
	report := monitor.CheckAsync(context.Background())
	elapsed := time.Since(start)

	// Should be faster than sequential (50ms + overhead vs 50ms parallel)
	if elapsed > 100*time.Millisecond {
		t.Errorf("async checks took too long: %v", elapsed)
	}

	if len(report.Checks) != 2 {
		t.Errorf("expected 2 checks, got %d", len(report.Checks))
	}
}

func TestCheckerFunc(t *testing.T) {
	called := false
	checker := NewCheckerFunc("test", func(ctx context.Context) CheckResult {
		called = true
		return Healthy("ok")
	})

	if checker.Name() != "test" {
		t.Errorf("expected name 'test', got %s", checker.Name())
	}

	result := checker.Check(context.Background())
	if !called {
		t.Error("check function was not called")
	}
	if result.Status != StatusHealthy {
		t.Errorf("expected healthy result")
	}
}
