package challengefsm

import (
	"testing"
	"time"
)

func TestMetricsRecord(t *testing.T) {
	m := NewSolveMetrics()

	m.Record("cloudflare", true, 100*time.Millisecond)
	m.Record("cloudflare", true, 200*time.Millisecond)
	m.Record("cloudflare", false, 50*time.Millisecond)

	rate := m.SuccessRate("cloudflare")
	expected := 2.0 / 3.0
	if rate < expected-0.01 || rate > expected+0.01 {
		t.Fatalf("expected success rate %.4f, got %.4f", expected, rate)
	}

	avg := m.AverageDuration("cloudflare")
	expectedAvg := (100 + 200 + 50) * time.Millisecond / 3
	if avg != expectedAvg {
		t.Fatalf("expected avg duration %v, got %v", expectedAvg, avg)
	}
}

func TestMetricsUnknownProvider(t *testing.T) {
	m := NewSolveMetrics()

	rate := m.SuccessRate("unknown")
	if rate != 0.0 {
		t.Fatalf("expected 0.0 for unknown provider, got %.4f", rate)
	}

	avg := m.AverageDuration("unknown")
	if avg != 0 {
		t.Fatalf("expected 0 for unknown provider, got %v", avg)
	}

	pm := m.GetProviderMetrics("unknown")
	if pm.TotalAttempts != 0 {
		t.Fatalf("expected 0 attempts for unknown provider, got %d", pm.TotalAttempts)
	}
}

func TestMetricsAllProviders(t *testing.T) {
	m := NewSolveMetrics()

	m.Record("a", true, 100*time.Millisecond)
	m.Record("b", false, 200*time.Millisecond)
	m.Record("c", true, 300*time.Millisecond)

	all := m.AllProviders()
	if len(all) != 3 {
		t.Fatalf("expected 3 providers, got %d", len(all))
	}

	if all["a"].SuccessCount != 1 {
		t.Fatalf("expected 1 success for 'a', got %d", all["a"].SuccessCount)
	}
	if all["b"].FailureCount != 1 {
		t.Fatalf("expected 1 failure for 'b', got %d", all["b"].FailureCount)
	}
}

func TestMetricsConcurrentSafety(t *testing.T) {
	m := NewSolveMetrics()

	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				m.Record("test", j%2 == 0, time.Duration(j)*time.Millisecond)
				_ = m.SuccessRate("test")
				_ = m.AverageDuration("test")
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	pm := m.GetProviderMetrics("test")
	if pm.TotalAttempts != 1000 {
		t.Fatalf("expected 1000 total attempts, got %d", pm.TotalAttempts)
	}
}
