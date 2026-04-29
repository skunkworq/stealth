package observability

import (
	"testing"
	"time"
)

func TestInMemoryCollector(t *testing.T) {
	collector := NewInMemoryCollector()

	// Test counter
	collector.IncCounter("requests", map[string]string{"method": "GET"})
	collector.IncCounter("requests", map[string]string{"method": "GET"})
	collector.IncCounter("requests", map[string]string{"method": "POST"})

	if v := collector.GetCounter("requests", map[string]string{"method": "GET"}); v != 2 {
		t.Errorf("expected counter=2, got %d", v)
	}
	if v := collector.GetCounter("requests", map[string]string{"method": "POST"}); v != 1 {
		t.Errorf("expected counter=1, got %d", v)
	}

	// Test AddCounter
	collector.AddCounter("bytes_sent", 100, nil)
	collector.AddCounter("bytes_sent", 50, nil)
	if v := collector.GetCounter("bytes_sent", nil); v != 150 {
		t.Errorf("expected counter=150, got %d", v)
	}

	// Test gauge
	collector.SetGauge("active_connections", 10, nil)
	if v := collector.GetGauge("active_connections", nil); v != 10 {
		t.Errorf("expected gauge=10, got %f", v)
	}

	collector.SetGauge("active_connections", 5, nil)
	if v := collector.GetGauge("active_connections", nil); v != 5 {
		t.Errorf("expected gauge=5, got %f", v)
	}

	// Test histogram
	collector.RecordHistogram("latency", 100, nil)
	collector.RecordHistogram("latency", 200, nil)
	collector.RecordHistogram("latency", 50, nil)

	stats := collector.GetHistogram("latency", nil)
	if stats.Count != 3 {
		t.Errorf("expected count=3, got %d", stats.Count)
	}
	if stats.Sum != 350 {
		t.Errorf("expected sum=350, got %f", stats.Sum)
	}
	if stats.Min != 50 {
		t.Errorf("expected min=50, got %f", stats.Min)
	}
	if stats.Max != 200 {
		t.Errorf("expected max=200, got %f", stats.Max)
	}
}

func TestTimer(t *testing.T) {
	collector := NewInMemoryCollector()

	timer := StartTimer("operation", map[string]string{"type": "test"})
	timer.collector = collector

	time.Sleep(10 * time.Millisecond)
	duration := timer.Stop()

	if duration < 10*time.Millisecond {
		t.Errorf("expected duration >= 10ms, got %v", duration)
	}

	// Verify it was recorded
	stats := collector.GetHistogram("operation", map[string]string{"type": "test"})
	if stats.Count != 1 {
		t.Errorf("expected count=1, got %d", stats.Count)
	}
}

func TestTimeFunc(t *testing.T) {
	collector := NewInMemoryCollector()
	SetGlobalCollector(collector)

	duration := TimeFunc("test_op", nil, func() {
		time.Sleep(5 * time.Millisecond)
	})

	if duration < 5*time.Millisecond {
		t.Errorf("expected duration >= 5ms, got %v", duration)
	}

	stats := collector.GetHistogram("test_op", nil)
	if stats.Count != 1 {
		t.Errorf("expected count=1, got %d", stats.Count)
	}
}

func TestGlobalCollector(t *testing.T) {
	// Save original
	original := GlobalCollector()

	// Set new collector
	collector := NewInMemoryCollector()
	SetGlobalCollector(collector)

	// Use package-level functions
	IncCounter("test", nil)
	AddCounter("test", 5, nil)
	SetGauge("gauge", 10, nil)
	RecordTiming("timing", 100*time.Millisecond, nil)

	if v := collector.GetCounter("test", nil); v != 6 {
		t.Errorf("expected counter=6, got %d", v)
	}
	if v := collector.GetGauge("gauge", nil); v != 10 {
		t.Errorf("expected gauge=10, got %f", v)
	}

	// Restore
	SetGlobalCollector(original)
}

func TestCollectorReset(t *testing.T) {
	collector := NewInMemoryCollector()

	collector.IncCounter("counter", nil)
	collector.SetGauge("gauge", 10, nil)
	collector.RecordHistogram("hist", 100, nil)

	collector.Reset()

	if v := collector.GetCounter("counter", nil); v != 0 {
		t.Errorf("expected counter=0 after reset, got %d", v)
	}
	if v := collector.GetGauge("gauge", nil); v != 0 {
		t.Errorf("expected gauge=0 after reset, got %f", v)
	}
}

func TestGetAllCounters(t *testing.T) {
	collector := NewInMemoryCollector()

	collector.IncCounter("a", map[string]string{"label": "1"})
	collector.IncCounter("a", map[string]string{"label": "1"})
	collector.IncCounter("b", map[string]string{"label": "2"})

	all := collector.GetAllCounters()
	if len(all) != 2 {
		t.Errorf("expected 2 counters, got %d", len(all))
	}
}

func TestGetAllGauges(t *testing.T) {
	collector := NewInMemoryCollector()

	collector.SetGauge("a", 1.0, nil)
	collector.SetGauge("b", 2.0, nil)

	all := collector.GetAllGauges()
	if len(all) != 2 {
		t.Errorf("expected 2 gauges, got %d", len(all))
	}
}
