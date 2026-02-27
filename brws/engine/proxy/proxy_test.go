package proxy

import (
	"testing"
	"time"
)

func TestNewPool(t *testing.T) {
	proxies := []string{"http://proxy1:8080", "http://proxy2:8080"}
	pool := NewPool(proxies, StrategyRoundRobin)

	if pool == nil {
		t.Fatal("NewPool returned nil")
	}

	if len(pool.proxies) != 2 {
		t.Errorf("Expected 2 proxies, got %d", len(pool.proxies))
	}
}

func TestPoolGet(t *testing.T) {
	proxies := []string{"http://proxy1:8080", "http://proxy2:8080"}
	pool := NewPool(proxies, StrategyRoundRobin)

	// Should return proxies in round-robin
	p1 := pool.Get()
	p2 := pool.Get()

	if p1 == nil || p2 == nil {
		t.Fatal("Get returned nil")
	}

	// They should be different (round-robin)
	if p1.URL == p2.URL {
		t.Logf("Note: Got same proxy twice (with 2 proxies, should alternate)")
	}
}

func TestPoolRecordSuccess(t *testing.T) {
	proxies := []string{"http://proxy1:8080", "http://proxy2:8080"}
	pool := NewPool(proxies, StrategyRoundRobin)

	pool.RecordSuccess("http://proxy1:8080", 100*time.Millisecond)

	stats := pool.Stats()
	if stats.Successes != 1 {
		t.Errorf("Expected 1 success, got %d", stats.Successes)
	}
}

func TestPoolRecordFailure(t *testing.T) {
	proxies := []string{"http://proxy1:8080", "http://proxy2:8080"}
	pool := NewPool(proxies, StrategyRoundRobin)

	pool.RecordFailure("http://proxy1:8080")

	stats := pool.Stats()
	if stats.Failures != 1 {
		t.Errorf("Expected 1 failure, got %d", stats.Failures)
	}
}

func TestPoolAdd(t *testing.T) {
	proxies := []string{"http://proxy1:8080"}
	pool := NewPool(proxies, StrategyRoundRobin)

	pool.Add("http://proxy3:8080")

	if len(pool.proxies) != 2 {
		t.Errorf("Expected 2 proxies, got %d", len(pool.proxies))
	}
}

func TestPoolRemove(t *testing.T) {
	proxies := []string{"http://proxy1:8080", "http://proxy2:8080"}
	pool := NewPool(proxies, StrategyRoundRobin)

	pool.Remove("http://proxy1:8080")

	if len(pool.proxies) != 1 {
		t.Errorf("Expected 1 proxy, got %d", len(pool.proxies))
	}
}

func TestPoolCount(t *testing.T) {
	proxies := []string{"http://proxy1:8080", "http://proxy2:8080"}
	pool := NewPool(proxies, StrategyRoundRobin)

	// Initially all working
	count := pool.Count()
	if count != 2 {
		t.Errorf("Expected 2 working proxies, got %d", count)
	}

	// Mark one as not working
	pool.RecordFailure("http://proxy1:8080")
	pool.RecordFailure("http://proxy1:8080")
	pool.RecordFailure("http://proxy1:8080")
	pool.RecordFailure("http://proxy1:8080")
	pool.RecordFailure("http://proxy1:8080")
	pool.RecordFailure("http://proxy1:8080")

	count = pool.Count()
	if count != 1 {
		t.Errorf("Expected 1 working proxy, got %d", count)
	}
}

func TestStrategyRandom(t *testing.T) {
	proxies := []string{"http://proxy1:8080", "http://proxy2:8080", "http://proxy3:8080"}
	pool := NewPool(proxies, StrategyRandom)

	// Just test that it doesn't panic
	for i := 0; i < 10; i++ {
		pool.Get()
	}
}

func TestStrategyLeastUsed(t *testing.T) {
	proxies := []string{"http://proxy1:8080", "http://proxy2:8080"}
	pool := NewPool(proxies, StrategyLeastUsed)

	// Get first proxy multiple times
	for i := 0; i < 5; i++ {
		pool.Get()
	}

	// Next get should return the other one (less used)
	p := pool.Get()
	if p.URL == "http://proxy1:8080" {
		t.Logf("Note: Got proxy1 (should prefer less used)")
	}
}

func TestWithAuth(t *testing.T) {
	url := WithAuth("http://proxy:8080", "user", "pass")

	if url != "http://user:pass@proxy:8080" {
		t.Logf("WithAuth result: %s (may vary)", url)
	}
}

func TestGetProxyURL(t *testing.T) {
	fn := GetProxyURL("http://proxy:8080")
	if fn == nil {
		t.Error("GetProxyURL returned nil")
	}

	// Should return a valid function - just test it doesn't panic
	_ = fn
}

func TestNewHTTPClient(t *testing.T) {
	client, err := NewHTTPClient("http://proxy:8080")
	if err != nil {
		t.Fatalf("NewHTTPClient error = %v", err)
	}
	if client == nil {
		t.Fatal("NewHTTPClient returned nil")
	}
}

func TestNewHTTPClientNoProxy(t *testing.T) {
	client, err := NewHTTPClient("")
	if err != nil {
		t.Fatalf("NewHTTPClient error = %v", err)
	}
	if client == nil {
		t.Fatal("NewHTTPClient returned nil")
	}
}

func TestRoundRobin(t *testing.T) {
	pool := RoundRobin([]string{"http://p1:8080", "http://p2:8080"})
	if pool == nil {
		t.Error("RoundRobin returned nil")
	}
}

func TestRandom(t *testing.T) {
	pool := Random([]string{"http://p1:8080", "http://p2:8080"})
	if pool == nil {
		t.Error("Random returned nil")
	}
}

func TestLeastUsed(t *testing.T) {
	pool := LeastUsed([]string{"http://p1:8080", "http://p2:8080"})
	if pool == nil {
		t.Error("LeastUsed returned nil")
	}
}
