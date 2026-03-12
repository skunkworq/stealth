package pool

import (
	"context"
	"testing"
	"time"

	"github.com/skunkworq/stealth/brws/engine"
)

type mockEngine struct {
	id string
}

func (m *mockEngine) Name() string                      { return "mock" }
func (m *mockEngine) Capabilities() engine.Capabilities { return engine.Capabilities{} }
func (m *mockEngine) Do(_ context.Context, _ *engine.Request) (*engine.Response, error) {
	return &engine.Response{Status: 200}, nil
}
func (m *mockEngine) Close() error { return nil }

func mockFactory() (engine.Engine, error) {
	return &mockEngine{id: "test"}, nil
}

func TestNewPool(t *testing.T) {
	pool, err := New(mockFactory, DefaultConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if pool == nil {
		t.Fatal("New() returned nil")
	}

	// Check initial instances created
	stats := pool.Stats()
	if stats.Created < 2 {
		t.Errorf("Expected at least 2 initial instances, got %d", stats.Created)
	}
}

func TestPoolAcquire(t *testing.T) {
	pool, _ := New(mockFactory, &Config{MaxSize: 5, MinSize: 1})
	_ = pool
	defer func() { _ = pool.Close() }()

	ctx := context.Background()

	inst, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	if inst == nil {
		t.Fatal("Acquire() returned nil")
	}

	pool.Release(inst)

	stats := pool.Stats()
	if stats.Requests != 1 {
		t.Errorf("Expected 1 request, got %d", stats.Requests)
	}
}

func TestPoolRelease(t *testing.T) {
	pool, _ := New(mockFactory, &Config{MaxSize: 5, MinSize: 1})
	_ = pool
	defer func() { _ = pool.Close() }()

	ctx := context.Background()
	inst, _ := pool.Acquire(ctx)
	_ = inst

	// Release should not error
	pool.Release(inst)

	stats := pool.Stats()
	if stats.Active < 0 {
		t.Errorf("Active count should not be negative")
	}
}

func TestPoolMaxSize(t *testing.T) {
	pool, _ := New(mockFactory, &Config{MaxSize: 2, MinSize: 1})
	_ = pool
	defer func() { _ = pool.Close() }()

	ctx := context.Background()

	// Acquire 2 instances
	inst1, _ := pool.Acquire(ctx)
	_ = inst1
	inst2, _ := pool.Acquire(ctx)
	_ = inst2

	stats := pool.Stats()
	if stats.Active > int64(pool.config.MaxSize) {
		t.Errorf("Active count %d exceeded max size %d", stats.Active, pool.config.MaxSize)
	}

	// Release and acquire more
	pool.Release(inst1)
	inst3, _ := pool.Acquire(ctx)
	_ = inst3
	pool.Release(inst2)
	pool.Release(inst3)
}

func TestPoolStats(t *testing.T) {
	pool, _ := New(mockFactory, &Config{MaxSize: 5, MinSize: 1})
	_ = pool
	defer func() { _ = pool.Close() }()

	ctx := context.Background()

	// Make some requests
	for i := 0; i < 5; i++ {
		inst, _ := pool.Acquire(ctx)
		_ = inst
		pool.Release(inst)
	}

	stats := pool.Stats()
	if stats.Requests != 5 {
		t.Errorf("Expected 5 requests, got %d", stats.Requests)
	}
}

func TestPoolClose(t *testing.T) {
	pool, _ := New(mockFactory, &Config{MaxSize: 5, MinSize: 2})
	_ = pool

	// Close should not error
	if err := pool.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestNeedsRecycle(t *testing.T) {
	pool, _ := New(mockFactory, &Config{
		MaxUses:     10,
		MaxAge:      1 * time.Millisecond,
		IdleTimeout: 1 * time.Millisecond,
	})
	_ = pool
	defer func() { _ = pool.Close() }()

	inst := &BrowserInstance{
		Engine:    &mockEngine{id: "test"},
		CreatedAt: time.Now().Add(-10 * time.Millisecond),
		LastUsed:  time.Now().Add(-10 * time.Millisecond),
		Uses:      11,
	}

	if !pool.needsRecycle(inst) {
		t.Error("Expected instance to need recycling due to max uses")
	}
}
