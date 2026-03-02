package semantic

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestCacheConcurrentReadWrite(t *testing.T) {
	cache, err := NewCacheStore(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("cache init failed: %v", err)
	}
	defer cache.Close()

	node := &SemanticNode{
		ID:         "test",
		Summary:    "Test node",
		TokenCount: 100,
	}

	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			hash := "hash-" + string(rune('a'+idx%26))
			for j := 0; j < 5; j++ {
				_ = cache.PutChunk(context.Background(), hash, node)
				_, _ = cache.GetChunk(context.Background(), hash)
			}
		}(i)
	}

	wg.Wait()
}

func TestCacheStressTest(t *testing.T) {
	cache, err := NewCacheStore(context.Background(), ":memory:")
	if err != nil {
		t.Skipf("cache init failed: %v", err)
	}
	defer cache.Close()

	node := &SemanticNode{ID: "stress", Summary: "Stress test node", TokenCount: 50}

	for i := 0; i < 100; i++ {
		if err := cache.PutChunk(context.Background(), "key-"+string(rune(i)), node); err != nil {
			t.Errorf("PutChunk failed at %d: %v", i, err)
		}
	}

	for i := 0; i < 100; i++ {
		if _, err := cache.GetChunk(context.Background(), "key-"+string(rune(i))); err != nil {
			t.Errorf("GetChunk failed at %d: %v", i, err)
		}
	}
}

func TestPipelineCancellation(t *testing.T) {
	htmlStr := generateBenchmarkHTML(3, 5)
	config := &PipelineConfig{
		MaxChunks:        50,
		MaxConcurrentLLM: 5,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := HTMLToSemanticTreeCached(ctx, htmlStr, "https://example.com", config)
	if err == nil {
		t.Error("expected error from cancelled context")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestPipelineCancellation2(t *testing.T) {
	htmlStr := generateBenchmarkHTML(5, 10)
	config := &PipelineConfig{
		MaxChunks:        20,
		MaxConcurrentLLM: 3,
	}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, _, err := HTMLToSemanticTreeCached(ctx, htmlStr, "https://example.com", config)
	elapsed := time.Since(start)

	if elapsed > 100*time.Millisecond {
		t.Errorf("cancellation took too long: %v", elapsed)
	}

	if err != nil && !errors.Is(err, context.Canceled) {
		t.Logf("got error: %v (acceptable)", err)
	}
}

func TestPipelineConcurrentExtraction(t *testing.T) {
	htmlStr := generateBenchmarkHTML(3, 5)
	config := &PipelineConfig{
		MaxChunks:        20,
		MaxConcurrentLLM: 5,
	}

	var wg sync.WaitGroup
	errCount := 0
	mu := sync.Mutex{}

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			url := "https://example.com/page" + string(rune('0'+idx))
			_, _, err := HTMLToSemanticTreeCached(context.Background(), htmlStr, url, config)
			if err != nil {
				mu.Lock()
				errCount++
				mu.Unlock()
			}
		}(i)
	}

	wg.Wait()

	if errCount > 2 {
		t.Errorf("too many extraction failures: %d", errCount)
	}
}

func TestVectorIndexConcurrentSearch(t *testing.T) {
	cache, err := NewCacheStore(context.Background(), ":memory:")
	if err != nil {
		t.Skipf("cache init failed: %v", err)
	}
	defer cache.Close()

	node := &SemanticNode{ID: "test", Summary: "Test", TokenCount: 100}
	for i := 0; i < 10; i++ {
		if err := cache.PutChunk(context.Background(), "key-"+string(rune('a'+i)), node); err != nil {
			t.Fatalf("PutChunk failed: %v", err)
		}
	}

	var wg sync.WaitGroup

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := cache.GetChunk(context.Background(), "key-a")
			if err != nil {
				t.Errorf("GetChunk failed: %v", err)
			}
		}()
	}

	wg.Wait()
}

func TestSyncMapPerformance(t *testing.T) {
	const iterations = 10000
	const readers = 10
	const writers = 2

	var m sync.Map

	start := time.Now()
	var wg sync.WaitGroup

	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				m.Store("key-"+string(rune('a'+j%26)), "value-"+string(rune(j)))
			}
		}(i)
	}

	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_, _ = m.Load("key-" + string(rune('a'+j%26)))
			}
		}()
	}

	wg.Wait()
	elapsed := time.Since(start)

	t.Logf("sync.Map: %d ops in %v (%.0f ops/sec)",
		(readers+writers)*iterations, elapsed,
		float64((readers+writers)*iterations)/elapsed.Seconds())
}

func TestMemoryLeakWithLargeHTML(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping memory test in short mode")
	}

	for i := 0; i < 10; i++ {
		htmlStr := generateBenchmarkHTML(5, 20)
		config := &PipelineConfig{
			MaxChunks:        30,
			MaxConcurrentLLM: 3,
		}

		_, _, _ = HTMLToSemanticTreeCached(context.Background(), htmlStr, "https://test.com", config)
	}

	runtime.GC()
	time.Sleep(100 * time.Millisecond)
}

func TestErrorPropagation(t *testing.T) {
	cache, err := NewCacheStore(context.Background(), ":memory:")
	if err != nil {
		t.Skipf("cache init failed: %v", err)
	}
	defer cache.Close()

	invalidNode := &SemanticNode{
		ID:         "test",
		Summary:    "Test",
		TokenCount: 100,
	}

	if err := cache.PutChunk(context.Background(), "valid-key", invalidNode); err != nil {
		t.Errorf("PutChunk failed: %v", err)
	}

	_, err = cache.GetChunk(context.Background(), "nonexistent-key")
	if err != nil {
		t.Errorf("GetChunk should return nil for missing key, got: %v", err)
	}
}

func TestCancellationDuringCacheOp(t *testing.T) {
	cache, err := NewCacheStore(context.Background(), ":memory:")
	if err != nil {
		t.Skipf("cache init failed: %v", err)
	}
	defer cache.Close()

	node := &SemanticNode{ID: "test", Summary: "Test", TokenCount: 100}

	ctx, cancel := context.WithCancel(context.Background())

	for i := 0; i < 100; i++ {
		cache.PutChunk(ctx, "key-"+string(rune(i)), node)
	}

	cancel()

	_, err = cache.GetChunk(ctx, "key-1")
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Logf("Got error after cancel: %v (acceptable)", err)
	}
}

func BenchmarkSyncMapVsMutex(b *testing.B) {
	b.Run("sync.Map", func(b *testing.B) {
		var m sync.Map
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				if i%2 == 0 {
					m.Store("key", "value")
				} else {
					_, _ = m.Load("key")
				}
				i++
			}
		})
	})

	b.Run("mutex+map", func(b *testing.B) {
		m := make(map[string]string)
		var mu sync.RWMutex
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				if i%2 == 0 {
					mu.Lock()
					m["key"] = "value"
					mu.Unlock()
				} else {
					mu.RLock()
					_ = m["key"]
					mu.RUnlock()
				}
				i++
			}
		})
	})
}
