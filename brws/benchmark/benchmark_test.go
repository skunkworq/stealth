// Package benchmark provides micro-benchmarks for core library components.
// Run with: go test -bench=. -benchmem -cpuprofile=cpu.prof -memprofile=mem.prof ./brws/benchmark/
package benchmark

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"runtime"
	"testing"
	"time"

	"github.com/stealth/brwslab/brws/engine"
	"github.com/stealth/brwslab/brws/engine/pool"
	"github.com/stealth/brwslab/brws/engine/profiles"
	"github.com/stealth/brwslab/brws/engine/proxy"
	"github.com/stealth/brwslab/brws/engine/spoof"
	"github.com/stealth/brwslab/brws/session"
)

// ============================================================================
// Spoof Engine Benchmarks
// ============================================================================

func BenchmarkSpoofEngineCreation(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		engine, err := spoof.NewChromeSpoof()
		if err != nil {
			b.Fatalf("failed to create chrome spoof: %v", err)
		}
		_ = engine
	}
}

func BenchmarkSpoofEngineCreationFirefox(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		engine, err := spoof.NewFirefoxSpoof()
		if err != nil {
			b.Fatalf("failed to create firefox spoof: %v", err)
		}
		_ = engine
	}
}

func BenchmarkSpoofEngineParallel(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			engine, err := spoof.NewChromeSpoof()
			if err != nil {
				b.Fatalf("failed to create spoof: %v", err)
			}
			_ = engine
		}
	})
}

// ============================================================================
// TLS Fingerprinting Benchmarks
// ============================================================================

func BenchmarkTLSFingerprintParse(b *testing.B) {
	// Sample JA3 fingerprint string parsing simulation
	ja3String := "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Simulate JA3 string parsing
		_ = len(ja3String)
		_ = ja3String[:3]
	}
}

func BenchmarkTLSFingerprintGeneration(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Simulate fingerprint generation
		fp := map[string]interface{}{
			"ja3":   "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0",
			"ja3_hash": "e7c1c1f9f4a9c7d4e5f6a7b8c9d0e1f2",
		}
		_ = fp
	}
}

func BenchmarkTLSFingerprintComparison(b *testing.B) {
	fp1 := "e7c1c1f9f4a9c7d4e5f6a7b8c9d0e1f2"
	fp2 := "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = fp1 == fp2
	}
}

// ============================================================================
// Pool Management Benchmarks
// ============================================================================

type mockEngine struct {
	id int //nolint:unused
}

func (m *mockEngine) Name() string { return "mock" }
func (m *mockEngine) Capabilities() engine.Capabilities { return engine.Capabilities{} }
func (m *mockEngine) Do(_ context.Context, _ *engine.Request) (*engine.Response, error) {
	return &engine.Response{}, nil
}
func (m *mockEngine) Close() error { return nil }

func BenchmarkPoolCreation(b *testing.B) {
	cfg := &pool.Config{
		MaxSize:     10,
		MinSize:     2,
		MaxUses:     100,
		MaxAge:      10 * time.Minute,
		IdleTimeout: 5 * time.Minute,
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		p, err := pool.New(func() (engine.Engine, error) { return &mockEngine{}, nil }, cfg)
		if err != nil {
			b.Fatalf("pool creation failed: %v", err)
		}
		_ = p.Close()
	}
}

func BenchmarkPoolAcquireRelease(b *testing.B) {
	cfg := pool.DefaultConfig()
	p, err := pool.New(func() (engine.Engine, error) { return &mockEngine{}, nil }, cfg)
	if err != nil {
		b.Fatalf("pool creation failed: %v", err)
	}
	defer func() { _ = p.Close() }()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		inst, err := p.Acquire(context.Background())
		if err != nil {
			b.Fatalf("acquire failed: %v", err)
		}
		p.Release(inst)
	}
}

func BenchmarkPoolParallel(b *testing.B) {
	cfg := &pool.Config{
		MaxSize:     50,
		MinSize:     10,
		MaxUses:     1000,
		MaxAge:      10 * time.Minute,
		IdleTimeout: 5 * time.Minute,
	}

	p, err := pool.New(func() (engine.Engine, error) { return &mockEngine{}, nil }, cfg)
	if err != nil {
		b.Fatalf("pool creation failed: %v", err)
	}
	defer func() { _ = p.Close() }()

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			inst, err := p.Acquire(context.Background())
			if err != nil {
				b.Fatalf("acquire failed: %v", err)
			}
			time.Sleep(time.Microsecond * 100) // Simulate work
			p.Release(inst)
		}
	})
}

// ============================================================================
// Session Management Benchmarks
// ============================================================================

func BenchmarkSessionCreation(b *testing.B) {
	tmpDir := b.TempDir()
	mgr, err := session.NewManager(tmpDir)
	if err != nil {
		b.Fatalf("manager creation failed: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sess, err := mgr.Create(fmt.Sprintf("session-%d", i), "chrome")
		if err != nil {
			b.Fatalf("session creation failed: %v", err)
		}
		_ = sess
	}
}

func BenchmarkSessionLoad(b *testing.B) {
	tmpDir := b.TempDir()
	mgr, err := session.NewManager(tmpDir)
	if err != nil {
		b.Fatalf("manager creation failed: %v", err)
	}

	// Create sessions to load
	for i := 0; i < 100; i++ {
		_, err := mgr.Create(fmt.Sprintf("session-%d", i), "chrome")
		if err != nil {
			b.Fatalf("session creation failed: %v", err)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		mgr2, err := session.NewManager(tmpDir)
		if err != nil {
			b.Fatalf("manager reload failed: %v", err)
		}
		_ = mgr2
	}
}

func BenchmarkSessionCookieOperations(b *testing.B) {
	tmpDir := b.TempDir()
	mgr, err := session.NewManager(tmpDir)
	if err != nil {
		b.Fatalf("manager creation failed: %v", err)
	}

	sess, err := mgr.Create("test-session", "chrome")
	if err != nil {
		b.Fatalf("session creation failed: %v", err)
	}

	testURL, _ := url.Parse("https://example.com")
	cookies := []*http.Cookie{
		{Name: "test", Value: "value"},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sess.SetCookies(testURL, cookies)
		result := sess.Cookies(testURL)
		_ = result
	}
}

// ============================================================================
// Profile Management Benchmarks
// ============================================================================

func BenchmarkProfileGeneration(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		profile := profiles.GetChrome120Mac()
		_ = profile
	}
}

func BenchmarkProfileSerialization(b *testing.B) {
	profile := profiles.GetChrome120Mac()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		data, err := json.Marshal(profile)
		if err != nil {
			b.Fatalf("marshal failed: %v", err)
		}

		var restored profiles.Profile
		err = json.Unmarshal(data, &restored)
		if err != nil {
			b.Fatalf("unmarshal failed: %v", err)
		}
	}
}

// ============================================================================
// Memory Allocation Benchmarks
// ============================================================================

func BenchmarkMemorySpoofEngine(b *testing.B) {
	b.ReportAllocs()

	var engines []*spoof.SpoofEngine
	for i := 0; i < b.N; i++ {
		eng, _ := spoof.NewChromeSpoof()
		engines = append(engines, eng)

		// Cleanup every 100 to avoid OOM
		if len(engines) >= 100 {
			engines = nil
			runtime.GC()
		}
	}
}

func BenchmarkMemoryPoolScaling(b *testing.B) {
	cfg := &pool.Config{
		MaxSize:     100,
		MinSize:     10,
		MaxUses:     1000,
		MaxAge:      10 * time.Minute,
		IdleTimeout: 5 * time.Minute,
	}

	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		p, _ := pool.New(func() (engine.Engine, error) { return &mockEngine{}, nil }, cfg)

		// Scale up
		var instances []*pool.BrowserInstance
		for j := 0; j < 50; j++ {
			inst, _ := p.Acquire(context.Background())
			instances = append(instances, inst)
		}

		// Release all
		for _, inst := range instances {
			p.Release(inst)
		}

		_ = p.Close()
	}
}

// ============================================================================
// Proxy Management Benchmarks
// ============================================================================

func BenchmarkProxyRotation(b *testing.B) {
	proxies := []string{
		"http://proxy1.example.com:8080",
		"http://proxy2.example.com:8080",
		"http://proxy3.example.com:8080",
	}

	p := proxy.NewPool(proxies, proxy.StrategyRoundRobin)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pr := p.Get()
		_ = pr
	}
}

func BenchmarkProxyPoolParallel(b *testing.B) {
	proxies := make([]string, 100)
	for i := 0; i < 100; i++ {
		proxies[i] = fmt.Sprintf("http://proxy%d.example.com:8080", i)
	}

	p := proxy.NewPool(proxies, proxy.StrategyRandom)

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pr := p.Get()
			_ = pr
		}
	})
}

// ============================================================================
// HTTP/2 Custom Transport Benchmarks
// ============================================================================

func BenchmarkHTTP2SettingsCreation(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		transport := spoof.ChromeHTTP2Transport()
		_ = transport.Settings
	}
}

func BenchmarkHTTP2HeaderEncoding(b *testing.B) {
	headers := map[string]string{
		"user-agent":      "Mozilla/5.0",
		"accept":          "text/html",
		"accept-language": "en-US",
		"accept-encoding": "gzip, deflate",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Simulate header encoding
		encoded := make([]byte, 0, 256)
		for k, v := range headers {
			encoded = append(encoded, k...)
			encoded = append(encoded, v...)
		}
		_ = encoded
	}
}

// ============================================================================
// Garbage Collection Benchmarks
// ============================================================================

func BenchmarkGCImpact(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Create and discard many objects
		for j := 0; j < 1000; j++ {
			eng, _ := spoof.NewChromeSpoof()
			_ = eng
		}
		runtime.GC()
	}
}

func BenchmarkGCLatency(b *testing.B) {
	// Measure GC pause times
	var pauseTimes []time.Duration

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		start := time.Now()
		runtime.GC()
		pause := time.Since(start)
		pauseTimes = append(pauseTimes, pause)
	}

	// Report statistics
	if len(pauseTimes) > 0 {
		var total time.Duration
		for _, p := range pauseTimes {
			total += p
		}
		b.ReportMetric(float64(total)/float64(len(pauseTimes)), "ns/pause")
	}
}
