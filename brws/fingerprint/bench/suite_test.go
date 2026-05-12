// Package benchmark contains comprehensive benchmark suites for performance analysis.
package benchmark

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/skunkworq/stealth/brws/browser/engine"
	instancepool "github.com/skunkworq/stealth/brws/browser/instancepool"
	"github.com/skunkworq/stealth/brws/stealth/script/spoof"
	"github.com/skunkworq/stealth/brws/stealth/profile/session"
)

// ============================================================================
// Performance Regression Suite
// ============================================================================

// BenchmarkSuite runs a comprehensive set of benchmarks
func BenchmarkSuite(b *testing.B) {
	b.Run("EngineCreation", func(b *testing.B) {
		BenchmarkSpoofEngineCreation(b)
	})

	b.Run("TLSFingerprinting", func(b *testing.B) {
		BenchmarkTLSFingerprintGeneration(b)
	})

	b.Run("PoolScaling", func(b *testing.B) {
		BenchmarkPoolParallel(b)
	})

	b.Run("SessionManagement", func(b *testing.B) {
		BenchmarkSessionCreation(b)
	})
}

// ============================================================================
// Memory Pressure Tests
// ============================================================================

func BenchmarkMemoryPressureHigh(b *testing.B) {
	// Test high memory pressure scenario
	if testing.Short() {
		b.Skip("Skipping high memory pressure test in short mode")
	}

	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Create many engines concurrently
		done := make(chan struct{}, 100)

		for j := 0; j < 100; j++ {
			go func() {
				defer func() { done <- struct{}{} }()

				// Simulate high allocation pattern
				data := make([]byte, 1024*1024) // 1MB
				_ = data
			}()
		}

		// Wait for all goroutines
		for j := 0; j < 100; j++ {
			<-done
		}

		// Force GC to measure impact
		runtime.GC()
	}
}

func BenchmarkMemoryLeakDetection(b *testing.B) {
	// Detect potential memory leaks
	if testing.Short() {
		b.Skip("Skipping leak detection in short mode")
	}

	snapshots := make([]MemorySnapshot, 0, b.N)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Run operation that should not leak
		eng, err := spoof.NewChromeSpoof()
		if err != nil {
			b.Fatalf("creation failed: %v", err)
		}
		_ = eng

		// Capture snapshot every 100 iterations
		if i%100 == 0 {
			runtime.GC()
			snapshots = append(snapshots, CaptureMemorySnapshot())
		}
	}

	// Analyze for leaks
	if len(snapshots) >= 2 {
		first := snapshots[0]
		last := snapshots[len(snapshots)-1]

		heapGrowth := int64(last.HeapAlloc) - int64(first.HeapAlloc) //nolint:gosec // G115: HeapAlloc values will fit in int64 for test purposes
		iterations := int64(len(snapshots) * 100)
		growthPerIteration := heapGrowth / iterations

		b.ReportMetric(float64(growthPerIteration), "heap_bytes/iter")

		// Flag potential leak if growth > 1KB per iteration
		if growthPerIteration > 1024 {
			b.Errorf("Potential memory leak detected: %d bytes/iteration", growthPerIteration)
		}
	}
}

// ============================================================================
// Concurrency & Scalability Tests
// ============================================================================

func BenchmarkConcurrencyScaling(b *testing.B) {
	concurrencyLevels := []int{1, 10, 50, 100}

	for _, level := range concurrencyLevels {
		b.Run(fmt.Sprintf("goroutines_%d", level), func(b *testing.B) {
			sem := make(chan struct{}, level)
			done := make(chan struct{}, level)

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				// Acquire slot
				sem <- struct{}{}

				go func() {
					defer func() {
						<-sem
						done <- struct{}{}
					}()

					// Simulate work
					eng, _ := spoof.NewChromeSpoof()
					_ = eng
				}()
			}

			// Wait for completion
			for i := 0; i < b.N; i++ {
				<-done
			}
		})
	}
}

func BenchmarkLockContention(b *testing.B) {
	// Benchmark lock contention in hot paths

	b.Run("PoolContention", func(b *testing.B) {
		cfg := &instancepool.Config{
			MaxSize:     10,
			MinSize:     2,
			MaxUses:     1000,
			MaxAge:      10 * time.Minute,
			IdleTimeout: 5 * time.Minute,
		}

		p, _ := instancepool.New(func() (engine.Engine, error) { return &mockEngine{}, nil }, cfg)
		defer func() { _ = p.Close() }()

		b.ReportAllocs()
		b.ResetTimer()

		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				inst, _ := p.Acquire(context.Background())
				p.Release(inst)
			}
		})
	})
}

// ============================================================================
// Latency Distribution Tests
// ============================================================================

func BenchmarkLatencyDistribution(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping latency distribution in short mode")
	}

	latencies := make([]time.Duration, 0, b.N)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		start := time.Now()

		// Operation to measure
		eng, _ := spoof.NewChromeSpoof()
		_ = eng

		latencies = append(latencies, time.Since(start))
	}

	// Calculate percentiles
	if len(latencies) > 0 {
		sort.Slice(latencies, func(i, j int) bool {
			return latencies[i] < latencies[j]
		})

		p50 := latencies[len(latencies)*50/100]
		p95 := latencies[len(latencies)*95/100]
		p99 := latencies[len(latencies)*99/100]

		b.ReportMetric(float64(p50), "p50_ns")
		b.ReportMetric(float64(p95), "p95_ns")
		b.ReportMetric(float64(p99), "p99_ns")
	}
}

// ============================================================================
// Resource Utilization Tests
// ============================================================================

func BenchmarkCPUUtilization(b *testing.B) {
	// Benchmark CPU-intensive operations

	b.Run("TLSConfigBuild", func(b *testing.B) {
		sig := spoof.LoadDefaultSignatures()["chrome-116"]

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			// Simulate TLS config building
			var cipherSuites []uint16
			for _, c := range sig.TLS.CipherSuites {
				if !c.IsGREASE {
					cipherSuites = append(cipherSuites, c.Value)
				}
			}
			_ = cipherSuites
		}
	})

	b.Run("ExtensionProcessing", func(b *testing.B) {
		sig := spoof.LoadDefaultSignatures()["chrome-116"]

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			// Simulate extension processing
			for _, ext := range sig.TLS.Extensions {
				_ = ext.Type
				_ = ext.IsGREASE
			}
		}
	})
}

// ============================================================================
// Startup & Warmup Tests
// ============================================================================

func BenchmarkColdStart(b *testing.B) {
	// Measure cold start performance

	b.Run("FirstEngine", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			// Each iteration is a fresh start
			eng, err := spoof.NewChromeSpoof()
			if err != nil {
				b.Fatalf("failed: %v", err)
			}
			_ = eng

			// Force cleanup between iterations
			runtime.GC()
		}
	})

	b.Run("WarmEngine", func(b *testing.B) {
		// Pre-warm
		for i := 0; i < 10; i++ {
			eng, _ := spoof.NewChromeSpoof()
			_ = eng
		}
		runtime.GC()

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			eng, _ := spoof.NewChromeSpoof()
			_ = eng
		}
	})
}

// ============================================================================
// Stress Tests
// ============================================================================

func BenchmarkStressTest(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping stress test in short mode")
	}

	// High load sustained test
	b.Run("SustainedLoad", func(b *testing.B) {
		cfg := &instancepool.Config{
			MaxSize:     100,
			MinSize:     10,
			MaxUses:     10000,
			MaxAge:      30 * time.Minute,
			IdleTimeout: 10 * time.Minute,
		}

		p, _ := instancepool.New(func() (engine.Engine, error) { return &mockEngine{}, nil }, cfg)
		defer func() { _ = p.Close() }()

		b.ReportAllocs()
		b.ResetTimer()

		// Run sustained load
		sem := make(chan struct{}, 50)
		done := make(chan struct{})
		errors := make(chan error, b.N)

		for i := 0; i < b.N; i++ {
			sem <- struct{}{}

			go func() {
				defer func() {
					<-sem
					done <- struct{}{}
				}()

				inst, err := p.Acquire(context.Background())
				if err != nil {
					errors <- err
					return
				}

				time.Sleep(time.Microsecond * 10) // Simulate work
				p.Release(inst)
			}()
		}

		// Wait for all
		for i := 0; i < b.N; i++ {
			<-done
		}

		close(errors)
		errorCount := 0
		for range errors {
			errorCount++
		}

		if errorCount > 0 {
			b.Errorf("Had %d errors during stress test", errorCount)
		}
	})
}

// ============================================================================
// Throughput Tests
// ============================================================================

func BenchmarkThroughput(b *testing.B) {
	// Measure operations per second

	b.Run("EngineCreationThroughput", func(b *testing.B) {
		start := time.Now()

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			eng, _ := spoof.NewChromeSpoof()
			_ = eng
		}

		elapsed := time.Since(start)
		opsPerSec := float64(b.N) / elapsed.Seconds()

		b.ReportMetric(opsPerSec, "ops/sec")
	})

	b.Run("SessionThroughput", func(b *testing.B) {
		tmpDir := b.TempDir()
		mgr, _ := session.NewManager(tmpDir)

		start := time.Now()

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			sess, _ := mgr.Create(fmt.Sprintf("sess-%d", i), "chrome")
			_ = sess
		}

		elapsed := time.Since(start)
		opsPerSec := float64(b.N) / elapsed.Seconds()

		b.ReportMetric(opsPerSec, "ops/sec")
	})
}
