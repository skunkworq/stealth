// Package benchmark provides comprehensive performance testing and analysis.
// This file contains utilities for running benchmarks and analyzing results.
package benchmark

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"sort"
	"testing"
	"time"
)

// BenchmarkRunner provides a configurable benchmark execution environment.
//
//nolint:revive // Type name stuttering is intentional for clarity
type BenchmarkRunner struct {
	Name          string
	Iterations    int
	Warmup        int
	EnableCPUProf bool
	EnableMemProf bool
	Results       []BenchmarkResult
}

// BenchmarkResult captures metrics from a single benchmark run.
//
//nolint:revive // Type name stuttering is intentional for clarity
type BenchmarkResult struct {
	Name         string
	Duration     time.Duration
	AllocBytes   uint64
	AllocObjects uint64
	HeapObjects  uint64
	Goroutines   int
	Timestamp    time.Time
}

// NewRunner creates a new benchmark runner with defaults
func NewRunner(name string) *BenchmarkRunner {
	return &BenchmarkRunner{
		Name:          name,
		Iterations:    1000,
		Warmup:        100,
		EnableCPUProf: false,
		EnableMemProf: false,
		Results:       make([]BenchmarkResult, 0),
	}
}

// Run executes benchmarks and collects metrics
func (r *BenchmarkRunner) Run(b *testing.B, fn func()) {
	// Warmup
	for i := 0; i < r.Warmup; i++ {
		fn()
	}

	// Force GC before measurement
	runtime.GC()
	runtime.Gosched()

	// Start profiling if enabled
	if r.EnableCPUProf {
		f, err := os.Create(fmt.Sprintf("%s_cpu.prof", r.Name))
		if err == nil {
			_ = pprof.StartCPUProfile(f)

			defer pprof.StopCPUProfile()
		}
	}

	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)
	start := time.Now()
	startGoroutines := runtime.NumGoroutine()

	// Run the benchmark
	for i := 0; i < r.Iterations; i++ {
		fn()
	}

	duration := time.Since(start)
	runtime.ReadMemStats(&m2)
	endGoroutines := runtime.NumGoroutine()

	result := BenchmarkResult{
		Name:         r.Name,
		Duration:     duration,
		AllocBytes:   m2.TotalAlloc - m1.TotalAlloc,
		AllocObjects: m2.Mallocs - m1.Mallocs,
		HeapObjects:  m2.HeapObjects,
		Goroutines:   endGoroutines - startGoroutines,
		Timestamp:    time.Now(),
	}

	r.Results = append(r.Results, result)

	// Write memory profile if enabled
	if r.EnableMemProf {
		f, err := os.Create(fmt.Sprintf("%s_mem.prof", r.Name))
		if err == nil {
			_ = pprof.WriteHeapProfile(f)
			_ = f.Close()
		}
	}

	// Report to testing.B
	b.ReportMetric(float64(duration)/float64(r.Iterations), "ns/op")
	b.ReportMetric(float64(result.AllocBytes)/float64(r.Iterations), "B/op")
	b.ReportMetric(float64(result.AllocObjects)/float64(r.Iterations), "allocs/op")
}

// Statistics returns statistical analysis of benchmark results
type Statistics struct {
	Count    int
	Min      time.Duration
	Max      time.Duration
	Mean     time.Duration
	Median   time.Duration
	P95      time.Duration
	P99      time.Duration
	StdDev   time.Duration
	TotalMem uint64
	AvgMem   uint64
}

// Analyze computes statistics from benchmark results
func (r *BenchmarkRunner) Analyze() Statistics {
	if len(r.Results) == 0 {
		return Statistics{}
	}

	durations := make([]time.Duration, len(r.Results))
	var totalMem uint64

	for i, r := range r.Results {
		durations[i] = r.Duration
		totalMem += r.AllocBytes
	}

	sort.Slice(durations, func(i, j int) bool {
		return durations[i] < durations[j]
	})

	count := len(durations)
	minDuration := durations[0]
	maxDuration := durations[count-1]

	var sum time.Duration
	for _, d := range durations {
		sum += d
	}
	mean := sum / time.Duration(count)

	median := durations[count/2]
	if count%2 == 0 {
		median = (durations[count/2-1] + durations[count/2]) / 2
	}

	p95Idx := int(float64(count) * 0.95)
	p99Idx := int(float64(count) * 0.99)
	p95 := durations[p95Idx]
	p99 := durations[p99Idx]

	var varianceSum float64
	for _, d := range durations {
		diff := float64(d - mean)
		varianceSum += diff * diff
	}
	stdDev := time.Duration(int64(varianceSum / float64(count)))

	return Statistics{
		Count:    count,
		Min:      minDuration,
		Max:      maxDuration,
		Mean:     mean,
		Median:   median,
		P95:      p95,
		P99:      p99,
		StdDev:   stdDev,
		TotalMem: totalMem,
		AvgMem:   totalMem / uint64(count),
	}
}

// PrintReport outputs a formatted benchmark report
func (r *BenchmarkRunner) PrintReport() {
	stats := r.Analyze()

	_, _ = fmt.Fprintf(os.Stdout, "\n========================================\n")
	_, _ = fmt.Fprintf(os.Stdout, "Benchmark Report: %s\n", r.Name)
	_, _ = fmt.Fprintf(os.Stdout, "========================================\n")
	_, _ = fmt.Fprintf(os.Stdout, "Iterations:     %d\n", r.Iterations)
	_, _ = fmt.Fprintf(os.Stdout, "Warmup:         %d\n", r.Warmup)
	_, _ = fmt.Fprintf(os.Stdout, "\n--- Timing Statistics ---\n")
	_, _ = fmt.Fprintf(os.Stdout, "Min:            %v\n", stats.Min)
	_, _ = fmt.Fprintf(os.Stdout, "Max:            %v\n", stats.Max)
	_, _ = fmt.Fprintf(os.Stdout, "Mean:           %v\n", stats.Mean)
	_, _ = fmt.Fprintf(os.Stdout, "Median:         %v\n", stats.Median)
	_, _ = fmt.Fprintf(os.Stdout, "P95:            %v\n", stats.P95)
	_, _ = fmt.Fprintf(os.Stdout, "P99:            %v\n", stats.P99)
	_, _ = fmt.Fprintf(os.Stdout, "StdDev:         %v\n", stats.StdDev)
	_, _ = fmt.Fprintf(os.Stdout, "\n--- Memory Statistics ---\n")
	_, _ = fmt.Fprintf(os.Stdout, "Total Alloc:    %d bytes\n", stats.TotalMem)
	_, _ = fmt.Fprintf(os.Stdout, "Avg Alloc:      %d bytes\n", stats.AvgMem)
	_, _ = fmt.Fprintf(os.Stdout, "========================================\n\n")
}

// MemorySnapshot captures memory statistics at a point in time
type MemorySnapshot struct {
	HeapAlloc    uint64
	HeapSys      uint64
	HeapIdle     uint64
	HeapInuse    uint64
	HeapReleased uint64
	HeapObjects  uint64
	StackInuse   uint64
	StackSys     uint64
	MSpanInuse   uint64
	MSpanSys     uint64
	MCacheInuse  uint64
	MCacheSys    uint64
	TotalAlloc   uint64
	Sys          uint64
	NumGC        uint32
	NumGoroutine int
	Timestamp    time.Time
}

// CaptureMemorySnapshot records current memory statistics
func CaptureMemorySnapshot() MemorySnapshot {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return MemorySnapshot{
		HeapAlloc:    m.HeapAlloc,
		HeapSys:      m.HeapSys,
		HeapIdle:     m.HeapIdle,
		HeapInuse:    m.HeapInuse,
		HeapReleased: m.HeapReleased,
		HeapObjects:  m.HeapObjects,
		StackInuse:   m.StackInuse,
		StackSys:     m.StackSys,
		MSpanInuse:   m.MSpanInuse,
		MSpanSys:     m.MSpanSys,
		MCacheInuse:  m.MCacheInuse,
		MCacheSys:    m.MCacheSys,
		TotalAlloc:   m.TotalAlloc,
		Sys:          m.Sys,
		NumGC:        m.NumGC,
		NumGoroutine: runtime.NumGoroutine(),
		Timestamp:    time.Now(),
	}
}

// PrintMemoryReport outputs memory statistics
func PrintMemoryReport(label string, snap MemorySnapshot) {
	_, _ = fmt.Fprintf(os.Stdout, "\n--- Memory Snapshot: %s ---\n", label)
	_, _ = fmt.Fprintf(os.Stdout, "Timestamp:      %s\n", snap.Timestamp.Format(time.RFC3339))
	_, _ = fmt.Fprintf(os.Stdout, "Heap Alloc:     %d bytes (%.2f MB)\n", snap.HeapAlloc, float64(snap.HeapAlloc)/(1024*1024))
	_, _ = fmt.Fprintf(os.Stdout, "Heap Sys:       %d bytes (%.2f MB)\n", snap.HeapSys, float64(snap.HeapSys)/(1024*1024))
	_, _ = fmt.Fprintf(os.Stdout, "Heap Inuse:     %d bytes (%.2f MB)\n", snap.HeapInuse, float64(snap.HeapInuse)/(1024*1024))
	_, _ = fmt.Fprintf(os.Stdout, "Heap Objects:   %d\n", snap.HeapObjects)
	_, _ = fmt.Fprintf(os.Stdout, "Stack Inuse:    %d bytes (%.2f MB)\n", snap.StackInuse, float64(snap.StackInuse)/(1024*1024))
	_, _ = fmt.Fprintf(os.Stdout, "Total Alloc:    %d bytes (%.2f MB)\n", snap.TotalAlloc, float64(snap.TotalAlloc)/(1024*1024))
	_, _ = fmt.Fprintf(os.Stdout, "System Memory:  %d bytes (%.2f MB)\n", snap.Sys, float64(snap.Sys)/(1024*1024))
	_, _ = fmt.Fprintf(os.Stdout, "Num GC:         %d\n", snap.NumGC)
	_, _ = fmt.Fprintf(os.Stdout, "Goroutines:     %d\n", snap.NumGoroutine)
	_, _ = fmt.Fprintln(os.Stdout)
}

// CompareSnapshots shows the delta between two memory snapshots
func CompareSnapshots(before, after MemorySnapshot) {
	// Calculate deltas using signed integers for negative values
	// These conversions are safe because memory values won't exceed int64 range in practice
	deltaHeap := safeDelta(after.HeapAlloc, before.HeapAlloc)
	deltaObjects := safeDelta(after.HeapObjects, before.HeapObjects)
	deltaGoroutines := after.NumGoroutine - before.NumGoroutine

	_, _ = fmt.Fprintf(os.Stdout, "\n--- Memory Delta ---\n")
	_, _ = fmt.Fprintf(os.Stdout, "Heap Change:    %+d bytes (%.2f MB)\n", deltaHeap, float64(deltaHeap)/(1024*1024))
	_, _ = fmt.Fprintf(os.Stdout, "Objects Change: %+d\n", deltaObjects)
	_, _ = fmt.Fprintf(os.Stdout, "Goroutines:     %+d\n", deltaGoroutines)
	_, _ = fmt.Fprintf(os.Stdout, "GC Runs:        %d\n", after.NumGC-before.NumGC)
	_, _ = fmt.Fprintln(os.Stdout)
}

// safeDelta calculates the difference between two uint64 values as int64.
// Handles the case where after < before (negative delta).
func safeDelta(after, before uint64) int64 {
	if after >= before {
		return safeInt64(after - before)
	}
	return -safeInt64(before - after)
}

// safeInt64 converts uint64 to int64 with bounds checking.
// Values exceeding math.MaxInt64 are clamped to math.MaxInt64.
func safeInt64(v uint64) int64 {
	const maxInt64 = uint64(^uint(0) >> 1) // math.MaxInt64
	if v > maxInt64 {
		return int64(maxInt64)
	}
	return int64(v)
}
