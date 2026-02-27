# Performance Benchmarks

This directory contains comprehensive micro-benchmarks for the `brwslab` core library to measure and optimize performance characteristics.

## Running Benchmarks

### Basic Usage

```bash
# Run all benchmarks
go test -bench=. ./brws/benchmark/

# Run with memory allocation stats
go test -bench=. -benchmem ./brws/benchmark/

# Run specific benchmark
go test -bench=BenchmarkSpoofEngineCreation ./brws/benchmark/

# Run with CPU profiling
go test -bench=. -cpuprofile=cpu.prof ./brws/benchmark/

# Run with memory profiling
go test -bench=. -memprofile=mem.prof ./brws/benchmark/

# Run for extended duration (better statistics)
go test -bench=. -benchtime=30s ./brws/benchmark/

# Run in short mode (skip heavy tests)
go test -bench=. -short ./brws/benchmark/
```

### Analyzing Profiles

```bash
# View CPU profile
go tool pprof cpu.prof

# View memory profile
go tool pprof mem.prof

# Generate flame graph
go tool pprof -http=:8080 cpu.prof

# Top 20 functions by CPU
go tool pprof -top 20 cpu.prof

# List specific function
go tool pprof -list=NewChromeSpoof cpu.prof
```

## Benchmark Categories

### 1. Component Benchmarks (`benchmark_test.go`)

Core component performance:

| Benchmark | Description | Target |
|-----------|-------------|--------|
| `BenchmarkSpoofEngineCreation` | TLS/HTTP config setup | < 1ms/op |
| `BenchmarkTLSFingerprintGeneration` | JA3/JA4 generation | < 100μs/op |
| `BenchmarkPoolAcquireRelease` | Pool hot path | < 10μs/op |
| `BenchmarkSessionCreation` | Session initialization | < 5ms/op |
| `BenchmarkProxyRotation` | Proxy selection | < 1μs/op |

### 2. Suite Benchmarks (`suite_test.go`)

Comprehensive performance analysis:

| Category | Tests | Purpose |
|----------|-------|---------|
| Memory Pressure | High allocation scenarios | GC impact analysis |
| Memory Leak Detection | Long-running allocation patterns | Leak identification |
| Concurrency Scaling | 1-100 goroutines | Lock contention analysis |
| Latency Distribution | P50/P95/P99 percentiles | Tail latency optimization |
| CPU Utilization | CPU-bound operations | Hot path identification |
| Cold Start | First operation performance | Initialization optimization |
| Stress Tests | Sustained high load | Stability under pressure |
| Throughput | Ops/second measurement | Capacity planning |

## Key Metrics

### Memory Metrics

```
B/op        - Bytes allocated per operation
allocs/op   - Number of allocations per operation
heap_bytes  - Heap growth per iteration (leak detection)
```

### Timing Metrics

```
ns/op       - Nanoseconds per operation
p50_ns      - 50th percentile latency
p95_ns      - 95th percentile latency
p99_ns      - 99th percentile latency
ops/sec     - Operations per second
```

### Resource Metrics

```
goroutines  - Active goroutine count
heap_bytes  - Heap memory usage
sys_bytes   - System memory usage
```

## Performance Targets

### Spoof Engine

| Metric | Target | Critical |
|--------|--------|----------|
| Creation Time | < 1ms | Yes |
| Memory/Engine | < 100KB | Yes |
| Allocs/Creation | < 50 | Yes |
| Parallel Scaling | Linear | No |

### Pool Management

| Metric | Target | Critical |
|--------|--------|----------|
| Acquire/Release | < 10μs | Yes |
| Lock Contention | < 1% | Yes |
| Memory/Instance | < 1KB | No |

### Session Management

| Metric | Target | Critical |
|--------|--------|----------|
| Creation | < 5ms | No |
| Cookie Ops | < 100μs | Yes |
| Serialization | < 1ms | No |

### TLS Fingerprinting

| Metric | Target | Critical |
|--------|--------|----------|
| JA3 Parse | < 50μs | Yes |
| Fingerprint Gen | < 100μs | Yes |
| Comparison | < 10μs | Yes |

## Optimization Guidelines

### Memory Optimization

1. **Reduce Allocations**
   ```go
   // Bad: allocations in hot path
   for i := 0; i < n; i++ {
       data := make([]byte, 1024)
       // use data
   }

   // Good: reuse buffer
   data := make([]byte, 1024)
   for i := 0; i < n; i++ {
       // reuse data
   }
   ```

2. **Pool Objects**
   ```go
   var bufPool = sync.Pool{
       New: func() interface{} {
           return make([]byte, 4096)
       },
   }
   ```

3. **Pre-allocate Slices**
   ```go
   // Bad: multiple reallocations
   var results []int
   for i := 0; i < 1000; i++ {
       results = append(results, i)
   }

   // Good: single allocation
   results := make([]int, 0, 1000)
   for i := 0; i < 1000; i++ {
       results = append(results, i)
   }
   ```

### CPU Optimization

1. **Avoid Reflection**
   - Use code generation instead
   - Type assertions over reflection

2. **Optimize Hot Paths**
   - Profile first (`go tool pprof`)
   - Focus on top 20 functions
   - Cache computed values

3. **Reduce Lock Contention**
   ```go
   // Bad: global lock
   var mu sync.Mutex
   func Get() {
       mu.Lock()
       defer mu.Unlock()
       // work
   }

   // Good: sharded locks
   type ShardedMap struct {
       shards [16]struct {
           mu sync.RWMutex
           m  map[string]interface{}
       }
   }
   ```

### Latency Optimization

1. **Batch Operations**
   ```go
   // Process multiple items at once
   func ProcessBatch(items []Item) {
       // Single operation for batch
   }
   ```

2. **Async Initialization**
   ```go
   // Start warming cache before needed
   func NewEngine() {
       e := &Engine{}
       go e.warmCache()
       return e
   }
   ```

## CI/CD Integration

```yaml
# .github/workflows/benchmark.yml
name: Benchmark
on: [push, pull_request]

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run benchmarks
        run: |
          go test -bench=. -benchmem -short \
            ./brws/benchmark/ > benchmark.txt
      
      - name: Compare with baseline
        run: |
          # Store results and compare
          cat benchmark.txt
```

## Regression Detection

```bash
# Save baseline results
go test -bench=. ./brws/benchmark/ > baseline.txt

# After changes
go test -bench=. ./brws/benchmark/ > current.txt

# Compare
benchcmp baseline.txt current.txt
```

## Troubleshooting

### High Memory Usage

1. Check allocation rate: `-benchmem` flag
2. Profile heap: `-memprofile=mem.prof`
3. Look for unbounded growth in leak tests
4. Check for slice append without capacity hints

### Poor Concurrency

1. Run lock contention test
2. Check `sync.Mutex` vs `sync.RWMutex` usage
3. Consider lock-free data structures
4. Profile with `-blockprofile=block.prof`

### High Latency

1. Check P99 metrics in latency tests
2. Profile CPU usage
3. Look for blocking operations
4. Consider pre-computation

## Additional Resources

- [Go Testing Documentation](https://golang.org/pkg/testing/)
- [Go Profiling Guide](https://blog.golang.org/pprof)
- [High Performance Go](https://dave.cheney.net/high-performance-go-workshop)
- [Go Data Structures](https://github.com/Workiva/go-datastructures)
