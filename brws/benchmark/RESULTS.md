# Performance Benchmark Results

This document tracks benchmark results and performance characteristics of the core library.

## Running Benchmarks

```bash
# Run all benchmarks
make bench

# Quick run (short mode)
make bench-quick

# With CPU profiling
make bench-cpu

# With memory profiling
make bench-mem

# Compare with baseline
make bench-compare
```

## Latest Results

**Date:** 2026-02-26  
**Platform:** macOS (Apple M2 Max)  
**Go Version:** 1.24

### Core Component Benchmarks

| Benchmark | ns/op | B/op | allocs/op | Status |
|-----------|-------|------|-----------|--------|
| SpoofEngineCreation (Chrome) | 2,368 | 8,936 | 73 | ✅ |
| SpoofEngineCreation (Firefox) | 2,256 | 8,288 | 65 | ✅ |
| SpoofEngineParallel | 3,280 | 8,936 | 73 | ✅ |
| PoolAcquireRelease | 178 | 1 | 0 | ✅ |
| PoolParallel | 9,871 | 0 | 0 | ✅ |
| SessionCreation | 216,335 | 3,678 | 27 | ⚠️ |
| SessionCookieOperations | 1,291 | 640 | 11 | ✅ |
| ProxyRotation | 52 | 0 | 0 | ✅ |
| HTTP2SettingsCreation | 7.3 | 0 | 0 | ✅ |
| HTTP2HeaderEncoding | 54 | 0 | 0 | ✅ |

### Memory Benchmarks

| Benchmark | ns/op | B/op | allocs/op | Notes |
|-----------|-------|------|-----------|-------|
| MemorySpoofEngine | 2,278,005 | 8,960 | 73 | Per 100 engines |
| MemoryPoolScaling | 20,541 | 9,785 | 216 | 50 instances |
| GCImpact | 333,902,021 | 8,936,048 | 73,002 | 1000 engines |
| GCLatency | 305,474,896 | - | - | ~305ms pause |

### Concurrency Benchmarks

| Goroutines | ns/op | B/op | allocs/op | Efficiency |
|------------|-------|------|-----------|------------|
| 1 | 8,997 | 9,496 | 75 | Baseline |
| 10 | 7,128 | 9,327 | 75 | 1.26x |
| 50 | 5,595 | 9,186 | 75 | 1.61x |
| 100 | 5,092 | 9,061 | 75 | 1.77x |

### Throughput Benchmarks

| Component | ops/sec | Notes |
|-----------|---------|-------|
| EngineCreation | 198,889 | High throughput |
| SessionCreation | 5,136 | I/O bound |

### Latency Percentiles

| P50 | P95 | P99 |
|-----|-----|-----|
| 2,125 ns | 6,958 ns | 94,250 ns |

## Performance Analysis

### Strengths

1. **Pool Management**: Very efficient acquire/release cycle (178 ns/op, 0 allocs)
2. **HTTP/2 Operations**: Zero-allocation hot paths (7-54 ns/op)
3. **Proxy Rotation**: Lock-free operation (52 ns/op)
4. **Concurrency**: Good scaling up to 100 goroutines (1.77x efficiency)

### Areas for Improvement

1. **Session Creation**: 216μs/op is relatively slow due to:
   - File system operations (profile directory creation)
   - UUID generation
   - Cookie jar initialization
   
   **Recommendations:**
   - Consider connection pooling for session storage
   - Batch session creation
   - Lazy initialization of cookie jar

2. **Spoof Engine Creation**: 2.3μs/op with 73 allocs
   - Most allocations are in TLS config building
   - Consider object pooling for engines
   - Lazy build of HTTP/2 settings

3. **Session Loading**: 2ms/op with 218KB allocations
   - Heavy I/O on session reload
   - Consider caching deserialized sessions
   - Implement incremental loading

4. **GC Latency**: ~305ms pause under high allocation
   - Consider reducing allocation rate
   - Use object pools for frequently created objects
   - Tune GOGC for lower latency

### Memory Characteristics

```
Per Engine: ~9KB allocated
Per Pool Instance: ~10KB overhead
Per Session: ~3.7KB allocated
```

## Optimization Opportunities

### High Priority

1. **Session Manager**
   - Implement write-behind caching
   - Batch persistence operations
   - Pre-allocate session buffer pool

2. **Spoof Engine**
   - Pool `utls.ClientHelloSpec` objects
   - Cache TLS extension arrays
   - Lazy initialization of unused features

3. **GC Pressure**
   - Reduce allocations in hot paths
   - Use sync.Pool for temporary buffers
   - Pre-size slices with known capacities

### Medium Priority

1. **HTTP/2 Encoding**
   - Current: 54 ns/op, 0 allocs
   - Could use pre-allocated HPACK encoder

2. **Profile Serialization**
   - Current: 6,093 ns/op, 26 allocs
   - Consider protobuf or flatbuffers

3. **Session Cookie Operations**
   - Current: 1,291 ns/op, 11 allocs
   - Optimize cookie jar lookups

## Profiling Commands

```bash
# CPU Profile
go test -bench=. -cpuprofile=cpu.prof ./brws/benchmark/
go tool pprof -http=:8080 cpu.prof

# Memory Profile
go test -bench=. -memprofile=mem.prof ./brws/benchmark/
go tool pprof -http=:8080 mem.prof

# Block Profile (contention)
go test -bench=. -blockprofile=block.prof ./brws/benchmark/
go tool pprof block.prof

# Mutex Profile
go test -bench=. -mutexprofile=mutex.prof ./brws/benchmark/
go tool pprof mutex.prof
```

## Comparison with Targets

| Metric | Target | Actual | Status |
|--------|--------|--------|--------|
| Engine Creation | < 1ms | 2.3μs | ✅ 434x better |
| Pool Acquire | < 10μs | 178ns | ✅ 56x better |
| Session Creation | < 5ms | 216μs | ✅ 23x better |
| Memory/Engine | < 100KB | 9KB | ✅ 11x better |
| Allocs/Creation | < 50 | 73 | ⚠️ 46% over |

## Next Steps

1. **Immediate (High ROI)**
   - [ ] Implement engine object pool
   - [ ] Add session write-behind caching
   - [ ] Profile-guided optimization on top 5 functions

2. **Short Term**
   - [ ] Reduce allocations in TLS config building
   - [ ] Optimize session persistence format
   - [ ] Add concurrent session loading

3. **Long Term**
   - [ ] Zero-allocation HTTP/2 frame encoding
   - [ ] Lock-free session management
   - [ ] Custom memory allocator for hot paths

## Benchmark Trends

Track performance changes over time:

| Date | Engine Creation | Pool Acquire | Session Create |
|------|-----------------|--------------|----------------|
| 2026-02-26 | 2.3μs | 178ns | 216μs |
| | | | |

---

*Last updated: 2026-02-26*
*Run benchmarks with: `make bench`*
