#!/bin/bash
# Benchmark runner for semantic extraction performance validation

set -e

echo "=== Semantic Extraction Benchmark Suite ==="
echo ""

# Create results directory
mkdir -p benchmark_results

# Run benchmarks with different sizes
echo "1. HTML Parsing Benchmarks"
echo "---------------------------"
go test -run=XXX -bench="BenchmarkCleanAndParseHTML" ./brws/semantic/ \
    -benchtime=3s \
    -count=5 \
    -cpu=1,2,4,8 \
    | tee benchmark_results/parsing.txt

echo ""
echo "2. DOM Chunking Benchmarks"
echo "--------------------------"
go test -run=XXX -bench="BenchmarkChunkDOM" ./brws/semantic/ \
    -benchtime=2s \
    -count=3 \
    | tee benchmark_results/chunking.txt

echo ""
echo "3. JSON Serialization Benchmarks"
echo "---------------------------------"
go test -run=XXX -bench="BenchmarkJSONEncoding|BenchmarkJSONDecoding" ./brws/semantic/ \
    -benchtime=2s \
    -count=3 \
    | tee benchmark_results/json.txt

echo ""
echo "4. Token Estimation Benchmarks"
echo "-------------------------------"
go test -run=XXX -bench="BenchmarkTokenEstimation" ./brws/semantic/ \
    -benchtime=2s \
    -count=3 \
    | tee benchmark_results/tokens.txt

echo ""
echo "5. Tree Traversal Benchmarks"
echo "-----------------------------"
go test -run=XXX -bench="BenchmarkTreeTraversal|BenchmarkTreeFindNode" ./brws/semantic/ \
    -benchtime=2s \
    -count=3 \
    | tee benchmark_results/tree.txt

echo ""
echo "6. Cache Operation Benchmarks"
echo "-----------------------------"
go test -run=XXX -bench="BenchmarkCache" ./brws/semantic/cache/... \
    -benchtime=2s \
    -count=3 \
    2>/dev/null || echo "Cache benchmarks not found (expected)"

echo ""
echo "7. Float Serialization Benchmarks"
echo "----------------------------------"
go test -run=XXX -bench="BenchmarkFloat" ./brws/semantic/index/... \
    -benchtime=2s \
    -count=3 \
    2>/dev/null || echo "Float benchmarks not found (expected)"

echo ""
echo "=== Benchmark Results Summary ==="
echo "Results saved to benchmark_results/"
echo ""

# Extract key metrics
echo "Key Performance Metrics:"
echo "------------------------"
grep -E "BenchmarkCleanAndParseHTML|BenchmarkChunkDOM|BenchmarkJSONEncoding|BenchmarkTokenEstimation" \
    benchmark_results/*.txt 2>/dev/null | \
    awk '{print $1": "$2" ns/op, "$4" B/op, "$6" allocs/op"}' || \
    echo "Run benchmarks first to see metrics"
