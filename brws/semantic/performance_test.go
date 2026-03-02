package semantic

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"testing"
)

// BenchmarkFloat32Before benchmarks the OLD implementation
func BenchmarkFloat32Before(b *testing.B) {
	floats := make([]float32, 1536)
	for i := range floats {
		floats[i] = float32(i) / 1536.0
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = floatsToBytesOLD(floats)
	}
}

// BenchmarkFloat32After benchmarks the NEW implementation
func BenchmarkFloat32After(b *testing.B) {
	floats := make([]float32, 1536)
	for i := range floats {
		floats[i] = float32(i) / 1536.0
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = floatsToBytes(floats)
	}
}

// OLD implementation (slow)
func floatsToBytesOLD(floats []float32) []byte {
	bytes := make([]byte, len(floats)*4)
	for i, f := range floats {
		bits := uint32(0)
		for j := 0; j < 32; j++ {
			if f < 0 {
				f = -f
				bits |= 1 << 31
			}
			if f >= 1 {
				f = f - float32(int(f))
				bits |= 1 << uint(30-j%31)
			}
			f = f * 2
		}
		bytes[i*4] = byte(bits >> 24)
		bytes[i*4+1] = byte(bits >> 16)
		bytes[i*4+2] = byte(bits >> 8)
		bytes[i*4+3] = byte(bits)
	}
	return bytes
}

// NEW implementation (fast) - same as in sqlite_vec.go
func floatsToBytes(floats []float32) []byte {
	buf := make([]byte, len(floats)*4)
	for i, f := range floats {
		binary.LittleEndian.PutUint32(buf[i*4:], math.Float32bits(f))
	}
	return buf
}

func benchmarkHTMLParsing(b *testing.B, depth, breadth int) {
	htmlStr := generateBenchmarkHTML(depth, breadth)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _, _, _ = cleanAndParseHTML(htmlStr)
	}
}

func BenchmarkHTMLParsing_Small(b *testing.B) {
	benchmarkHTMLParsing(b, 2, 5) // 50 elements
}

func BenchmarkHTMLParsing_Medium(b *testing.B) {
	benchmarkHTMLParsing(b, 4, 10) // 500 elements
}

func BenchmarkHTMLParsing_Large(b *testing.B) {
	benchmarkHTMLParsing(b, 6, 20) // 5000 elements
}

func BenchmarkHTMLParsing_XLarge(b *testing.B) {
	benchmarkHTMLParsing(b, 8, 30) // 15000 elements
}

func BenchmarkTreeTraversal_Optimized(b *testing.B) {
	tree := generateBenchmarkTree(1000, 4)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = tree.AllNodes()
	}
}

func BenchmarkTreeFindNode_Deep(b *testing.B) {
	tree := generateBenchmarkTree(100, 6)
	targetID := ""
	for _, n := range tree.RootNodes {
		if len(n.Children) > 0 && len(n.Children[0].Children) > 0 {
			targetID = n.Children[0].Children[0].ID
			break
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = tree.FindNode(targetID)
	}
}

func BenchmarkStructuralHash(b *testing.B) {
	htmlStr := generateBenchmarkHTML(5, 15)
	_, doc, _, _ := cleanAndParseHTML(htmlStr)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = computeStructuralHash(doc)
	}
}

func BenchmarkInteractiveElements(b *testing.B) {
	htmlStr := generateBenchmarkHTML(5, 10)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = extractInteractiveElements(htmlStr)
	}
}

func BenchmarkImageExtraction(b *testing.B) {
	htmlStr := `
<html>
<body>
<img src="/img1.jpg" alt="Image 1">
<img src="/img2.jpg" alt="Image 2">
<img src="/img3.jpg" alt="Image 3">
<img src="https://example.com/img4.png" alt="Image 4">
<div><img src="/img5.webp" alt="Image 5"></div>
</body>
</html>`
	_, doc, _, _ := cleanAndParseHTML(htmlStr)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = extractImagesFromDoc(doc, "https://example.com")
	}
}

// Cache benchmarks

func BenchmarkCacheGet(b *testing.B) {
	cache, err := NewCacheStore(context.Background(), ":memory:")
	if err != nil {
		b.Skipf("cache init failed: %v", err)
	}
	defer cache.Close()

	node := &SemanticNode{
		ID:         "test",
		Summary:    "Test node",
		TokenCount: 100,
	}
	hash := "test-hash-12345"
	cache.PutChunk(context.Background(), hash, node)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = cache.GetChunk(context.Background(), hash)
	}
}

func BenchmarkCachePut(b *testing.B) {
	cache, err := NewCacheStore(context.Background(), ":memory:")
	if err != nil {
		b.Skipf("cache init failed: %v", err)
	}
	defer cache.Close()

	node := &SemanticNode{
		ID:         "test",
		Summary:    "Test node with some longer content to make it realistic",
		TokenCount: 100,
		Children:   make([]SemanticNode, 5),
		Actions:    []Action{{Type: ActionClick, Selector: "button", Description: "Submit"}},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		hash := fmt.Sprintf("hash-%d", i)
		_ = cache.PutChunk(context.Background(), hash, node)
	}
}

func BenchmarkCacheGetMiss(b *testing.B) {
	cache, err := NewCacheStore(context.Background(), ":memory:")
	if err != nil {
		b.Skipf("cache init failed: %v", err)
	}
	defer cache.Close()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = cache.GetChunk(context.Background(), fmt.Sprintf("nonexistent-%d", i))
	}
}

// Concurrent cache operations
func BenchmarkCacheConcurrent(b *testing.B) {
	cache, err := NewCacheStore(context.Background(), ":memory:")
	if err != nil {
		b.Skipf("cache init failed: %v", err)
	}
	defer cache.Close()

	node := &SemanticNode{ID: "test", Summary: "Concurrent test", TokenCount: 50}
	for i := 0; i < 100; i++ {
		cache.PutChunk(context.Background(), fmt.Sprintf("key-%d", i), node)
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if i%2 == 0 {
				_, _ = cache.GetChunk(context.Background(), fmt.Sprintf("key-%d", i%100))
			} else {
				_ = cache.PutChunk(context.Background(), fmt.Sprintf("key-%d", i%100), node)
			}
			i++
		}
	})
}

// Token estimation with different text sizes
func benchmarkTokenEstimation(b *testing.B, wordCount int) {
	text := ""
	for i := 0; i < wordCount; i++ {
		text += "word "
	}

	b.ResetTimer()
	b.SetBytes(int64(len(text)))

	for i := 0; i < b.N; i++ {
		_ = EstimateTokens(text)
	}
}

func BenchmarkEstimateTokens_100(b *testing.B)  { benchmarkTokenEstimation(b, 100) }
func BenchmarkEstimateTokens_500(b *testing.B)  { benchmarkTokenEstimation(b, 500) }
func BenchmarkEstimateTokens_1000(b *testing.B) { benchmarkTokenEstimation(b, 1000) }
func BenchmarkEstimateTokens_5000(b *testing.B) { benchmarkTokenEstimation(b, 5000) }
