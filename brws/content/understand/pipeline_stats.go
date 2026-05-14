package understand

import (
	"context"
	"sync/atomic"
)

// CompressionStats tracks pipeline compression metrics.
type CompressionStats struct {
	RawHTMLBytes        int64
	CleanHTMLBytes      int64
	TotalChunks         int
	ChunksCached        uint32
	ChunksLLMCompressed uint32
	CompressedTokens    uint32
	FullTreeTokens      uint32
	PageCacheHit        bool
	DurationMS          int64
}

// CompressionRatio returns the ratio of compressed to full tokens.
func (s *CompressionStats) CompressionRatio() float32 {
	if s.FullTreeTokens == 0 {
		return 0
	}
	return float32(s.CompressedTokens) / float32(s.FullTreeTokens)
}

// EstimatedRawTokens estimates raw tokens from HTML bytes.
func (s *CompressionStats) EstimatedRawTokens() int {
	return int(s.CleanHTMLBytes / 4)
}

// TokensSaved returns the number of tokens saved by compression.
func (s *CompressionStats) TokensSaved() int64 {
	return int64(s.EstimatedRawTokens()) - int64(s.CompressedTokens)
}

// pipelineStats tracks internal pipeline statistics.
type pipelineStats struct {
	cacheHits        uint32
	llmCalls         uint32
	llmSemaphore     chan struct{}
	workSemaphore    chan struct{}
	maxConcurrentLLM int
}

func (s *pipelineStats) recordCacheHit() { atomic.AddUint32(&s.cacheHits, 1) }
func (s *pipelineStats) recordLLMCall()  { atomic.AddUint32(&s.llmCalls, 1) }
func (s *pipelineStats) snapshot() (uint32, uint32) {
	return atomic.LoadUint32(&s.cacheHits), atomic.LoadUint32(&s.llmCalls)
}

func (s *pipelineStats) acquireLLMSlot() {
	if s.llmSemaphore != nil {
		s.llmSemaphore <- struct{}{}
	}
}

func (s *pipelineStats) releaseLLMSlot() {
	if s.llmSemaphore != nil {
		<-s.llmSemaphore
	}
}

func (s *pipelineStats) tryAcquireWorkSlot(ctx context.Context) bool {
	if s.workSemaphore == nil {
		return true
	}

	select {
	case s.workSemaphore <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	default:
		return false
	}
}

func (s *pipelineStats) releaseWorkSlot() {
	if s.workSemaphore != nil {
		<-s.workSemaphore
	}
}
