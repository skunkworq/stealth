package semantic

import (
	"context"
	"runtime"
	"time"
)

// HTMLToSemanticTree converts HTML to a semantic tree.
// Deprecated: Use HTMLToSemanticTreeCached instead.
func HTMLToSemanticTree(ctx context.Context, htmlStr, url string, config *PipelineConfig) (*SemanticTree, *CompressionStats, error) {
	return HTMLToSemanticTreeCached(ctx, htmlStr, url, config)
}

// HTMLToSemanticTreeCached converts HTML to a semantic tree with caching support.
func HTMLToSemanticTreeCached(ctx context.Context, htmlStr, url string, config *PipelineConfig) (*SemanticTree, *CompressionStats, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	start := time.Now()
	rawBytes := len(htmlStr)
	domain := ExtractDomain(url)

	var stats pipelineStats
	maxConcurrent := config.MaxConcurrentLLM
	if maxConcurrent <= 0 {
		maxConcurrent = 10
	}
	stats.llmSemaphore = make(chan struct{}, maxConcurrent)

	workLimit := maxConcurrent * 4
	minWorkLimit := runtime.GOMAXPROCS(0) * 2

	if workLimit < minWorkLimit {
		workLimit = minWorkLimit
	}

	if workLimit > 0 {
		stats.workSemaphore = make(chan struct{}, workLimit)
	}

	cleanedHTML, doc, title, err := cleanAndParseHTML(htmlStr)
	if err != nil {
		return nil, nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	structuralHash := computeStructuralHash(doc)
	chunks := chunkDOM(doc, url)
	chunks = limitChunkTree(chunks, config.MaxChunks)

	totalChunks := countChunks(chunks)

	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	var nodes []SemanticNode
	if len(chunks) > 0 {
		nodes, err = compressChunksParallel(ctx, chunks, url, config, &stats)
		if err != nil {
			return nil, nil, err
		}
	}

	cached, llmCompressed := stats.snapshot()

	var compressedTokenCount uint32
	for _, node := range nodes {
		compressedTokenCount += node.SubtreeTokenCount
	}

	fullTokenCount := uint32(EstimateTokens(cleanedHTML))
	cleanBytes := len(cleanedHTML)

	rootNode := SemanticNode{
		ID:                SelectorToID("body"),
		Summary:           title,
		StructuralHash:    structuralHash,
		IsDynamic:         false,
		Children:          nodes,
		Images:            extractImagesFromDoc(doc, url),
		DOMSelector:       "body",
		TokenCount:        EstimateTokens(title),
		SubtreeTokenCount: compressedTokenCount,
	}

	tree := &SemanticTree{
		RootNodes:      []SemanticNode{rootNode},
		StructuralHash: structuralHash,
		Domain:         domain,
		URL:            url,
		Title:          title,
	}

	runStats := &CompressionStats{
		RawHTMLBytes:        int64(rawBytes),
		CleanHTMLBytes:      int64(cleanBytes),
		TotalChunks:         totalChunks,
		ChunksCached:        cached,
		ChunksLLMCompressed: llmCompressed,
		CompressedTokens:    compressedTokenCount,
		FullTreeTokens:      fullTokenCount,
		PageCacheHit:        false,
		DurationMS:          time.Since(start).Milliseconds(),
	}

	return tree, runStats, nil
}

// buildShortSelector creates a short CSS selector for an element.
func buildShortSelector(tag, id, class string) string {
	if id != "" {
		return "#" + id
	}
	if class != "" {
		classes := splitFields(class)
		if len(classes) > 0 {
			return tag + "." + classes[0]
		}
	}
	return tag
}

// splitFields splits a string by whitespace.
func splitFields(s string) []string {
	var fields []string
	for _, f := range splitString(s, ' ') {
		if f != "" {
			fields = append(fields, f)
		}
	}
	return fields
}

// splitString splits a string by a separator.
func splitString(s string, sep byte) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func limitChunkTree(chunks []DomChunk, maxChunks int) []DomChunk {
	if maxChunks <= 0 || len(chunks) == 0 {
		return chunks
	}

	remaining := maxChunks

	var trim func(items []DomChunk) []DomChunk

	trim = func(items []DomChunk) []DomChunk {
		if remaining <= 0 || len(items) == 0 {
			return nil
		}

		out := make([]DomChunk, 0, len(items))
		for i := range items {
			if remaining <= 0 {
				break
			}

			remaining--
			item := items[i]
			item.Children = trim(item.Children)
			out = append(out, item)
		}

		return out
	}

	return trim(chunks)
}
