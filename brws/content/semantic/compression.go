package semantic

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
)

// compressChunksParallel compresses chunks in parallel.
func compressChunksParallel(ctx context.Context, chunks []DomChunk, url string, config *PipelineConfig, stats *pipelineStats) ([]SemanticNode, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	nodes := make([]SemanticNode, len(chunks))
	errors := make([]error, len(chunks))
	var firstErr atomic.Pointer[error]

	processChunk := func(idx int, c DomChunk) {
		node, err := compressChunkRecursive(ctx, c, url, "", idx, config, stats)
		if err != nil {
			var zero error
			if firstErr.CompareAndSwap(&zero, &err) {
				cancel()
			}

			errors[idx] = err

			return
		}

		nodes[idx] = *node
	}

	for i, chunk := range chunks {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if stats != nil && stats.tryAcquireWorkSlot(ctx) {
			wg.Add(1)

			go func(idx int, c DomChunk) {
				defer wg.Done()
				defer stats.releaseWorkSlot()

				processChunk(idx, c)
			}(i, chunk)

			continue
		}

		if err := ctx.Err(); err != nil {
			return nil, err
		}

		processChunk(i, chunk)
	}
	wg.Wait()

	if err := firstErr.Load(); err != nil {
		return nil, *err
	}

	for _, err := range errors {
		if err != nil {
			return nil, err
		}
	}

	return nodes, nil
}

// compressChunkRecursive recursively compresses a chunk and its children.
func compressChunkRecursive(ctx context.Context, chunk DomChunk, url, idPrefix string, index int, config *PipelineConfig, stats *pipelineStats) (*SemanticNode, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	contentKey := ContentHash(chunk.HTML)

	if len(chunk.Children) == 0 {
		return compressLeafChunk(ctx, chunk, url, index, config, stats, contentKey)
	}

	var wg sync.WaitGroup

	childNodesByIndex := make([]SemanticNode, len(chunk.Children))
	childNodePresent := make([]bool, len(chunk.Children))
	childErrors := make([]error, len(chunk.Children))
	var firstErr atomic.Pointer[error]
	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	processChild := func(idx int, c DomChunk) {
		node, err := compressChunkRecursive(cancelCtx, c, url, "", idx, config, stats)
		if err != nil {
			var zero error
			if firstErr.CompareAndSwap(&zero, &err) {
				cancel()
			}

			childErrors[idx] = err

			return
		}

		childNodesByIndex[idx] = *node
		childNodePresent[idx] = true
	}

	for i, child := range chunk.Children {
		select {
		case <-cancelCtx.Done():
			return nil, cancelCtx.Err()
		default:
		}

		if stats != nil && stats.tryAcquireWorkSlot(cancelCtx) {
			wg.Add(1)

			go func(idx int, c DomChunk) {
				defer wg.Done()
				defer stats.releaseWorkSlot()

				processChild(idx, c)
			}(i, child)

			continue
		}

		if err := cancelCtx.Err(); err != nil {
			return nil, err
		}

		processChild(i, child)
	}
	wg.Wait()

	if err := firstErr.Load(); err != nil {
		return nil, *err
	}

	for _, err := range childErrors {
		if err != nil {
			return nil, err
		}
	}

	childNodes := make([]SemanticNode, 0, len(chunk.Children))

	for i := range childNodesByIndex {
		if childNodePresent[i] {
			childNodes = append(childNodes, childNodesByIndex[i])
		}
	}

	if config.Cache != nil {
		if cachedNode, err := config.Cache.GetChunk(ctx, contentKey); err == nil && cachedNode != nil {
			stats.recordCacheHit()
			cachedNode.ID = SelectorToID(chunk.Selector)
			cachedNode.DOMSelector = chunk.Selector
			cachedNode.Children = childNodes
			cachedNode.SubtreeTokenCount = cachedNode.TokenCount + sumSubtreeTokenCounts(childNodes)
			return cachedNode, nil
		}
	}

	stats.recordLLMCall()

	parentNode, err := compressParentChunk(ctx, chunk, childNodes, config)
	if err != nil {
		return nil, err
	}

	if config.Cache != nil {
		_ = config.Cache.PutChunk(ctx, contentKey, parentNode)
	}

	return parentNode, nil
}

// compressLeafChunk compresses a leaf chunk (no children).
func compressLeafChunk(ctx context.Context, chunk DomChunk, url string, index int, config *PipelineConfig, stats *pipelineStats, contentKey string) (*SemanticNode, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if config.Cache != nil {
		if cachedNode, err := config.Cache.GetChunk(ctx, contentKey); err == nil && cachedNode != nil {
			stats.recordCacheHit()
			cachedNode.ID = SelectorToID(chunk.Selector)
			cachedNode.DOMSelector = chunk.Selector
			return cachedNode, nil
		}
	}

	if config.LLMClient == nil {
		return buildNodeFromChunkNoLLMWithContext(ctx, &chunk), nil
	}

	stats.recordLLMCall()

	matchedElements := matchInteractiveElements(chunk.HTML, extractInteractiveElements(chunk.HTML))

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	rawText := extractRawTextFromHTML(chunk.HTML)
	rawTextTokens := EstimateTokens(rawText)

	var interactiveSection string
	if len(matchedElements) == 0 {
		interactiveSection = "\nThis chunk has NO interactive elements. Output an empty \"element_descriptions\" array."
	} else {
		interactiveSection = fmt.Sprintf("\nThis chunk has %d interactive elements (extracted from the DOM):\n", len(matchedElements))
		for i, el := range matchedElements {
			interactiveSection += fmt.Sprintf("  [%d] <%s> → %s\n", i, el.Tag, el.ActionType)
		}
		interactiveSection += "\nFor each element, provide a short description of what it does."
	}

	prompt := fmt.Sprintf(`Compress this HTML fragment into a JSON object.

This is a LEAF node (deepest level). Your summary should be DETAILED and SPECIFIC.
Include actual content: names, prices, values, labels, counts.

Output a JSON object with:
- "summary": detailed description (5-40 tokens). Include specific content (names, prices, ratings).
- "is_dynamic": true if content changes between visits
- "stable": true ONLY if summary describes a fixed structure (e.g. "search input"), false if it contains specific data
- "element_descriptions": array of strings, one per interactive element listed below, in the SAME ORDER.
%s

HTML:
%s

Output ONE JSON object. No markdown. No explanation.`, interactiveSection, chunk.HTML)

	type leafResponse struct {
		Summary             string   `json:"summary"`
		IsDynamic           bool     `json:"is_dynamic"`
		Stable              bool     `json:"stable"`
		ElementDescriptions []string `json:"element_descriptions"`
	}

	var parsed leafResponse
	stats.acquireLLMSlot()
	err := config.LLMClient.CompleteJSON(ctx,
		"You compress HTML into structured JSON. Output valid JSON only. Never output markdown or commentary.",
		prompt, &parsed)
	stats.releaseLLMSlot()
	if err != nil {
		return nil, err
	}

	var children []SemanticNode
	for i, el := range matchedElements {
		var desc string
		if i < len(parsed.ElementDescriptions) {
			desc = parsed.ElementDescriptions[i]
		} else {
			desc = fmt.Sprintf("%s element", el.Tag)
		}

		action := buildActionFromInteractive(el, desc)
		childID := fmt.Sprintf("%s-c%d", SelectorToID(chunk.Selector), i)
		tokenCount := EstimateTokens(desc)

		children = append(children, SemanticNode{
			ID:                childID,
			Summary:           desc,
			StructuralHash:    "",
			IsDynamic:         false,
			Children:          nil,
			Actions:           []Action{action},
			Images:            nil,
			DOMSelector:       el.Selector,
			TokenCount:        tokenCount,
			SubtreeTokenCount: tokenCount,
		})
	}

	parentID := SelectorToID(chunk.Selector)
	summaryTokens := EstimateTokens(parsed.Summary)
	subtreeTokens := summaryTokens + sumSubtreeTokenCounts(children) + rawTextTokens

	node := &SemanticNode{
		ID:                parentID,
		Summary:           parsed.Summary,
		StructuralHash:    chunk.StructuralHash,
		IsDynamic:         parsed.IsDynamic,
		DynamicSelector:   "",
		Children:          children,
		Actions:           nil,
		Images:            chunk.Images,
		DOMSelector:       chunk.Selector,
		TokenCount:        summaryTokens,
		SubtreeTokenCount: subtreeTokens,
		Stable:            parsed.Stable,
		RawText:           rawText,
		RawTextTokens:     rawTextTokens,
	}

	if parsed.IsDynamic {
		node.DynamicSelector = chunk.Selector
	}

	if config.Cache != nil {
		_ = config.Cache.PutChunk(ctx, contentKey, node)
	}

	return node, nil
}

// compressParentChunk compresses a parent chunk (has children).
func compressParentChunk(ctx context.Context, chunk DomChunk, childNodes []SemanticNode, config *PipelineConfig) (*SemanticNode, error) {
	if config.LLMClient == nil {
		return buildParentNodeFromChunkNoLLM(chunk, childNodes), nil
	}

	var childContext strings.Builder
	for i, child := range childNodes {
		actionStr := ""
		if len(child.Actions) > 0 {
			var types []string
			for _, a := range child.Actions {
				types = append(types, string(a.Type))
			}
			actionStr = fmt.Sprintf(" (%s)", strings.Join(types, ","))
		}
		childContext.WriteString(fmt.Sprintf("  Child %d: [#%s] %s%s (%d children)\n",
			i, child.ID, child.Summary, actionStr, len(child.Children)))
	}

	prompt := fmt.Sprintf(`Compress this HTML section into a JSON semantic node.
This is a PARENT node — it contains sub-sections that are already compressed below.

Your summary should be STRUCTURAL and GENERIC: describe WHAT KIND of content is here,
not specific details. Examples: "product grid", "navigation menu", "login form",
"article content", "sidebar links".

Output a JSON object with:
- "summary": structural description (3-15 tokens). Generic, not specific.
- "is_dynamic": true if content changes between visits
- "stable": true if this is a fixed page structure (e.g. "navigation"), false if content varies

Child sections already compressed:
%s

HTML:
%s

Output ONE JSON object. No markdown. No explanation.`, childContext.String(), chunk.HTML)

	type parentResponse struct {
		Summary   string `json:"summary"`
		IsDynamic bool   `json:"is_dynamic"`
		Stable    bool   `json:"stable"`
	}

	var parsed parentResponse
	err := config.LLMClient.CompleteJSON(ctx,
		"You compress HTML into structured JSON. Output valid JSON only. Never output markdown or commentary.",
		prompt, &parsed)
	if err != nil {
		return nil, err
	}

	summaryTokens := EstimateTokens(parsed.Summary)
	subtreeTokens := summaryTokens + sumSubtreeTokenCounts(childNodes)

	node := &SemanticNode{
		ID:                SelectorToID(chunk.Selector),
		Summary:           parsed.Summary,
		StructuralHash:    chunk.StructuralHash,
		IsDynamic:         parsed.IsDynamic,
		DynamicSelector:   "",
		Children:          childNodes,
		Actions:           nil,
		Images:            chunk.Images,
		DOMSelector:       chunk.Selector,
		TokenCount:        summaryTokens,
		SubtreeTokenCount: subtreeTokens,
		Stable:            parsed.Stable,
	}

	if parsed.IsDynamic {
		node.DynamicSelector = chunk.Selector
	}

	return node, nil
}
