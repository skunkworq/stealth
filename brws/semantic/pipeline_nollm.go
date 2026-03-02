package semantic

import (
	"fmt"
)

func buildNodeFromChunkNoLLM(chunk DomChunk, index int) *SemanticNode {
	nodeID := SelectorToID(chunk.Selector)
	summary := fmt.Sprintf("%s section", chunk.Tag)

	rawText := extractRawTextFromHTML(chunk.HTML)
	if len(rawText) > 20 && len(rawText) < 200 {
		summary = rawText
	} else if len(rawText) >= 200 {
		summary = rawText[:197] + "..."
	}

	tokenCount := EstimateTokens(summary)

	node := &SemanticNode{
		ID:                nodeID,
		Summary:           summary,
		StructuralHash:    chunk.StructuralHash,
		IsDynamic:         false,
		DOMSelector:       chunk.Selector,
		TokenCount:        tokenCount,
		SubtreeTokenCount: tokenCount,
	}

	matchedElements := extractInteractiveElements(chunk.HTML)
	for i, el := range matchedElements {
		if i >= 10 {
			break
		}
		action := buildActionFromInteractive(el, el.Tag+" element")
		node.Actions = append(node.Actions, action)
	}

	for i, child := range chunk.Children {
		childNode := buildNodeFromChunkNoLLM(child, i)
		node.Children = append(node.Children, *childNode)
		node.SubtreeTokenCount += childNode.SubtreeTokenCount
	}

	return node
}

func buildParentNodeFromChunkNoLLM(chunk DomChunk, childNodes []SemanticNode) *SemanticNode {
	nodeID := SelectorToID(chunk.Selector)
	summary := fmt.Sprintf("%s container with %d sections", chunk.Tag, len(childNodes))

	var totalChildTokens uint32
	for _, child := range childNodes {
		totalChildTokens += child.SubtreeTokenCount
	}

	node := &SemanticNode{
		ID:                nodeID,
		Summary:           summary,
		StructuralHash:    chunk.StructuralHash,
		IsDynamic:         false,
		DOMSelector:       chunk.Selector,
		Children:          childNodes,
		TokenCount:        EstimateTokens(summary),
		SubtreeTokenCount: totalChildTokens,
	}

	for _, child := range childNodes {
		node.Actions = append(node.Actions, child.Actions...)
	}

	return node
}
