package semantic

import (
	"golang.org/x/net/html"
)

// computeStructuralHash computes a structural hash for the document body.
func computeStructuralHash(doc *html.Node) string {
	body := findElement(doc, "body")
	if body == nil {
		return StructuralHash("html", nil, nil)
	}

	childrenHashes := make([]string, 0)
	for c := body.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode {
			childrenHashes = append(childrenHashes, hashElementRecursive(c))
		}
	}

	return StructuralHash("body", nil, childrenHashes)
}

// hashElementRecursive recursively hashes an element and its children.
func hashElementRecursive(n *html.Node) string {
	tag := n.Data
	var classes []string
	for _, attr := range n.Attr {
		if attr.Key == "class" {
			classes = fields(attr.Val)
		}
	}

	childrenHashes := make([]string, 0)
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode {
			childrenHashes = append(childrenHashes, hashElementRecursive(c))
		}
	}

	return StructuralHash(tag, classes, childrenHashes)
}

// findElement finds an element by tag name in the document.
func findElement(n *html.Node, tag string) *html.Node {
	if n.Type == html.ElementNode && n.Data == tag {
		return n
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if found := findElement(c, tag); found != nil {
			return found
		}
	}
	return nil
}

// collectSummaries collects all summaries from nodes.
func collectSummaries(nodes []SemanticNode) []string {
	var summaries []string
	for i := range nodes {
		summaries = append(summaries, collectNodeSummaries(&nodes[i])...)
	}
	return summaries
}

// collectNodeSummaries recursively collects summaries from a node.
func collectNodeSummaries(node *SemanticNode) []string {
	summaries := []string{node.Summary}
	for i := range node.Children {
		summaries = append(summaries, collectNodeSummaries(&node.Children[i])...)
	}
	return summaries
}

// assignEmbeddings assigns embeddings to nodes.
func assignEmbeddings(nodes []SemanticNode, embeddings [][]float32) {
	idx := 0
	for i := range nodes {
		assignNodeEmbeddings(&nodes[i], embeddings, &idx)
	}
}

// assignNodeEmbeddings recursively assigns embeddings to a node.
func assignNodeEmbeddings(node *SemanticNode, embeddings [][]float32, idx *int) {
	if *idx < len(embeddings) {
		node.Embedding = embeddings[*idx]
		*idx++
	}
	for i := range node.Children {
		assignNodeEmbeddings(&node.Children[i], embeddings, idx)
	}
}

// sumTokenCounts sums token counts from nodes.
func sumTokenCounts(nodes []SemanticNode) uint32 {
	var total uint32
	for i := range nodes {
		total += nodes[i].TokenCount
	}
	return total
}

// sumSubtreeTokenCounts sums subtree token counts from nodes.
func sumSubtreeTokenCounts(nodes []SemanticNode) uint32 {
	var total uint32
	for i := range nodes {
		total += nodes[i].SubtreeTokenCount
	}
	return total
}

// fields splits a string by whitespace.
func fields(s string) []string {
	var result []string
	for _, f := range splitString(s, ' ') {
		if f != "" {
			result = append(result, f)
		}
	}
	return result
}


