package semantic

import (
	"context"
	"encoding/json"
	"testing"
)

func BenchmarkCleanAndParseHTML(b *testing.B) {
	htmlStr := generateBenchmarkHTML(1000, 100)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _, _, _ = cleanAndParseHTML(htmlStr)
	}
}

func BenchmarkHTMLToSemanticTree(b *testing.B) {
	config := &PipelineConfig{
		MaxChunks:        50,
		MaxConcurrentLLM: 5,
		LLMClient:        nil,
	}
	htmlStr := generateBenchmarkHTML(500, 50)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, stats, _ := HTMLToSemanticTreeCached(ctx, htmlStr, "https://example.com", config)
		if stats != nil {
			b.SetBytes(int64(stats.FullTreeTokens))
		}
	}
}

func BenchmarkChunkDOM(b *testing.B) {
	htmlStr := generateBenchmarkHTML(2000, 200)
	_, doc, _, _ := cleanAndParseHTML(htmlStr)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = chunkDOM(doc, "https://example.com")
	}
}

func BenchmarkComputeStructuralHash(b *testing.B) {
	htmlStr := generateBenchmarkHTML(1000, 100)
	_, doc, _, _ := cleanAndParseHTML(htmlStr)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = computeStructuralHash(doc)
	}
}

func BenchmarkExtractInteractiveElements(b *testing.B) {
	htmlStr := generateBenchmarkHTML(500, 50)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = extractInteractiveElements(htmlStr)
	}
}

func BenchmarkJSONEncoding(b *testing.B) {
	tree := generateBenchmarkTree(100, 5)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(tree)
	}
}

func BenchmarkJSONDecoding(b *testing.B) {
	tree := generateBenchmarkTree(100, 5)
	data, _ := json.Marshal(tree)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		var decoded SemanticTree
		_ = json.Unmarshal(data, &decoded)
	}
}

func BenchmarkTokenEstimation(b *testing.B) {
	text := generateBenchmarkText(1000)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = EstimateTokens(text)
	}
}

func BenchmarkTreeTraversal(b *testing.B) {
	tree := generateBenchmarkTree(500, 4)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = tree.AllNodes()
	}
}

func BenchmarkTreeFindNode(b *testing.B) {
	tree := generateBenchmarkTree(500, 4)
	var targetID string
	for _, n := range tree.RootNodes {
		if len(n.Children) > 0 {
			targetID = n.Children[0].ID
			break
		}
	}
	if targetID == "" && len(tree.RootNodes) > 0 {
		targetID = tree.RootNodes[0].ID
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = tree.FindNode(targetID)
	}
}

func generateBenchmarkHTML(depth, breadth int) string {
	html := `<!DOCTYPE html>
<html>
<head><title>Benchmark Page</title></head>
<body>
`
	html += generateHTMLNodes(depth, breadth)
	html += `</body></html>`
	return html
}

func generateHTMLNodes(depth, breadth int) string {
	if depth <= 0 {
		return "<p>This is some text content for benchmarking purposes.</p>"
	}

	html := ""
	for i := 0; i < breadth; i++ {
		html += `<div class="section" id="section-` + string(rune(i)) + `">`
		html += `<a href="/link/` + string(rune(i)) + `">Link ` + string(rune(i)) + `</a>`
		html += `<button type="button">Button ` + string(rune(i)) + `</button>`
		html += `<input type="text" placeholder="Input ` + string(rune(i)) + `">`
		html += generateHTMLNodes(depth-1, breadth/2)
		html += `</div>`
	}
	return html
}

func generateBenchmarkTree(nodeCount, depth int) *SemanticTree {
	nodes := make([]SemanticNode, nodeCount)
	for i := 0; i < nodeCount; i++ {
		nodes[i] = SemanticNode{
			ID:          string(rune(i)),
			Summary:     "This is a benchmark summary for node " + string(rune(i)),
			Embedding:   make([]float32, 1536),
			Children:    generateChildren(i, depth),
			Actions:     generateActions(i),
			TokenCount:  uint32(100 + i%50),
			DOMSelector: "body > div:nth-child(" + string(rune(i)) + ")",
		}
	}
	return &SemanticTree{
		URL:            "https://benchmark.example.com",
		Domain:         "benchmark.example.com",
		Title:          "Benchmark Tree",
		RootNodes:      nodes,
		StructuralHash: "benchmark-hash-" + string(rune(nodeCount)),
	}
}

func generateChildren(parentIdx, depth int) []SemanticNode {
	if depth <= 0 {
		return nil
	}
	children := make([]SemanticNode, 2)
	for i := range children {
		children[i] = SemanticNode{
			ID:         string(rune(parentIdx*10 + i)),
			Summary:    "Child node",
			Children:   generateChildren(parentIdx*10+i, depth-1),
			TokenCount: 50,
		}
	}
	return children
}

func generateActions(nodeIdx int) []Action {
	return []Action{
		{Type: ActionClick, Selector: "button.btn-" + string(rune(nodeIdx)), Description: "Click action"},
		{Type: ActionFill, Selector: "input.field-" + string(rune(nodeIdx)), Description: "Fill input"},
	}
}

func generateBenchmarkText(wordCount int) string {
	text := ""
	for i := 0; i < wordCount; i++ {
		text += "word "
	}
	return text
}
