package semantic

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/html"
)

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

func (s *CompressionStats) CompressionRatio() float32 {
	if s.FullTreeTokens == 0 {
		return 0
	}
	return float32(s.CompressedTokens) / float32(s.FullTreeTokens)
}

func (s *CompressionStats) EstimatedRawTokens() int {
	return int(s.CleanHTMLBytes / 4)
}

func (s *CompressionStats) TokensSaved() int64 {
	return int64(s.EstimatedRawTokens()) - int64(s.CompressedTokens)
}

type VisionClient struct {
	client *LLMClient
}

func NewVisionClient(llmClient *LLMClient) *VisionClient {
	return &VisionClient{client: llmClient}
}

type PipelineConfig struct {
	LLMClient        *LLMClient
	EmbeddingClient  *EmbeddingClient
	VisionClient     *VisionClient
	Cache            *CacheStore
	MaxDepth         int
	MinContentLen    int
	MaxChunks        int
	MaxConcurrentLLM int
}

type DomChunk struct {
	Selector            string
	Tag                 string
	HTML                string
	StructuralHash      string
	Children            []DomChunk
	Images              []ImageRef
	Depth               int
	InteractiveElements []InteractiveElement
}

type pipelineStats struct {
	cacheHits        uint32
	llmCalls         uint32
	llmSemaphore     chan struct{}
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

func HTMLToSemanticTree(ctx context.Context, htmlStr, url string, config *PipelineConfig) (*SemanticTree, *CompressionStats, error) {
	return HTMLToSemanticTreeCached(ctx, htmlStr, url, config)
}

func HTMLToSemanticTreeCached(ctx context.Context, htmlStr, url string, config *PipelineConfig) (*SemanticTree, *CompressionStats, error) {
	start := time.Now()
	rawBytes := len(htmlStr)
	domain := ExtractDomain(url)

	var stats pipelineStats
	maxConcurrent := config.MaxConcurrentLLM
	if maxConcurrent <= 0 {
		maxConcurrent = 10
	}
	stats.llmSemaphore = make(chan struct{}, maxConcurrent)

	cleanHTML, doc, err := cleanAndParseHTML(htmlStr)
	if err != nil {
		return nil, nil, err
	}
	cleanBytes := len(cleanHTML)

	title := extractTitle(htmlStr)
	structuralHash := computeStructuralHash(doc)
	pageImages := extractImagesFromDoc(doc, url)

	_ = extractInteractiveElements(htmlStr)
	chunks := chunkDOM(doc, url)

	totalChunks := countChunks(chunks)

	if config.MaxChunks > 0 && len(chunks) > config.MaxChunks {
		chunks = chunks[:config.MaxChunks]
	}

	nodes, err := compressChunksParallel(ctx, chunks, url, config, &stats)
	if err != nil {
		return nil, nil, err
	}

	cached, llmCompressed := stats.snapshot()

	attachImagesToNodes(nodes, pageImages)

	if config.EmbeddingClient != nil {
		allSummaries := collectSummaries(nodes)
		if len(allSummaries) > 0 {
			embeddings, err := config.EmbeddingClient.EmbedBatch(ctx, allSummaries)
			if err == nil && len(embeddings) > 0 {
				assignEmbeddings(nodes, embeddings)
			}
		}
	}

	compressedTokenCount := sumTokenCounts(nodes)
	fullTokenCount := sumSubtreeTokenCounts(nodes)

	tree := &SemanticTree{
		URL:                  url,
		Domain:               domain,
		Title:                title,
		RootNodes:            nodes,
		CompressedTokenCount: compressedTokenCount,
		FullTokenCount:       fullTokenCount,
		StructuralHash:       structuralHash,
		CreatedAt:            time.Now(),
		DynamicSlotsFilledAt: time.Now(),
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

func cleanAndParseHTML(htmlStr string) (string, *html.Node, error) {
	doc, err := html.Parse(strings.NewReader(htmlStr))
	if err != nil {
		return "", nil, NewParseError(err.Error())
	}
	cleaned := cleanHTMLNode(doc)
	return cleaned, doc, nil
}

func cleanHTMLNode(doc *html.Node) string {
	traverseAndClean(doc)
	return renderNode(doc)
}

func traverseAndClean(n *html.Node) {
	var remove []*html.Node

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if shouldRemoveNode(c) {
			remove = append(remove, c)
		}
	}

	for _, r := range remove {
		r.Parent.RemoveChild(r)
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		traverseAndClean(c)
	}
}

func shouldRemoveNode(n *html.Node) bool {
	if n.Type != html.ElementNode {
		return false
	}

	noiseTags := []string{"script", "style", "noscript", "meta", "link",
		"head", "iframe", "canvas", "video", "audio",
		"template", "slot", "svg", "path", "rect"}

	for _, tag := range noiseTags {
		if n.Data == tag {
			return true
		}
	}

	for _, attr := range n.Attr {
		if attr.Key == "style" {
			style := attr.Val
			if strings.Contains(style, "display: none") ||
				strings.Contains(style, "display:none") ||
				strings.Contains(style, "visibility: hidden") ||
				strings.Contains(style, "visibility:hidden") {
				return true
			}
		}
		if attr.Key == "aria-hidden" && attr.Val == "true" {
			text := extractTextContent(n)
			if len(text) < 3 && !hasInteractiveChildren(n) {
				return true
			}
		}
		for _, class := range []string{"hidden", "sr-only", "visually-hidden", "d-none"} {
			if attr.Key == "class" && strings.Contains(attr.Val, class) {
				return true
			}
		}
	}

	return false
}

func hasInteractiveChildren(n *html.Node) bool {
	var check func(node *html.Node) bool
	check = func(node *html.Node) bool {
		if node.Type == html.ElementNode {
			for _, tag := range []string{"a", "button", "input", "select", "textarea"} {
				if node.Data == tag {
					return true
				}
			}
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			if check(c) {
				return true
			}
		}
		return false
	}
	return check(n)
}

func extractTextContent(n *html.Node) string {
	var text strings.Builder
	var walk func(node *html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.TextNode {
			text.WriteString(node.Data)
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return strings.TrimSpace(text.String())
}

func renderNode(n *html.Node) string {
	var b strings.Builder
	renderNodeToBuilder(n, &b)
	return b.String()
}

func renderNodeToBuilder(n *html.Node, b *strings.Builder) {
	switch n.Type {
	case html.TextNode:
		b.WriteString(n.Data)
		return
	case html.ElementNode:
		b.WriteString("<")
		b.WriteString(n.Data)
		keepAttrs := []string{"href", "src", "alt", "title", "type", "name", "value",
			"placeholder", "id", "role", "aria-label", "for", "action",
			"method", "target", "rel", "selected", "checked", "disabled"}
		keepMap := make(map[string]bool)
		for _, a := range keepAttrs {
			keepMap[a] = true
		}
		for _, attr := range n.Attr {
			if keepMap[attr.Key] || !strings.HasPrefix(attr.Key, "data-") && attr.Key != "class" && attr.Key != "style" {
				fmt.Fprintf(b, " %s=\"%s\"", attr.Key, attr.Val)
			}
		}
		b.WriteString(">")

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			renderNodeToBuilder(c, b)
		}

		b.WriteString("</")
		b.WriteString(n.Data)
		b.WriteString(">")
	case html.DocumentNode:
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			renderNodeToBuilder(c, b)
		}
	}
}

func extractTitle(htmlStr string) string {
	doc, err := html.Parse(strings.NewReader(htmlStr))
	if err != nil {
		return ""
	}

	var findTitle func(n *html.Node) string
	findTitle = func(n *html.Node) string {
		if n.Type == html.ElementNode && n.Data == "title" {
			return extractTextContent(n)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if title := findTitle(c); title != "" {
				return title
			}
		}
		return ""
	}
	return findTitle(doc)
}

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

func hashElementRecursive(n *html.Node) string {
	tag := n.Data
	var classes []string
	for _, attr := range n.Attr {
		if attr.Key == "class" {
			classes = strings.Fields(attr.Val)
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

func chunkDOM(doc *html.Node, pageURL string) []DomChunk {
	body := findElement(doc, "body")
	if body == nil {
		return nil
	}

	var chunks []DomChunk
	tagCounts := make(map[string]int)

	for c := body.FirstChild; c != nil; c = c.NextSibling {
		if c.Type != html.ElementNode {
			continue
		}

		tag := c.Data
		tagCounts[tag]++
		nth := tagCounts[tag]

		var selector string
		if nth == 1 {
			selector = fmt.Sprintf("body > %s", tag)
		} else {
			selector = fmt.Sprintf("body > %s:nth-of-type(%d)", tag, nth)
		}

		if chunk := chunkNode(c, selector, tag, pageURL, 0); chunk != nil {
			chunks = append(chunks, *chunk)
		}
	}

	return chunks
}

func chunkNode(n *html.Node, selector, tag, pageURL string, depth int) *DomChunk {
	if tag == "div" || tag == "span" {
		children := elementChildren(n)
		directText := ""
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if c.Type == html.TextNode {
				directText += c.Data
			}
		}
		if len(children) == 1 && strings.TrimSpace(directText) == "" {
			child := children[0]
			childTag := child.Data
			childSelector := fmt.Sprintf("%s > %s", selector, childTag)
			return chunkNode(child, childSelector, childTag, pageURL, depth)
		}
	}

	outerHTML := renderNode(n)

	textContent := extractTextContent(n)
	if strings.TrimSpace(textContent) == "" {
		if !strings.Contains(outerHTML, "<img") &&
			!strings.Contains(outerHTML, "<input") &&
			!strings.Contains(outerHTML, "<button") &&
			!strings.Contains(outerHTML, "<a ") {
			return nil
		}
	}

	structuralHash := hashElementRecursive(n)
	images := extractImagesFromElement(n, pageURL)

	elementChildrenList := elementChildren(n)

	sectionTags := []string{"header", "footer", "nav", "main", "aside", "section", "article", "dialog", "form"}
	listTags := []string{"ul", "ol", "tbody", "dl"}

	shouldSplit := len(outerHTML) > 4000 ||
		contains(sectionTags, tag) ||
		contains(listTags, tag) ||
		isGridNode(n)

	if shouldSplit && depth < 8 && len(elementChildrenList) > 0 {
		var childChunks []DomChunk
		var inlinedChildrenHTML strings.Builder
		childTagCounts := make(map[string]int)

		for _, child := range elementChildrenList {
			childTag := child.Data
			childTagCounts[childTag]++
			nth := childTagCounts[childTag]

			var childSelector string
			if nth == 1 {
				childSelector = fmt.Sprintf("%s > %s", selector, childTag)
			} else {
				childSelector = fmt.Sprintf("%s > %s:nth-of-type(%d)", selector, childTag, nth)
			}

			childHTML := renderNode(child)
			if len(childHTML) >= 100 {
				if childChunk := chunkNode(child, childSelector, childTag, pageURL, depth+1); childChunk != nil {
					childChunks = append(childChunks, *childChunk)
				}
			} else {
				inlinedChildrenHTML.WriteString(childHTML)
			}
		}

		if len(childChunks) > 0 {
			shallowHTML := buildShallowHTML(n, inlinedChildrenHTML.String())
			return &DomChunk{
				Selector:       selector,
				Tag:            tag,
				HTML:           shallowHTML,
				StructuralHash: structuralHash,
				Children:       childChunks,
				Images:         images,
				Depth:          depth,
			}
		}
	}

	return &DomChunk{
		Selector:       selector,
		Tag:            tag,
		HTML:           outerHTML,
		StructuralHash: structuralHash,
		Images:         images,
		Depth:          depth,
	}
}

func elementChildren(n *html.Node) []*html.Node {
	var children []*html.Node
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode {
			children = append(children, c)
		}
	}
	return children
}

func buildShallowHTML(n *html.Node, inlinedChildren string) string {
	tag := n.Data

	var attrStr strings.Builder
	for _, attr := range n.Attr {
		attrStr.WriteString(fmt.Sprintf(" %s=\"%s\"", attr.Key, attr.Val))
	}

	directText := ""
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.TextNode {
			directText += c.Data + " "
		}
	}
	directText = strings.TrimSpace(directText)

	return fmt.Sprintf("<%s%s>%s%s</%s>", tag, attrStr.String(), directText, inlinedChildren, tag)
}

func isGridNode(n *html.Node) bool {
	children := elementChildren(n)
	count := len(children)
	if count < 4 {
		return false
	}

	tagCounts := make(map[string]int)
	for _, c := range children {
		tagCounts[c.Data]++
	}

	for _, cnt := range tagCounts {
		if float32(cnt)/float32(count) > 0.6 {
			return true
		}
	}
	return false
}

func contains(list []string, item string) bool {
	for _, i := range list {
		if i == item {
			return true
		}
	}
	return false
}

func countChunks(chunks []DomChunk) int {
	total := len(chunks)
	for _, c := range chunks {
		total += countChunks(c.Children)
	}
	return total
}

func compressChunksParallel(ctx context.Context, chunks []DomChunk, url string, config *PipelineConfig, stats *pipelineStats) ([]SemanticNode, error) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	nodes := make([]SemanticNode, len(chunks))
	errors := make([]error, len(chunks))

	for i, chunk := range chunks {
		wg.Add(1)
		go func(idx int, c DomChunk) {
			defer wg.Done()
			node, err := compressChunkRecursive(ctx, c, url, "", idx, config, stats)
			mu.Lock()
			if err != nil {
				errors[idx] = err
			} else {
				nodes[idx] = *node
			}
			mu.Unlock()
		}(i, chunk)
	}
	wg.Wait()

	for _, err := range errors {
		if err != nil {
			return nil, err
		}
	}

	return nodes, nil
}

func compressChunkRecursive(ctx context.Context, chunk DomChunk, url string, idPrefix string, index int, config *PipelineConfig, stats *pipelineStats) (*SemanticNode, error) {
	contentKey := ContentHash(chunk.HTML)

	if len(chunk.Children) == 0 {
		return compressLeafChunk(ctx, chunk, url, index, config, stats, contentKey)
	}

	var childNodes []SemanticNode
	var mu sync.Mutex
	var wg sync.WaitGroup
	childErrors := make([]error, len(chunk.Children))

	for i, child := range chunk.Children {
		wg.Add(1)
		go func(idx int, c DomChunk) {
			defer wg.Done()
			node, err := compressChunkRecursive(ctx, c, url, "", idx, config, stats)
			mu.Lock()
			if err != nil {
				childErrors[idx] = err
			} else {
				childNodes = append(childNodes, *node)
			}
			mu.Unlock()
		}(i, child)
	}
	wg.Wait()

	for _, err := range childErrors {
		if err != nil {
			return nil, err
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

func compressLeafChunk(ctx context.Context, chunk DomChunk, url string, index int, config *PipelineConfig, stats *pipelineStats, contentKey string) (*SemanticNode, error) {
	if config.Cache != nil {
		if cachedNode, err := config.Cache.GetChunk(ctx, contentKey); err == nil && cachedNode != nil {
			stats.recordCacheHit()
			cachedNode.ID = SelectorToID(chunk.Selector)
			cachedNode.DOMSelector = chunk.Selector
			return cachedNode, nil
		}
	}

	if config.LLMClient == nil {
		return buildNodeFromChunkNoLLM(chunk, index), nil
	}

	stats.recordLLMCall()

	matchedElements := matchInteractiveElements(chunk.HTML, extractInteractiveElements(chunk.HTML))

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
not the specific content itself.

Output a single JSON object with:
- "summary": STRUCTURAL description (5-20 tokens)
- "is_dynamic": true if content changes between visits
- "stable": true if this layout description stays the same even when children change

Already-compressed children:
%s

Output ONE JSON object. No markdown. No explanation.`, childContext.String())

	type parentResponse struct {
		Summary   string `json:"summary"`
		IsDynamic bool   `json:"is_dynamic"`
		Stable    bool   `json:"stable"`
	}

	var parsed parentResponse
	if err := config.LLMClient.CompleteJSON(ctx,
		"You compress HTML into structured JSON. Output valid JSON only. Never output markdown or commentary.",
		prompt, &parsed); err != nil {
		return nil, err
	}

	parentID := SelectorToID(chunk.Selector)
	summaryTokens := EstimateTokens(parsed.Summary)

	node := &SemanticNode{
		ID:                parentID,
		Summary:           parsed.Summary,
		StructuralHash:    chunk.StructuralHash,
		IsDynamic:         parsed.IsDynamic,
		DynamicSelector:   "",
		Children:          childNodes,
		Actions:           nil,
		Images:            chunk.Images,
		DOMSelector:       chunk.Selector,
		TokenCount:        summaryTokens,
		SubtreeTokenCount: summaryTokens + sumSubtreeTokenCounts(childNodes),
		Stable:            parsed.Stable,
	}

	if parsed.IsDynamic {
		node.DynamicSelector = chunk.Selector
	}

	return node, nil
}

func extractImagesFromDoc(doc *html.Node, pageURL string) []ImageRef {
	return extractImagesFromElement(doc, pageURL)
}

func extractImagesFromElement(n *html.Node, pageURL string) []ImageRef {
	var images []ImageRef
	var walk func(node *html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "img" {
			var src, alt string
			for _, attr := range node.Attr {
				switch attr.Key {
				case "src":
					src = attr.Val
				case "alt":
					alt = attr.Val
				}
			}
			if src != "" && !strings.HasPrefix(src, "data:") {
				url := resolveURL(src, pageURL)
				images = append(images, ImageRef{
					URL:     url,
					Alt:     alt,
					URLHash: ContentHash(url),
				})
			}
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return images
}

func resolveURL(src, pageURL string) string {
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		return src
	}
	if strings.HasPrefix(src, "//") {
		return "https:" + src
	}
	if strings.HasPrefix(src, "/") {
		parts := strings.SplitN(pageURL, "://", 2)
		if len(parts) > 1 {
			domain := strings.Split(parts[1], "/")[0]
			return fmt.Sprintf("%s://%s%s", parts[0], domain, src)
		}
	}
	return pageURL + "/" + src
}

func attachImagesToNodes(nodes []SemanticNode, images []ImageRef) {
	if len(images) == 0 || len(nodes) == 0 {
		return
	}

	perNode := len(images) / len(nodes)
	if perNode < 1 {
		perNode = 1
	}

	for i := range nodes {
		if len(images) == 0 {
			break
		}
		take := perNode
		if take > len(images) {
			take = len(images)
		}
		nodes[i].Images = append(nodes[i].Images, images[:take]...)
		images = images[take:]
	}

	if len(images) > 0 && len(nodes) > 0 {
		nodes[len(nodes)-1].Images = append(nodes[len(nodes)-1].Images, images...)
	}
}

func extractInteractiveElements(htmlStr string) []InteractiveElement {
	doc, err := html.Parse(strings.NewReader(htmlStr))
	if err != nil {
		return nil
	}

	var elements []InteractiveElement
	interactiveTags := []string{"a", "button", "input", "select", "textarea"}

	attrs := []string{"href", "aria-label", "title", "type", "name", "placeholder", "role", "value", "id"}

	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			for _, tag := range interactiveTags {
				if n.Data == tag {
					el := InteractiveElement{
						Tag:   tag,
						Attrs: make(map[string]string),
					}

					for _, attr := range n.Attr {
						for _, a := range attrs {
							if attr.Key == a {
								el.Attrs[a] = attr.Val
							}
						}
					}

					el.Selector = buildShortSelector(tag, n)
					if el.Selector != "" {
						switch tag {
						case "input", "textarea":
							inputType := el.Attrs["type"]
							switch inputType {
							case "checkbox", "radio":
								el.ActionType = "toggle"
							default:
								el.ActionType = "fill"
							}
						case "select":
							el.ActionType = "select"
						default:
							el.ActionType = "click"
						}
						elements = append(elements, el)
					}
					break
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	return elements
}

func buildShortSelector(tag string, n *html.Node) string {
	for _, attr := range n.Attr {
		if attr.Key == "id" && attr.Val != "" && !strings.Contains(attr.Val, " ") {
			return "#" + attr.Val
		}
	}

	if tag == "a" {
		for _, attr := range n.Attr {
			if attr.Key == "href" {
				href := attr.Val
				if href != "" && href != "#" && href != "/" {
					path := strings.Split(href, "?")[0]
					if len(path) > 1 {
						return fmt.Sprintf("a[href*='%s']", path)
					}
				}
			}
		}
	}

	for _, attr := range n.Attr {
		if attr.Key == "aria-label" && attr.Val != "" {
			return fmt.Sprintf("%s[aria-label='%s']", tag, attr.Val)
		}
		if attr.Key == "data-testid" && attr.Val != "" {
			return fmt.Sprintf("[data-testid='%s']", attr.Val)
		}
		if attr.Key == "name" && attr.Val != "" {
			return fmt.Sprintf("%s[name='%s']", tag, attr.Val)
		}
	}

	if tag == "input" || tag == "textarea" {
		for _, attr := range n.Attr {
			if attr.Key == "placeholder" && attr.Val != "" {
				return fmt.Sprintf("%s[placeholder*='%s']", tag, attr.Val)
			}
		}
	}

	return tag
}

func matchInteractiveElements(chunkHTML string, elements []InteractiveElement) []InteractiveElement {
	return elements
}

func buildActionFromInteractive(el InteractiveElement, desc string) Action {
	switch el.ActionType {
	case "fill":
		fieldType := FieldTypeText
		switch el.Attrs["type"] {
		case "password":
			fieldType = FieldTypePassword
		case "email":
			fieldType = FieldTypeEmail
		case "number":
			fieldType = FieldTypeNumber
		case "search":
			fieldType = FieldTypeSearch
		case "url":
			fieldType = FieldTypeURL
		}
		return Action{
			Type:        ActionFill,
			Selector:    el.Selector,
			Description: desc,
			FillOptions: &FillOptions{FieldType: fieldType},
		}
	case "select":
		return Action{
			Type:        ActionSelect,
			Selector:    el.Selector,
			Description: desc,
			SelectOpts:  &SelectOpts{},
		}
	case "toggle":
		return Action{
			Type:        ActionToggle,
			Selector:    el.Selector,
			Description: desc,
			ToggleState: new(bool),
		}
	default:
		return Action{
			Type:        ActionClick,
			Selector:    el.Selector,
			Description: desc,
		}
	}
}

func extractRawTextFromHTML(htmlStr string) string {
	doc, err := html.Parse(strings.NewReader(htmlStr))
	if err != nil {
		return ""
	}

	body := findElement(doc, "body")
	if body == nil {
		body = doc
	}

	text := extractTextContent(body)
	if strings.TrimSpace(text) == "" {
		return ""
	}

	return strings.Join(strings.Fields(text), " ")
}

func collectSummaries(nodes []SemanticNode) []string {
	var summaries []string
	for i := range nodes {
		summaries = append(summaries, collectNodeSummaries(&nodes[i])...)
	}
	return summaries
}

func collectNodeSummaries(node *SemanticNode) []string {
	summaries := []string{node.Summary}
	for i := range node.Children {
		summaries = append(summaries, collectNodeSummaries(&node.Children[i])...)
	}
	return summaries
}

func assignEmbeddings(nodes []SemanticNode, embeddings [][]float32) {
	idx := 0
	for i := range nodes {
		assignNodeEmbeddings(&nodes[i], embeddings, &idx)
	}
}

func assignNodeEmbeddings(node *SemanticNode, embeddings [][]float32, idx *int) {
	if *idx < len(embeddings) {
		node.Embedding = embeddings[*idx]
		*idx++
	}
	for i := range node.Children {
		assignNodeEmbeddings(&node.Children[i], embeddings, idx)
	}
}

func sumTokenCounts(nodes []SemanticNode) uint32 {
	var total uint32
	for i := range nodes {
		total += nodes[i].TokenCount
	}
	return total
}

func sumSubtreeTokenCounts(nodes []SemanticNode) uint32 {
	var total uint32
	for i := range nodes {
		total += nodes[i].SubtreeTokenCount
	}
	return total
}
