package semantic

import (
	"fmt"
	"strings"

	"golang.org/x/net/html"
)

// Section tags that should trigger chunk splitting.
var sectionTags = []string{
	"header", "footer", "nav", "main", "aside", "section", "article", "dialog", "form",
}

// List tags that should trigger chunk splitting.
var listTags = []string{
	"ul", "ol", "tbody", "dl",
}

// chunkDOM chunks the DOM into processable segments.
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

// chunkNode recursively chunks a DOM node.
func chunkNode(n *html.Node, selector, tag, pageURL string, depth int) *DomChunk {
	// Skip wrapper divs/spans with single children
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

	// Determine if we should split this node into child chunks
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

// elementChildren returns the element children of a node.
func elementChildren(n *html.Node) []*html.Node {
	var children []*html.Node
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode {
			children = append(children, c)
		}
	}
	return children
}

// buildShallowHTML creates shallow HTML with inlined children.
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

// isGridNode checks if a node appears to be a grid/list container.
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

// countChunks counts total chunks including nested children.
func countChunks(chunks []DomChunk) int {
	total := len(chunks)
	for _, c := range chunks {
		total += countChunks(c.Children)
	}
	return total
}

// contains checks if a string slice contains an item.
func contains(list []string, item string) bool {
	for _, i := range list {
		if i == item {
			return true
		}
	}
	return false
}
