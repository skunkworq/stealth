package understand

import (
	"fmt"
	"strings"

	"golang.org/x/net/html"
)

// Noise tags that should be removed during cleaning.
var noiseTags = []string{
	"script", "style", "noscript", "meta", "link",
	"head", "iframe", "canvas", "video", "audio",
	"template", "slot", "svg", "path", "rect",
}

// Hidden class names that indicate content should be removed.
var hiddenClasses = []string{
	"hidden", "sr-only", "visually-hidden", "d-none",
}

// Attributes to keep when rendering cleaned HTML.
var keepAttrs = []string{
	"href", "src", "alt", "title", "type", "name", "value",
	"placeholder", "id", "role", "aria-label", "for", "action",
	"method", "target", "rel", "selected", "checked", "disabled",
}

// cleanAndParseHTML parses HTML and returns cleaned HTML, the document, and title.
func cleanAndParseHTML(htmlStr string) (string, *html.Node, string, error) {
	doc, err := html.Parse(strings.NewReader(htmlStr))
	if err != nil {
		return "", nil, "", NewParseError(err.Error())
	}
	title := findTitleInDoc(doc)
	cleaned := cleanHTMLNode(doc)
	return cleaned, doc, title, nil
}

// findTitleInDoc extracts the title from the HTML document.
func findTitleInDoc(doc *html.Node) string {
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

// cleanHTMLNode cleans the HTML document by removing noise tags.
func cleanHTMLNode(doc *html.Node) string {
	traverseAndClean(doc)
	return renderNode(doc)
}

// traverseAndClean recursively removes noise nodes from the document.
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

// shouldRemoveNode determines if a node should be removed during cleaning.
func shouldRemoveNode(n *html.Node) bool {
	if n.Type != html.ElementNode {
		return false
	}

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
		for _, class := range hiddenClasses {
			if attr.Key == "class" && strings.Contains(attr.Val, class) {
				return true
			}
		}
	}

	return false
}

// hasInteractiveChildren checks if a node has interactive child elements.
func hasInteractiveChildren(n *html.Node) bool {
	interactiveTags := []string{"a", "button", "input", "select", "textarea"}

	var check func(node *html.Node) bool
	check = func(node *html.Node) bool {
		if node.Type == html.ElementNode {
			for _, tag := range interactiveTags {
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

// extractTextContent extracts all text content from a node.
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

// renderNode renders an HTML node back to string.
func renderNode(n *html.Node) string {
	var b strings.Builder
	renderNodeToBuilder(n, &b)
	return b.String()
}

// renderNodeToBuilder renders a node to a string builder.
func renderNodeToBuilder(n *html.Node, b *strings.Builder) {
	switch n.Type {
	case html.TextNode:
		b.WriteString(n.Data)
		return
	case html.ElementNode:
		b.WriteString("<")
		b.WriteString(n.Data)

		keepMap := make(map[string]bool)
		for _, a := range keepAttrs {
			keepMap[a] = true
		}
		for _, attr := range n.Attr {
			if keepMap[attr.Key] || (!strings.HasPrefix(attr.Key, "data-") && attr.Key != "class" && attr.Key != "style") {
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

// extractRawTextFromHTML extracts raw text from HTML string.
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
