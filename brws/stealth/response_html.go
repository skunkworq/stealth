package stealth

import (
	"strings"

	"golang.org/x/net/html"
)

// HTMLElement represents a single HTML element node.
type HTMLElement struct {
	node *html.Node
}

// Text returns the visible text content of the element.
func (e *HTMLElement) Text() string {
	return collectText(e.node)
}

// Attr returns the value of the named attribute, or an empty string if absent.
func (e *HTMLElement) Attr(name string) string {
	for _, a := range e.node.Attr {
		if a.Key == name {
			return a.Val
		}
	}
	return ""
}

// HTMLDocument provides DOM-style querying over a parsed HTML response.
type HTMLDocument struct {
	root *html.Node
}

// QuerySelectorAll returns all elements matching the given CSS-style selector.
// Supported selectors: tag name (e.g. "div", "h1"), class (e.g. ".foo"),
// and ID (e.g. "#bar").  More complex selectors fall back to tag-name search.
func (d *HTMLDocument) QuerySelectorAll(selector string) []*HTMLElement {
	if d.root == nil {
		return nil
	}

	var results []*HTMLElement

	// Parse simple selector forms.
	switch {
	case strings.HasPrefix(selector, "."):
		className := selector[1:]
		walk(d.root, func(n *html.Node) bool {
			if n.Type == html.ElementNode {
				for _, a := range n.Attr {
					if a.Key == "class" && containsClass(a.Val, className) {
						results = append(results, &HTMLElement{node: n})
						return true
					}
				}
			}
			return false
		})
	case strings.HasPrefix(selector, "#"):
		id := selector[1:]
		walk(d.root, func(n *html.Node) bool {
			if n.Type == html.ElementNode {
				for _, a := range n.Attr {
					if a.Key == "id" && a.Val == id {
						results = append(results, &HTMLElement{node: n})
						return true
					}
				}
			}
			return false
		})
	default:
		// Tag name search.
		walk(d.root, func(n *html.Node) bool {
			if n.Type == html.ElementNode && n.Data == selector {
				results = append(results, &HTMLElement{node: n})
				return true
			}
			return false
		})
	}

	return results
}

// QuerySelector returns the first element matching the selector, or nil.
func (d *HTMLDocument) QuerySelector(selector string) *HTMLElement {
	all := d.QuerySelectorAll(selector)
	if len(all) > 0 {
		return all[0]
	}
	return nil
}

// AsHTML parses the response body as an HTML document, returning a
// queryable DOM wrapper.
//
// When to use AsHTML vs. content/understand.SemanticTree:
//   - AsHTML: lightweight DOM queries — link extraction, form detection,
//     quick text checks, or any use-case that doesn't need token budgeting.
//   - SemanticTree: passing the page to an LLM, semantic search, or
//     any context where token count matters. SemanticTree compresses and
//     annotates the page structure (30–60% token reduction) and builds
//     a vector index for retrieval; AsHTML skips all of that overhead.
func (r *Response) AsHTML() (*HTMLDocument, error) {
	r.ensureParsed()
	if r.doc == nil {
		return nil, nil
	}
	return &HTMLDocument{root: r.doc}, nil
}

// walk traverses the HTML tree depth-first, calling fn on each node.
// If fn returns true the node is collected but traversal continues.
func walk(n *html.Node, fn func(*html.Node) bool) {
	if fn(n) {
		// collected
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walk(c, fn)
	}
}

// containsClass checks whether classAttr contains the given class name.
func containsClass(classAttr, class string) bool {
	classes := strings.Fields(classAttr)
	for _, c := range classes {
		if c == class {
			return true
		}
	}
	return false
}
