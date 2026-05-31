package collect

import (
	"strings"

	"golang.org/x/net/html"
)

var skipTags = map[string]bool{
	"script": true, "style": true, "head": true, "noscript": true,
	"template": true, "svg": true,
}

var blockTags = map[string]bool{
	"p": true, "div": true, "br": true, "li": true, "tr": true,
	// td/th are separated too: contact pages often lay out phone/address
	// across adjacent table cells, and without a boundary "0412" + "345 678"
	// would concatenate and fail the verbatim match.
	"td": true, "th": true,
	"section": true, "article": true, "h1": true, "h2": true,
	"h3": true, "h4": true, "h5": true, "h6": true,
}

// visibleText renders the human-visible text of an HTML document: script/style/
// head are dropped, block elements become line breaks, whitespace is collapsed.
func visibleText(rawHTML string) string {
	node, err := html.Parse(strings.NewReader(rawHTML))
	if err != nil {
		return ""
	}
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && skipTags[n.Data] {
			return
		}
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
		if n.Type == html.ElementNode && blockTags[n.Data] {
			b.WriteByte('\n')
		}
	}
	walk(node)
	var out []string
	for _, ln := range strings.Split(b.String(), "\n") {
		if ln = strings.Join(strings.Fields(ln), " "); ln != "" {
			out = append(out, ln)
		}
	}
	return strings.Join(out, "\n")
}
