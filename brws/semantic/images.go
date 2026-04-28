package semantic

import (
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// ExtractImagesFromDoc extracts images from the HTML document.
func ExtractImagesFromDoc(doc *html.Node, pageURL string) []ImageRef {
	var images []ImageRef
	body := findElement(doc, "body")
	if body == nil {
		return images
	}

	var extract func(n *html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "img" {
			img := extractImageFromNode(n, pageURL)
			if img.URL != "" {
				images = append(images, img)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}
	extract(body)

	return images
}

// extractImagesFromElement extracts images from an element.
func extractImagesFromElement(n *html.Node, pageURL string) []ImageRef {
	var images []ImageRef

	var extract func(node *html.Node)
	extract = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "img" {
			img := extractImageFromNode(node, pageURL)
			if img.URL != "" {
				images = append(images, img)
			}
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}
	extract(n)

	return images
}

// extractImageFromNode extracts image data from an img node.
func extractImageFromNode(n *html.Node, pageURL string) ImageRef {
	img := ImageRef{}

	for _, attr := range n.Attr {
		switch attr.Key {
		case "src":
			img.URL = resolveURL(attr.Val, pageURL)
			img.URLHash = ContentHash(img.URL)
		case "alt":
			img.Alt = attr.Val
		}
	}

	return img
}

// resolveURL resolves a relative URL against a base URL.
func resolveURL(href, base string) string {
	if href == "" {
		return ""
	}

	// Already absolute
	if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") || strings.HasPrefix(href, "data:") {
		return href
	}

	// Protocol-relative
	if strings.HasPrefix(href, "//") {
		if strings.HasPrefix(base, "https://") {
			return "https:" + href
		}
		return "http:" + href
	}

	// Parse base URL
	baseURL, err := url.Parse(base)
	if err != nil {
		return href
	}

	// Resolve relative URL
	refURL, err := url.Parse(href)
	if err != nil {
		return href
	}

	resolved := baseURL.ResolveReference(refURL)
	return resolved.String()
}

// attachImagesToNodes attaches images to semantic nodes based on selectors.
func attachImagesToNodes(nodes []SemanticNode, images []ImageRef) {
	// For now, images are stored at the chunk level
	// In a full implementation, this would distribute images to the most relevant nodes
}

// extractCSSImages extracts image URLs from CSS background properties.
func extractCSSImages(css string) []string {
	var urls []string

	// Match url(...) patterns
	pattern := regexp.MustCompile(`url\(["']?([^"')]+)["']?\)`)
	matches := pattern.FindAllStringSubmatch(css, -1)

	for _, match := range matches {
		if len(match) >= 2 {
			urls = append(urls, match[1])
		}
	}

	return urls
}
