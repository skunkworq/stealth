package engine

import (
	"encoding/json"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

type TextResponse struct {
	*Response
	Text string
}

func NewTextResponse(resp *Response) *TextResponse {
	return &TextResponse{
		Response: resp,
		Text:     string(resp.Body),
	}
}

func (r *TextResponse) Json() (map[string]interface{}, error) {
	var result map[string]interface{}
	err := json.Unmarshal(r.Body, &result)
	return result, err
}

func (r *TextResponse) JsonP(path string) (interface{}, error) {
	return nil, nil
}

type HtmlResponse struct {
	*TextResponse
	doc *html.Node
}

func NewHtmlResponse(resp *Response) *HtmlResponse {
	hr := &HtmlResponse{
		TextResponse: NewTextResponse(resp),
	}
	hr.parseHtml()
	return hr
}

func (r *HtmlResponse) parseHtml() {
	doc, err := html.Parse(strings.NewReader(r.Text))
	if err == nil {
		r.doc = doc
	}
}

func (r *HtmlResponse) CSS(selector string) []HtmlElement {
	if r.doc == nil {
		return nil
	}
	return r.queryCSS(selector)
}

func (r *HtmlResponse) XPath(xpathExpr string) []HtmlElement {
	if r.doc == nil {
		return nil
	}
	return r.queryXPath(xpathExpr)
}

func (r *HtmlResponse) queryCSS(selector string) []HtmlElement {
	var results []HtmlElement
	sel := normalizeCSS(selector)

	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if matchesSelector(n, sel) {
			results = append(results, &htmlNode{n})
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(r.doc)
	return results
}

func (r *HtmlResponse) queryXPath(xpath string) []HtmlElement {
	var results []HtmlElement
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		results = append(results, &htmlNode{n})
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(r.doc)
	return results
}

func normalizeCSS(sel string) string {
	sel = strings.TrimSpace(sel)
	sel = strings.TrimPrefix(sel, ".")
	sel = strings.TrimPrefix(sel, "#")
	return sel
}

func matchesSelector(n *html.Node, sel string) bool {
	if n.Type != html.ElementNode {
		return false
	}
	tagName := atom.Lookup([]byte(strings.ToLower(n.Data)))
	switch sel {
	case "a", "a[href]":
		return tagName == atom.A
	case "img":
		return tagName == atom.Img
	case "div":
		return tagName == atom.Div
	case "span":
		return tagName == atom.Span
	case "p":
		return tagName == atom.P
	case "form":
		return tagName == atom.Form
	case "input":
		return tagName == atom.Input
	case "button":
		return tagName == atom.Button
	case "script":
		return tagName == atom.Script
	case "style":
		return tagName == atom.Style
	case "link":
		return tagName == atom.Link
	case "meta":
		return tagName == atom.Meta
	case "title":
		return tagName == atom.Title
	case "body":
		return tagName == atom.Body
	case "head":
		return tagName == atom.Head
	case "h1":
		return tagName == atom.H1
	case "h2":
		return tagName == atom.H2
	case "h3":
		return tagName == atom.H3
	case "ul":
		return tagName == atom.Ul
	case "ol":
		return tagName == atom.Ol
	case "li":
		return tagName == atom.Li
	case "table":
		return tagName == atom.Table
	case "tr":
		return tagName == atom.Tr
	case "td", "th":
		return tagName == atom.Td || tagName == atom.Th
	}
	return strings.EqualFold(n.Data, sel)
}

type HtmlElement interface {
	Text() string
	Attr(key string) string
	AllAttr() map[string]string
}

type htmlNode struct {
	node *html.Node
}

func (e *htmlNode) Text() string {
	var sb strings.Builder
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			sb.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(e.node)
	return sb.String()
}

func (e *htmlNode) Attr(key string) string {
	for _, attr := range e.node.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}

func (e *htmlNode) AllAttr() map[string]string {
	result := make(map[string]string)
	for _, attr := range e.node.Attr {
		result[attr.Key] = attr.Val
	}
	return result
}

func (r *HtmlResponse) GetTitle() string {
	title := r.xpathFirst(".//title")
	if title != nil {
		return title.Text()
	}
	return ""
}

func (r *HtmlResponse) GetLinks() []string {
	var links []string
	for _, a := range r.xpathAll(".//a[@href]") {
		href := a.Attr("href")
		if href != "" {
			links = append(links, href)
		}
	}
	return links
}

func (r *HtmlResponse) GetImages() []string {
	var images []string
	for _, img := range r.xpathAll(".//img[@src]") {
		src := img.Attr("src")
		if src != "" {
			images = append(images, src)
		}
	}
	return images
}

func (r *HtmlResponse) GetMeta() map[string]string {
	meta := make(map[string]string)
	for _, m := range r.xpathAll(".//meta[@name or @property]") {
		name := m.Attr("name")
		if name == "" {
			name = m.Attr("property")
		}
		content := m.Attr("content")
		if name != "" && content != "" {
			meta[name] = content
		}
	}
	return meta
}

func (r *HtmlResponse) xpathFirst(xpath string) HtmlElement {
	results := r.xpathAll(xpath)
	if len(results) > 0 {
		return results[0]
	}
	return nil
}

func (r *HtmlResponse) xpathAll(xpath string) []HtmlElement {
	if r.doc == nil {
		return nil
	}
	var results []HtmlElement
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		results = append(results, &htmlNode{n})
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(r.doc)
	return results
}

func (r *HtmlResponse) GetForms() []FormInfo {
	var forms []FormInfo
	for _, f := range r.xpathAll(".//form") {
		form := extractFormInfo(f.(*htmlNode))
		if form != nil {
			forms = append(forms, *form)
		}
	}
	return forms
}

type FormInfo struct {
	Action string
	Method string
	Fields []FormField
}

type FormField struct {
	Name     string
	Type     string
	Value    string
	Required bool
}

func extractFormInfo(n *htmlNode) *FormInfo {
	form := &FormInfo{
		Action: n.Attr("action"),
		Method: n.Attr("method"),
	}
	if form.Method == "" {
		form.Method = "get"
	}

	var walk func(node *html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode {
			tagName := atom.Lookup([]byte(strings.ToLower(node.Data)))
			if tagName == atom.Input || tagName == atom.Textarea || tagName == atom.Select {
				field := FormField{
					Name:  getAttr(node, "name"),
					Type:  getAttr(node, "type"),
					Value: getAttr(node, "value"),
				}
				if field.Type == "" {
					if tagName == atom.Textarea {
						field.Type = "textarea"
					} else if tagName == atom.Select {
						field.Type = "select"
					} else {
						field.Type = "text"
					}
				}
				hasRequired := getAttr(node, "required")
				field.Required = hasRequired != ""
				form.Fields = append(form.Fields, field)
			}
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n.node)
	return form
}

func getAttr(n *html.Node, key string) string {
	for _, attr := range n.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}
