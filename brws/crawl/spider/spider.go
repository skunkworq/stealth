package spider

import (
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"

	"github.com/skunkworq/stealth/brws/browser/engine"
)

type Spider interface {
	Name() string
	Start() []*Request
	Parse(Response) []*Request
}

type FuncSpider struct {
	name  string
	start []*Request
	parse func(Response) []*Request
}

func NewSpider(name string, start []*Request, parse func(Response) []*Request) Spider {
	return &FuncSpider{
		name:  name,
		start: start,
		parse: parse,
	}
}

func (s *FuncSpider) Name() string {
	return s.name
}

func (s *FuncSpider) Start() []*Request {
	return s.start
}

func (s *FuncSpider) Parse(resp Response) []*Request {
	if s.parse != nil {
		return s.parse(resp)
	}
	return nil
}

type Request struct {
	URL         string
	Method      string
	Headers     map[string]string
	Body        []byte
	Callback    func(Response) []*Request
	Meta        map[string]interface{}
	Priority    int
	DontFilter  bool
	Depth       int
	ErrCallback func(error, Response)
}

func NewRequest(url string, callback func(Response) []*Request) *Request {
	return &Request{
		URL:        url,
		Method:     "GET",
		Callback:   callback,
		Meta:       make(map[string]interface{}),
		DontFilter: false,
	}
}

func NewFormRequest(urlStr string, formData map[string]string, callback func(Response) []*Request) *Request {
	parts := make([]string, 0, len(formData))
	for k, v := range formData {
		parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
	}
	body := strings.Join(parts, "&")

	return &Request{
		URL:      urlStr,
		Method:   "POST",
		Body:     []byte(body),
		Headers:  map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		Callback: callback,
		Meta:     make(map[string]interface{}),
	}
}

func NewJSONRequest(url string, data interface{}, callback func(Response) []*Request) *Request {
	body, _ := json.Marshal(data)
	return &Request{
		URL:      url,
		Method:   "POST",
		Body:     body,
		Headers:  map[string]string{"Content-Type": "application/json"},
		Callback: callback,
		Meta:     make(map[string]interface{}),
	}
}

func (r *Request) SetMethod(method string) *Request {
	r.Method = method
	return r
}

func (r *Request) SetBody(body []byte) *Request {
	r.Body = body
	return r
}

func (r *Request) SetHeader(key, value string) *Request {
	if r.Headers == nil {
		r.Headers = make(map[string]string)
	}
	r.Headers[key] = value
	return r
}

func (r *Request) SetMeta(key string, value interface{}) *Request {
	r.Meta[key] = value
	return r
}

func (r *Request) SetPriority(priority int) *Request {
	r.Priority = priority
	return r
}

func (r *Request) SetDontFilter(dontFilter bool) *Request {
	r.DontFilter = dontFilter
	return r
}

func (r *Request) SetDepth(depth int) *Request {
	r.Depth = depth
	return r
}

type Response struct {
	Request *Request
	Status  int
	Body    []byte
	Text    string
	URL     string
	Headers map[string]string
	Meta    map[string]interface{}
	Engine  string
	Timing  time.Duration
}

func (r *Response) Follow(url string) *Request {
	return NewRequest(url, nil).SetDepth(r.Request.Depth + 1)
}

func (r *Response) FollowAll(urls []string) []*Request {
	result := make([]*Request, len(urls))
	for i, url := range urls {
		result[i] = r.Follow(url)
	}
	return result
}

func (r *Response) GetMeta(key string) interface{} {
	if r.Meta != nil {
		return r.Meta[key]
	}
	if r.Request != nil {
		return r.Request.Meta[key]
	}
	return nil
}

func (r *Response) CSS(selector string) []Element {
	return r.queryCSS(selector)
}

func (r *Response) XPath(xpath string) []Element {
	return r.queryXPath(xpath)
}

func (r *Response) queryCSS(selector string) []Element {
	doc, err := html.Parse(strings.NewReader(r.Text))
	if err != nil {
		return nil
	}

	sel := normalizeSelector(selector)
	var results []Element

	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if matchesSelector(n, sel) {
			results = append(results, &htmlElement{node: n})
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return results
}

func (r *Response) queryXPath(xpath string) []Element {
	doc, err := html.Parse(strings.NewReader(r.Text))
	if err != nil {
		return nil
	}

	var results []Element
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		results = append(results, &htmlElement{node: n})
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return results
}

func normalizeSelector(sel string) string {
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

type Element = engine.HTMLElement

type htmlElement struct {
	node *html.Node
}

func (e *htmlElement) Text() string {
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

func (e *htmlElement) Attr(key string) string {
	for _, attr := range e.node.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}

func (e *htmlElement) AllAttr() map[string]string {
	result := make(map[string]string)
	for _, attr := range e.node.Attr {
		result[attr.Key] = attr.Val
	}
	return result
}

func (r *Response) GetTitle() string {
	els := r.CSS("title")
	if len(els) > 0 {
		return els[0].Text()
	}
	return ""
}

func (r *Response) GetLinks() []string {
	var links []string
	for _, a := range r.CSS("a") {
		href := a.Attr("href")
		if href != "" {
			links = append(links, href)
		}
	}
	return links
}

func (r *Response) GetImages() []string {
	var images []string
	for _, img := range r.CSS("img") {
		src := img.Attr("src")
		if src != "" {
			images = append(images, src)
		}
	}
	return images
}

func ToEngineRequest(req *Request) *engine.Request {
	headers := make(map[string][]string)
	for k, v := range req.Headers {
		headers[k] = []string{v}
	}
	return &engine.Request{
		Method:  req.Method,
		URL:     req.URL,
		Headers: headers,
		Body:    req.Body,
	}
}
