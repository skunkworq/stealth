package scrapegraph

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/net/html"

	"github.com/skunkworq/stealth/brws/browser/engine"
	"github.com/skunkworq/stealth/brws/stealth"
)

// ---------------------------------------------------------------------------
// FetchNode
// ---------------------------------------------------------------------------

// FetchNode ingests content from URLs or local files.
//
// Fetch priority for web URLs:
//  1. StealthClient — full challenge-solving stack (Cloudflare, DataDome, etc.)
//  2. Engine — any registered engine (native, chromium, chromium-stealth, firefox, webkit)
//  3. Default — native engine created inline
type FetchNode struct {
	Base         baseNode
	Engine       engine.Engine // optional; overrides default native engine
	Timeout      int           // seconds
	BrowserBase  map[string]interface{}
	ScrapeDo     map[string]interface{}
	StorageState string

	// StealthClient optionally provides challenge-aware, anti-detect fetching.
	// Takes precedence over Engine when set.
	StealthClient *stealth.Adaptive
}

// NewFetchNode creates a FetchNode.
func NewFetchNode(input, output string, nodeConfig map[string]interface{}) *FetchNode {
	return &FetchNode{
		Base: baseNode{
			nodeName:   "FetchNode",
			nodeType:   "node",
			inputExpr:  input,
			output:     []string{output},
			minInputs:  1,
			nodeConfig: nodeConfig,
		},
		Timeout: 30,
	}
}

func (n *FetchNode) Name() string      { return n.Base.nodeName }
func (n *FetchNode) NodeType() string  { return n.Base.nodeType }
func (n *FetchNode) InputExpr() string { return n.Base.inputExpr }
func (n *FetchNode) Outputs() []string { return n.Base.output }
func (n *FetchNode) MinInputs() int    { return n.Base.minInputs }

func (n *FetchNode) Execute(ctx context.Context, state State) (State, string, error) {
	keys, err := ParseInputKeys(state, n.Base.inputExpr)
	if err != nil {
		return state, "", fmt.Errorf("parse input: %w", err)
	}
	if len(keys) < n.Base.minInputs {
		return state, "", fmt.Errorf("fetch node requires at least %d inputs, got %d", n.Base.minInputs, len(keys))
	}

	source, _ := state[keys[0]].(string)
	inputType := keys[0]

	var docs []Document

	switch {
	case inputType == "url" && (strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://")):
		docs, err = n.fetchWeb(ctx, source)
	case inputType == "local_dir" || inputType == "file":
		docs, err = n.fetchLocal(source)
	default:
		// Treat as raw content already in state
		docs = []Document{{PageContent: source, Metadata: map[string]string{"source": inputType}}}
	}

	if err != nil {
		return state, "", err
	}

	out := state.Clone()
	out[n.Base.output[0]] = docs
	out["doc"] = docs

	// Promote challenge metadata from first document to graph state so
	// ConditionalNode can branch on it.
	if len(docs) > 0 {
		if v, ok := docs[0].Metadata["challenge_solved"]; ok {
			out["challenge_solved"] = v == "true"
		}
		if v, ok := docs[0].Metadata["challenge_detected"]; ok {
			out["challenge_detected"] = v == "true"
		}
	}

	return out, "", nil
}

func (n *FetchNode) fetchWeb(ctx context.Context, source string) ([]Document, error) {
	var content string
	var meta map[string]string

	timeout := time.Duration(n.Timeout) * time.Second

	if n.StealthClient != nil {
		resp, err := n.StealthClient.Navigate(ctx, source)
		if err != nil {
			return nil, fmt.Errorf("stealth fetch: %w", err)
		}
		content = string(resp.Body)
		meta = map[string]string{
			"source":             source,
			"final_url":          resp.FinalURL,
			"challenge_solved":   fmt.Sprintf("%v", resp.ChallengeSolved),
			"challenge_detected": fmt.Sprintf("%v", resp.ChallengeSolved),
		}
	} else {
		eng := n.Engine
		if eng == nil {
			var err error
			eng, err = engine.New("native", engine.Options{Timeout: timeout, HTTP2: true})
			if err != nil {
				return nil, fmt.Errorf("create engine: %w", err)
			}
			defer eng.Close()
		}
		resp, err := eng.Do(ctx, &engine.Request{
			Method:          "GET",
			URL:             source,
			FollowRedirects: true,
			Timeout:         timeout,
		})
		if err != nil {
			return nil, fmt.Errorf("engine fetch: %w", err)
		}
		content = string(resp.Body)
		finalURL := resp.FinalURL
		if finalURL == "" {
			finalURL = source
		}
		meta = map[string]string{
			"source":    source,
			"final_url": finalURL,
			"status":    fmt.Sprintf("%d", resp.Status),
		}
	}

	// Simple HTML cleanup: if it looks like HTML, extract text.
	if strings.Contains(content, "<html") || strings.Contains(content, "<!DOCTYPE") {
		content = htmlToText(content)
	}

	return []Document{{PageContent: content, Metadata: meta}}, nil
}

func (n *FetchNode) fetchLocal(source string) ([]Document, error) {
	data, err := os.ReadFile(filepath.Clean(source))
	if err != nil {
		return nil, err
	}
	content := string(data)
	ext := filepath.Ext(source)
	if ext == ".html" || ext == ".htm" {
		content = htmlToText(content)
	}
	return []Document{{PageContent: content, Metadata: map[string]string{"source": source}}}, nil
}

// Document is the canonical content container.
type Document struct {
	PageContent string            `json:"page_content"`
	Metadata    map[string]string `json:"metadata"`
}

// ---------------------------------------------------------------------------
// ParseNode
// ---------------------------------------------------------------------------

// ParseNode transforms raw documents into token-sized chunks.
type ParseNode struct {
	Base      baseNode
	ChunkSize int
	ParseHTML bool
	ParseURLs bool
}

// NewParseNode creates a ParseNode.
func NewParseNode(input, output string, chunkSize int, nodeConfig map[string]interface{}) *ParseNode {
	parseHTML := true
	if v, ok := nodeConfig["parse_html"].(bool); ok {
		parseHTML = v
	}
	parseURLs := false
	if v, ok := nodeConfig["parse_urls"].(bool); ok {
		parseURLs = v
	}
	return &ParseNode{
		Base: baseNode{
			nodeName:   "ParseNode",
			nodeType:   "node",
			inputExpr:  input,
			output:     []string{output},
			minInputs:  1,
			nodeConfig: nodeConfig,
		},
		ChunkSize: chunkSize,
		ParseHTML: parseHTML,
		ParseURLs: parseURLs,
	}
}

func (n *ParseNode) Name() string      { return n.Base.nodeName }
func (n *ParseNode) NodeType() string  { return n.Base.nodeType }
func (n *ParseNode) InputExpr() string { return n.Base.inputExpr }
func (n *ParseNode) Outputs() []string { return n.Base.output }
func (n *ParseNode) MinInputs() int    { return n.Base.minInputs }

func (n *ParseNode) Execute(ctx context.Context, state State) (State, string, error) {
	keys, err := ParseInputKeys(state, n.Base.inputExpr)
	if err != nil {
		return state, "", fmt.Errorf("parse input: %w", err)
	}
	if len(keys) == 0 {
		return state, "", fmt.Errorf("parse node missing required input")
	}

	docs, ok := state[keys[0]].([]Document)
	if !ok || len(docs) == 0 {
		return state, "", fmt.Errorf("parse node expects []Document in %q", keys[0])
	}

	text := docs[0].PageContent
	if n.ParseHTML {
		text = htmlToText(text)
	}

	// Token-aware chunk sizing: reserve overhead for prompt.
	effectiveSize := n.ChunkSize - 250
	if effectiveSize < 100 {
		effectiveSize = n.ChunkSize
	}
	chunks := splitText(text, effectiveSize)

	out := state.Clone()
	out[n.Base.output[0]] = chunks
	out[StateKeyParsedDoc] = chunks

	if n.ParseURLs {
		links, imgs := extractURLs(text)
		out["link_urls"] = links
		out["img_urls"] = imgs
	}

	return out, "", nil
}

// ---------------------------------------------------------------------------
// HTML helpers
// ---------------------------------------------------------------------------

func htmlToText(input string) string {
	doc, err := html.Parse(strings.NewReader(input))
	if err != nil {
		return input
	}
	var buf strings.Builder
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.TextNode {
			buf.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
		if n.Type == html.ElementNode {
			switch n.Data {
			case "br", "p", "div", "h1", "h2", "h3", "h4", "h5", "h6", "li", "tr":
				buf.WriteByte('\n')
			}
		}
	}
	f(doc)
	// Collapse multiple newlines
	lines := strings.Split(buf.String(), "\n")
	var out []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

func extractURLs(text string) (links, images []string) {
	doc, err := html.Parse(strings.NewReader(text))
	if err != nil {
		return nil, nil
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, a := range n.Attr {
				if a.Key == "href" {
					links = append(links, a.Val)
				}
			}
		}
		if n.Type == html.ElementNode && n.Data == "img" {
			for _, a := range n.Attr {
				if a.Key == "src" {
					images = append(images, a.Val)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return links, images
}

// splitText breaks text into chunks of roughly maxChars, preferring sentence
// and word boundaries.
func splitText(text string, maxChars int) []string {
	if maxChars <= 0 {
		maxChars = 4000
	}
	var chunks []string
	runes := []rune(text)
	for len(runes) > 0 {
		if len(runes) <= maxChars {
			chunks = append(chunks, string(runes))
			break
		}
		cut := maxChars
		// Try to cut at newline, then period+space, then space.
		for i := cut; i > cut/2; i-- {
			if runes[i] == '\n' {
				cut = i + 1
				break
			}
		}
		if cut == maxChars {
			for i := cut; i > cut/2; i-- {
				if runes[i] == '.' && i+1 < len(runes) && runes[i+1] == ' ' {
					cut = i + 2
					break
				}
			}
		}
		if cut == maxChars {
			for i := cut; i > cut/2; i-- {
				if runes[i] == ' ' {
					cut = i + 1
					break
				}
			}
		}
		chunks = append(chunks, string(runes[:cut]))
		runes = runes[cut:]
	}
	return chunks
}

// baseNode holds the common fields for every node to avoid repetition.
type baseNode struct {
	nodeName   string
	nodeType   string
	inputExpr  string
	output     []string
	minInputs  int
	nodeConfig map[string]interface{}
}

// safeURLJoin resolves a possibly relative href against a base URL.
func safeURLJoin(base, href string) string {
	b, err := url.Parse(base)
	if err != nil {
		return href
	}
	u, err := url.Parse(href)
	if err != nil {
		return href
	}
	return b.ResolveReference(u).String()
}

// approxTokenCount gives a very rough token estimate (1 token ≈ 4 runes for
// latin text; 1 token ≈ 1 rune for CJK).
func approxTokenCount(s string) int {
	tokens := 0
	for _, r := range s {
		if utf8.RuneLen(r) > 2 {
			tokens++
		} else {
			tokens += 1 // will be divided
		}
	}
	return tokens/4 + 1
}
