// Package main provides an MCP server for Claude Desktop integration.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/skunkworq/stealth/brws/browser/engine"
	_ "github.com/skunkworq/stealth/brws/browser/engine/http/native"
	"github.com/skunkworq/stealth/brws/content/semantic"
)

type MCPRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      interface{}     `json:"id,omitempty"`
}

type MCPResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *MCPError       `json:"error,omitempty"`
	ID      interface{}     `json:"id,omitempty"`
}

type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema InputSchema `json:"inputSchema"`
}

type InputSchema struct {
	Type       string              `json:"type"`
	Properties map[string]Property `json:"properties,omitempty"`
	Required   []string            `json:"required,omitempty"`
}

type Property struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

var (
	engineName = "native"
	eng        engine.Engine
	engMutex   sync.Mutex
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("MCP server error: %v", err)
	}
}

func run() error {
	decoder := json.NewDecoder(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)

	for {
		var req MCPRequest
		if err := decoder.Decode(&req); err != nil {
			if err.Error() == "EOF" {
				return nil
			}
			log.Printf("Decode error: %v", err)
			continue
		}

		resp := handleRequest(req)
		if err := encoder.Encode(resp); err != nil {
			log.Printf("Encode error: %v", err)
		}
	}
}

func handleRequest(req MCPRequest) MCPResponse {
	switch req.Method {
	case "initialize":
		return handleInitialize(req)
	case "tools/list":
		return handleToolsList(req)
	case "tools/call":
		return handleToolsCall(req)
	default:
		return MCPResponse{
			JSONRPC: "2.0",
			Error: &MCPError{
				Code:    -32601,
				Message: "Method not found",
			},
			ID: req.ID,
		}
	}
}

func handleInitialize(req MCPRequest) MCPResponse {
	result := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities": map[string]interface{}{
			"tools": true,
		},
		"serverInfo": map[string]string{
			"name":    "stealth-mcp",
			"version": "0.1.0",
		},
	}

	resultBytes, _ := json.Marshal(result)
	return MCPResponse{
		JSONRPC: "2.0",
		Result:  resultBytes,
		ID:      req.ID,
	}
}

func handleToolsList(req MCPRequest) MCPResponse {
	tools := []Tool{
		{
			Name:        "stealth_fetch",
			Description: "Fetch a URL and extract semantic tree. Returns structured data with title, nodes, actions, and token compression stats.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"url": {
						Type:        "string",
						Description: "URL to fetch",
					},
				},
				Required: []string{"url"},
			},
		},
		{
			Name:        "stealth_search",
			Description: "Search for content within a previously fetched page using CSS selector or text search.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"query": {
						Type:        "string",
						Description: "CSS selector or text to search for",
					},
				},
				Required: []string{"query"},
			},
		},
		{
			Name:        "stealth_links",
			Description: "Extract all links from the last fetched page.",
			InputSchema: InputSchema{
				Type:       "object",
				Properties: map[string]Property{},
			},
		},
		{
			Name:        "stealth_forms",
			Description: "Extract all forms from the last fetched page.",
			InputSchema: InputSchema{
				Type:       "object",
				Properties: map[string]Property{},
			},
		},
	}

	toolsBytes, _ := json.Marshal(tools)
	return MCPResponse{
		JSONRPC: "2.0",
		Result:  toolsBytes,
		ID:      req.ID,
	}
}

var (
	lastTree *semantic.SemanticTree
	lastURL  string
)

func handleToolsCall(req MCPRequest) MCPResponse {
	var params struct {
		Name string          `json:"name"`
		Args json.RawMessage `json:"arguments,omitempty"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return errorResponse(req.ID, -32602, "Invalid params")
	}

	var result json.RawMessage
	var err error

	switch params.Name {
	case "stealth_fetch":
		result, err = toolFetch(params.Args)
	case "stealth_search":
		result, err = toolSearch(params.Args)
	case "stealth_links":
		result, err = toolLinks()
	case "stealth_forms":
		result, err = toolForms()
	default:
		return errorResponse(req.ID, -32601, "Tool not found: "+params.Name)
	}

	if err != nil {
		return errorResponse(req.ID, -32000, err.Error())
	}

	return MCPResponse{
		JSONRPC: "2.0",
		Result:  result,
		ID:      req.ID,
	}
}

func errorResponse(id interface{}, code int, msg string) MCPResponse {
	// Note: errBytes reserved for future logging
	return MCPResponse{
		JSONRPC: "2.0",
		Error:   &MCPError{Code: code, Message: msg},
		ID:      id,
	}
}

func getEngine() (engine.Engine, error) {
	engMutex.Lock()
	defer engMutex.Unlock()

	if eng != nil {
		return eng, nil
	}

	e, err := engine.New(engineName, engine.Options{
		Stealth:     true,
		StealthTLS:  true,
		ProfileName: "chrome-120-macos",
		Timeout:     30,
	})
	if err != nil {
		return nil, err
	}
	eng = e
	return eng, nil
}

func toolFetch(args json.RawMessage) (json.RawMessage, error) {
	var params struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}

	if params.URL == "" {
		return nil, fmt.Errorf("url is required")
	}

	eng, err := getEngine()
	if err != nil {
		return nil, fmt.Errorf("get engine: %w", err)
	}

	ctx := context.Background()
	resp, err := eng.Do(ctx, &engine.Request{
		URL:     params.URL,
		Timeout: 30,
	})
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	config := &semantic.PipelineConfig{
		MaxChunks:        50,
		MaxConcurrentLLM: 0,
	}

	tree, stats, err := semantic.HTMLToSemanticTreeCached(ctx, string(resp.Body), params.URL, config)
	if err != nil {
		return nil, fmt.Errorf("extract semantic: %w", err)
	}

	lastTree = tree
	lastURL = params.URL

	result := map[string]interface{}{
		"url":     params.URL,
		"status":  resp.Status,
		"size":    len(resp.Body),
		"title":   tree.Title,
		"domain":  tree.Domain,
		"nodes":   len(tree.AllNodes()),
		"actions": countActions(tree),
	}

	if stats != nil && stats.FullTreeTokens > 0 {
		result["tokens_in"] = stats.FullTreeTokens
		result["tokens_out"] = stats.CompressedTokens
		result["compression"] = fmt.Sprintf("%.1f%%",
			float64(stats.CompressedTokens)/float64(stats.FullTreeTokens)*100)
	}

	return json.Marshal(result)
}

func toolSearch(args json.RawMessage) (json.RawMessage, error) {
	if lastTree == nil {
		return nil, fmt.Errorf("no page fetched yet")
	}

	var params struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}

	matches := []string{}
	for _, n := range lastTree.AllNodes() {
		if params.Query != "" && (contains(n.Summary, params.Query) || contains(n.DOMSelector, params.Query)) {
			matches = append(matches, n.Summary)
		}
	}

	return json.Marshal(map[string]interface{}{
		"query":   params.Query,
		"matches": matches,
		"count":   len(matches),
	})
}

func toolLinks() (json.RawMessage, error) {
	if lastTree == nil {
		return nil, fmt.Errorf("no page fetched yet")
	}

	links := []string{}
	for _, n := range lastTree.AllNodes() {
		for _, a := range n.Actions {
			if a.Type == "click" && contains(a.Selector, "href") {
				links = append(links, a.Description)
			}
		}
	}

	return json.Marshal(map[string]interface{}{
		"url":   lastURL,
		"links": links,
		"count": len(links),
	})
}

func toolForms() (json.RawMessage, error) {
	if lastTree == nil {
		return nil, fmt.Errorf("no page fetched yet")
	}

	forms := []string{}
	for _, n := range lastTree.AllNodes() {
		for _, a := range n.Actions {
			if a.Type == "fill" {
				forms = append(forms, a.Description)
			}
		}
	}

	return json.Marshal(map[string]interface{}{
		"url":   lastURL,
		"forms": forms,
		"count": len(forms),
	})
}

func countActions(tree *semantic.SemanticTree) int {
	count := 0
	for _, n := range tree.AllNodes() {
		count += len(n.Actions)
	}
	return count
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && (s[:len(substr)] == substr || contains(s[1:], substr)))
}
