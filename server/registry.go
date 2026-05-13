package server

import (
	"context"
	"fmt"

	"github.com/skunkworq/stealth/brws/llm/completions"
)

// Tool is a callable capability exposed to agents.
type Tool struct {
	Name        string
	Description string
	Parameters  ToolSchema                // JSON-schema-like description
	Execute     func(ctx context.Context, args map[string]interface{}) (interface{}, error)
}

// ToolSchema describes expected parameters.
type ToolSchema struct {
	Type       string                 `json:"type"`
	Properties map[string]ToolProperty `json:"properties"`
	Required   []string               `json:"required"`
}

// ToolProperty describes one parameter field.
type ToolProperty struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

// Registry holds all available tools.
type Registry struct {
	tools map[string]Tool
}

// NewRegistry creates a registry with default tools.
func NewRegistry() *Registry {
	r := &Registry{tools: make(map[string]Tool)}
	r.registerDefaults()
	return r
}

// Register adds a tool.
func (r *Registry) Register(t Tool) {
	r.tools[t.Name] = t
}

// Get retrieves a tool by name.
func (r *Registry) Get(name string) (Tool, bool) {
	t, ok := r.tools[name]
	return t, ok
}

// List returns all tool names.
func (r *Registry) List() []string {
	names := make([]string, 0, len(r.tools))
	for n := range r.tools {
		names = append(names, n)
	}
	return names
}

// SchemaForLLM returns a JSON description of tools for system prompts.
func (r *Registry) SchemaForLLM(names []string) []map[string]interface{} {
	out := make([]map[string]interface{}, 0)
	for _, n := range names {
		t, ok := r.tools[n]
		if !ok {
			continue
		}
		out = append(out, map[string]interface{}{
			"name":        t.Name,
			"description": t.Description,
			"parameters":  t.Parameters,
		})
	}
	return out
}

func (r *Registry) registerDefaults() {
	r.Register(Tool{
		Name:        "web_search",
		Description: "Search the web for information. Returns a list of result snippets.",
		Parameters: ToolSchema{
			Type: "object",
			Properties: map[string]ToolProperty{
				"query": {Type: "string", Description: "Search query"},
			},
			Required: []string{"query"},
		},
		Execute: toolWebSearch,
	})

	r.Register(Tool{
		Name:        "browse",
		Description: "Fetch and read a web page. Returns the page text content.",
		Parameters: ToolSchema{
			Type: "object",
			Properties: map[string]ToolProperty{
				"url": {Type: "string", Description: "URL to fetch"},
			},
			Required: []string{"url"},
		},
		Execute: toolBrowse,
	})

	r.Register(Tool{
		Name:        "extract",
		Description: "Extract structured data from text using the LLM.",
		Parameters: ToolSchema{
			Type: "object",
			Properties: map[string]ToolProperty{
				"text":   {Type: "string", Description: "Text to analyze"},
				"schema": {Type: "string", Description: "Description of desired output structure"},
			},
			Required: []string{"text", "schema"},
		},
		Execute: toolExtract,
	})

	r.Register(Tool{
		Name:        "write_file",
		Description: "Write text content to a file in your workspace. Other agents can read it by reference.",
		Parameters: ToolSchema{
			Type: "object",
			Properties: map[string]ToolProperty{
				"path":    {Type: "string", Description: "Filename (e.g. findings.md)"},
				"content": {Type: "string", Description: "File content"},
			},
			Required: []string{"path", "content"},
		},
		Execute: toolWriteFile,
	})

	r.Register(Tool{
		Name:        "read_file",
		Description: "Read a file from the workspace. Use {agent_id}/filename.md to read another agent's file.",
		Parameters: ToolSchema{
			Type: "object",
			Properties: map[string]ToolProperty{
				"path": {Type: "string", Description: "File reference path"},
			},
			Required: []string{"path"},
		},
		Execute: toolReadFile,
	})

	r.Register(Tool{
		Name:        "list_files",
		Description: "List files in an agent's workspace. Defaults to your own files.",
		Parameters: ToolSchema{
			Type: "object",
			Properties: map[string]ToolProperty{
				"target_agent": {Type: "string", Description: "Agent ID to list (optional, defaults to self)"},
			},
		},
		Execute: toolListFiles,
	})

	r.Register(Tool{
		Name:        "screenshot",
		Description: "Navigate to a URL and capture a screenshot. The image is saved to your workspace and a reference is returned.",
		Parameters: ToolSchema{
			Type: "object",
			Properties: map[string]ToolProperty{
				"url": {Type: "string", Description: "URL to screenshot"},
			},
			Required: []string{"url"},
		},
		Execute: toolScreenshot,
	})

	r.Register(Tool{
		Name:        "spawn_agent",
		Description: "Spawn a sub-agent to handle a specific subtask. Use this when the task can be broken into independent pieces.",
		Parameters: ToolSchema{
			Type: "object",
			Properties: map[string]ToolProperty{
				"goal":       {Type: "string", Description: "What the sub-agent should accomplish"},
				"agent_type": {Type: "string", Description: "Type of agent: research, browser, analysis"},
			},
			Required: []string{"goal"},
		},
		Execute: toolSpawnAgentStub, // real implementation swaps in via orchestrator
	})
}

// ---------------------------------------------------------------------------
// Default tool implementations (stubs — can be overridden)
// ---------------------------------------------------------------------------

func toolWebSearch(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	query, _ := args["query"].(string)
	if query == "" {
		return nil, fmt.Errorf("query is required")
	}
	// Stub: return a mock result. In production, wire to DuckDuckGo or SearchGraph.
	return map[string]interface{}{
		"query": query,
		"results": []map[string]string{
			{"title": "Result 1 for " + query, "url": "https://example.com/1", "snippet": "..."},
			{"title": "Result 2 for " + query, "url": "https://example.com/2", "snippet": "..."},
		},
	}, nil
}

func toolBrowse(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	url, _ := args["url"].(string)
	if url == "" {
		return nil, fmt.Errorf("url is required")
	}
	// Stub: return placeholder. In production, wire to stealth.Client.Navigate().
	return map[string]interface{}{
		"url":     url,
		"title":   "Page Title",
		"content": "This is a placeholder page content. Wire this tool to the brws stealth client for real browsing.",
	}, nil
}

func toolExtract(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	text, _ := args["text"].(string)
	schema, _ := args["schema"].(string)
	if text == "" || schema == "" {
		return nil, fmt.Errorf("text and schema are required")
	}
	// Stub: ask the LLM if available via context.
	bus := BusFromCtx(ctx)
	_ = bus // could use LLM from context if wired
	return map[string]interface{}{
		"extraction": "Placeholder extraction of: " + text[:min(len(text), 100)],
		"schema":     schema,
	}, nil
}

// toolSpawnAgentStub is replaced at runtime by the orchestrator.
func toolSpawnAgentStub(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return nil, fmt.Errorf("spawn_agent must be called through the orchestrator")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// WithLLM is a convenience to inject an LLM into a context for tools that need it.
func WithLLM(ctx context.Context, llm completions.LLM) context.Context {
	return context.WithValue(ctx, llmKey{}, llm)
}

// LLMFromCtx retrieves the LLM from context.
func LLMFromCtx(ctx context.Context) completions.LLM {
	v, _ := ctx.Value(llmKey{}).(completions.LLM)
	return v
}

type llmKey struct{}
