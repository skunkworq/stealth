package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/skunkworq/stealth/brws/semantic"
	"github.com/skunkworq/stealth/brws/semantic/index"
)

type Tools struct {
	config *semantic.PipelineConfig
	cache  *semantic.CacheStore
	index  *index.HNSWIndex
}

func main() {
	ctx := context.Background()

	config, err := semantic.NewConfigFromEnv()
	if err != nil {
		config = &semantic.PipelineConfig{}
	}

	cache, err := semantic.NewCacheStore(ctx, "")
	if err != nil {
		log.Printf("Warning: Failed to create cache store: %v, using no cache", err)
		cache = nil
	}
	if cache != nil {
		defer cache.Close()
	}

	tools := &Tools{
		config: config,
		cache:  cache,
		index:  index.NewHNSWIndex(1536),
	}

	s := server.NewMCPServer(
		"semantic-mcp",
		"1.0.0",
		server.WithToolCapabilities(true),
	)

	s.AddTool(mcp.NewTool("extract_semantic_tree",
		mcp.WithDescription("Extract a semantic tree from a URL or HTML content. Returns a compressed hierarchical representation of the page structure."),
		mcp.WithString("url", mcp.Required(), mcp.Description("URL to extract semantic tree from")),
		mcp.WithString("html", mcp.Description("Optional HTML content to extract from (if provided, URL is used only for context)")),
		mcp.WithBoolean("include_forms", mcp.Description("Include form schema extraction")),
		mcp.WithBoolean("include_grounding", mcp.Description("Include visual grounding (bounding boxes)")),
	), tools.extractSemanticTree)

	s.AddTool(mcp.NewTool("diff_semantic_trees",
		mcp.WithDescription("Compare two semantic trees and return the differences (added/removed/modified nodes)"),
		mcp.WithString("old_url", mcp.Required(), mcp.Description("URL of the first/older page")),
		mcp.WithString("new_url", mcp.Required(), mcp.Description("URL of the second/newer page")),
	), tools.diffSemanticTrees)

	s.AddTool(mcp.NewTool("get_form_schemas",
		mcp.WithDescription("Extract form schemas from HTML content, including field types, labels, validation constraints"),
		mcp.WithString("html", mcp.Required(), mcp.Description("HTML content to extract forms from")),
	), tools.getFormSchemas)

	s.AddTool(mcp.NewTool("serialize_tree",
		mcp.WithDescription("Serialize a semantic tree to [WEBFURL] text format for LLM context"),
		mcp.WithString("url", mcp.Required(), mcp.Description("URL to extract and serialize")),
		mcp.WithNumber("token_budget", mcp.Description("Maximum tokens for the output (default 4000)")),
	), tools.serializeTree)

	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func (t *Tools) extractSemanticTree(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	url, err := request.RequireString("url")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	html := request.GetString("html", "")
	includeForms := request.GetBool("include_forms", false)
	includeGrounding := request.GetBool("include_grounding", false)

	var tree *semantic.SemanticTree

	if html != "" {
		tree, _, err = semantic.HTMLToSemanticTreeCached(ctx, html, url, t.config)
	} else {
		resp, fetchErr := http.Get(url)
		if fetchErr != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch URL: %v", fetchErr)), nil
		}
		defer resp.Body.Close()

		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to read response: %v", readErr)), nil
		}
		html = string(body)
		tree, _, err = semantic.HTMLToSemanticTreeCached(ctx, html, url, t.config)
	}

	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to extract semantic tree: %v", err)), nil
	}

	result := map[string]interface{}{
		"url":               tree.URL,
		"title":             tree.Title,
		"structural_hash":   tree.StructuralHash,
		"compressed_tokens": tree.CompressedTokenCount,
		"original_tokens":   tree.FullTokenCount,
		"root_nodes_count":  len(tree.RootNodes),
	}

	if tree.CompressedTokenCount > 0 {
		result["compression_ratio"] = float64(tree.FullTokenCount) / float64(tree.CompressedTokenCount)
	}

	if includeForms {
		forms := semantic.ExtractFormSchemas(html)
		result["forms"] = forms
	}

	if includeGrounding {
		grounding := semantic.ExtractVisualGrounding(html, 1920, 1080)
		result["visual_grounding"] = grounding
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (t *Tools) diffSemanticTrees(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	oldURL, err := request.RequireString("old_url")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	newURL, err := request.RequireString("new_url")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	oldTree, err := t.fetchTree(ctx, oldURL)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch old URL: %v", err)), nil
	}

	newTree, err := t.fetchTree(ctx, newURL)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch new URL: %v", err)), nil
	}

	diff := semantic.ComputeDiff(oldTree, newTree)

	result := map[string]interface{}{
		"url":             diff.URL,
		"has_changes":     diff.HasChanges(),
		"changed_count":   len(diff.ChangedChunks),
		"added_count":     len(diff.AddedChunks),
		"removed_count":   len(diff.RemovedChunks),
		"unchanged_count": diff.UnchangedCount,
		"change_percent":  diff.ChangedPercent(),
		"summary":         diff.Summary(),
		"changed_chunks":  diff.ChangedChunks,
		"added_chunks":    diff.AddedChunks,
		"removed_chunks":  diff.RemovedChunks,
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (t *Tools) getFormSchemas(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	html, err := request.RequireString("html")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	forms := semantic.ExtractFormSchemas(html)

	result := map[string]interface{}{
		"forms_count": len(forms),
		"forms":       forms,
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(data)), nil
}

func (t *Tools) serializeTree(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	url, err := request.RequireString("url")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	initialBudget := uint32(request.GetInt("token_budget", 4000))
	maxBudget := initialBudget * 4

	tree, fetchErr := t.fetchTree(ctx, url)
	if fetchErr != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch URL: %v", fetchErr)), nil
	}

	state := semantic.InitialPack(tree, initialBudget, maxBudget)
	serialized := semantic.SerializeTree(tree, state, nil)

	return mcp.NewToolResultText(serialized), nil
}

func (t *Tools) fetchTree(ctx context.Context, url string) (*semantic.SemanticTree, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	html := string(body)

	tree, _, err := semantic.HTMLToSemanticTreeCached(ctx, html, url, t.config)
	if err != nil {
		return nil, err
	}

	return tree, nil
}

func init() {
	if os.Getenv("OPENROUTER_API_KEY") == "" {
		os.Setenv("OPENROUTER_API_KEY", "-")
	}
}
