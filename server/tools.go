package server

import (
	"context"
	"fmt"
	"time"

	"github.com/chromedp/chromedp"
)

// workspaceKey is the context key for the Workspace.
type workspaceKey struct{}

// CtxWithWorkspace injects a workspace into context.
func CtxWithWorkspace(ctx context.Context, ws *Workspace) context.Context {
	return context.WithValue(ctx, workspaceKey{}, ws)
}

// WorkspaceFromCtx retrieves the workspace from context.
func WorkspaceFromCtx(ctx context.Context) *Workspace {
	v, _ := ctx.Value(workspaceKey{}).(*Workspace)
	return v
}

// sessionIDKey carries the session ID for tools.
type sessionIDKey struct{}

// CtxWithSessionID injects session ID into context.
func CtxWithSessionID(ctx context.Context, sid string) context.Context {
	return context.WithValue(ctx, sessionIDKey{}, sid)
}

// SessionIDFromCtx retrieves session ID from context.
func SessionIDFromCtx(ctx context.Context) string {
	v, _ := ctx.Value(sessionIDKey{}).(string)
	return v
}

// agentIDKey carries the agent ID for tools.
type agentIDKey struct{}

// CtxWithAgentID injects agent ID into context.
func CtxWithAgentID(ctx context.Context, aid string) context.Context {
	return context.WithValue(ctx, agentIDKey{}, aid)
}

// AgentIDFromCtx retrieves agent ID from context.
func AgentIDFromCtx(ctx context.Context) string {
	v, _ := ctx.Value(agentIDKey{}).(string)
	return v
}

// ---------------------------------------------------------------------------
// Workspace tools
// ---------------------------------------------------------------------------

func toolWriteFile(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	ws := WorkspaceFromCtx(ctx)
	sid := SessionIDFromCtx(ctx)
	aid := AgentIDFromCtx(ctx)
	if ws == nil || sid == "" || aid == "" {
		return nil, fmt.Errorf("workspace not available")
	}

	path, _ := args["path"].(string)
	content, _ := args["content"].(string)
	if path == "" {
		return nil, fmt.Errorf("path is required")
	}

	absPath, refPath, err := ws.WriteFile(sid, aid, path, []byte(content))
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"absolute_path": absPath,
		"reference":     refPath,
		"status":        "written",
	}, nil
}

func toolReadFile(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	ws := WorkspaceFromCtx(ctx)
	sid := SessionIDFromCtx(ctx)
	aid := AgentIDFromCtx(ctx)
	if ws == nil || sid == "" || aid == "" {
		return nil, fmt.Errorf("workspace not available")
	}

	refPath, _ := args["path"].(string)
	if refPath == "" {
		return nil, fmt.Errorf("path is required")
	}

	data, err := ws.ReadFile(sid, aid, refPath)
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"content": string(data),
		"path":    refPath,
	}, nil
}

func toolListFiles(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	ws := WorkspaceFromCtx(ctx)
	sid := SessionIDFromCtx(ctx)
	aid := AgentIDFromCtx(ctx)
	if ws == nil || sid == "" || aid == "" {
		return nil, fmt.Errorf("workspace not available")
	}

	// If target_agent specified, list that agent's files. Otherwise list caller's.
	targetAgent, _ := args["target_agent"].(string)
	if targetAgent == "" {
		targetAgent = aid
	}

	files, err := ws.ListFiles(sid, targetAgent)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"agent_id": targetAgent,
		"files":    files,
	}, nil
}

// ---------------------------------------------------------------------------
// Screenshot tool
// ---------------------------------------------------------------------------

func toolScreenshot(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	ws := WorkspaceFromCtx(ctx)
	sid := SessionIDFromCtx(ctx)
	aid := AgentIDFromCtx(ctx)
	if ws == nil || sid == "" || aid == "" {
		return nil, fmt.Errorf("workspace not available")
	}

	url, _ := args["url"].(string)
	if url == "" {
		return nil, fmt.Errorf("url is required")
	}

	// Create a headless browser context for the screenshot.
	allocCtx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	screenshotCtx, cancel2 := context.WithTimeout(allocCtx, 30*time.Second)
	defer cancel2()

	var buf []byte
	if err := chromedp.Run(screenshotCtx,
		chromedp.Navigate(url),
		chromedp.CaptureScreenshot(&buf),
	); err != nil {
		return nil, fmt.Errorf("screenshot failed: %w", err)
	}

	filename := fmt.Sprintf("screenshot_%d.png", time.Now().Unix())
	absPath, refPath, err := ws.WriteFile(sid, aid, filename, buf)
	if err != nil {
		return nil, fmt.Errorf("save screenshot: %w", err)
	}

	return map[string]string{
		"url":       url,
		"filename":  filename,
		"reference": refPath,
		"path":      absPath,
		"size":      fmt.Sprintf("%d bytes", len(buf)),
	}, nil
}
