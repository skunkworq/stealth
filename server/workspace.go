package server

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Workspace provides a shared filesystem for agents within a session.
// Each agent gets its own sub-directory, but can read files from sibling
// agents by referencing paths like "{agent_id}/filename.md".
type Workspace struct {
	mu      sync.RWMutex
	baseDir string
}

// NewWorkspace creates a workspace rooted at baseDir.
func NewWorkspace(baseDir string) *Workspace {
	_ = os.MkdirAll(baseDir, 0755)
	return &Workspace{baseDir: baseDir}
}

// SessionDir returns the directory for a session.
func (w *Workspace) SessionDir(sessionID string) string {
	return filepath.Join(w.baseDir, sessionID)
}

// AgentDir returns the directory for an agent within a session.
func (w *Workspace) AgentDir(sessionID, agentID string) string {
	return filepath.Join(w.baseDir, sessionID, agentID)
}

// WriteFile writes data to a path relative to the agent's directory.
// Returns the absolute path and the session-relative reference path.
func (w *Workspace) WriteFile(sessionID, agentID, filePath string, data []byte) (absPath, refPath string, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	agentDir := w.AgentDir(sessionID, agentID)
	if err := os.MkdirAll(agentDir, 0755); err != nil {
		return "", "", fmt.Errorf("mkdir: %w", err)
	}

	// Sanitize: prevent directory traversal outside agent dir.
	clean := filepath.Clean(filePath)
	if strings.Contains(clean, "..") {
		return "", "", fmt.Errorf("invalid path: %s", filePath)
	}

	absPath = filepath.Join(agentDir, clean)
	// Ensure still inside workspace.
	if !strings.HasPrefix(absPath, filepath.Clean(w.baseDir)) {
		return "", "", fmt.Errorf("path escapes workspace")
	}

	if err := os.WriteFile(absPath, data, 0644); err != nil {
		return "", "", fmt.Errorf("write: %w", err)
	}

	refPath = filepath.Join(agentID, clean)
	return absPath, refPath, nil
}

// ReadFile reads a file by session-relative reference path.
// Paths can be:
//   - "myfile.md" (resolved in caller's agent dir)
//   - "{agent_id}/theirfile.md" (resolved in that agent's dir)
func (w *Workspace) ReadFile(sessionID, callerAgentID, refPath string) ([]byte, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	clean := filepath.Clean(refPath)
	if strings.Contains(clean, "..") {
		return nil, fmt.Errorf("invalid path: %s", refPath)
	}

	// If refPath contains a slash, the first segment might be another agent's ID.
	var absPath string
	if strings.Contains(clean, string(filepath.Separator)) {
		// Try as session-relative path first.
		absPath = filepath.Join(w.SessionDir(sessionID), clean)
	} else {
		// Single filename — resolve in caller's directory.
		absPath = filepath.Join(w.AgentDir(sessionID, callerAgentID), clean)
	}

	absPath = filepath.Clean(absPath)
	if !strings.HasPrefix(absPath, filepath.Clean(w.baseDir)) {
		return nil, fmt.Errorf("path escapes workspace")
	}

	return os.ReadFile(absPath)
}

// ListFiles lists all files in an agent's directory, returning reference paths.
func (w *Workspace) ListFiles(sessionID, agentID string) ([]string, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	agentDir := w.AgentDir(sessionID, agentID)
	entries, err := os.ReadDir(agentDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		files = append(files, filepath.Join(agentID, e.Name()))
	}
	return files, nil
}

// FileMeta holds metadata about a file in the workspace.
type FileMeta struct {
	Name     string    `json:"name"`
	AgentID  string    `json:"agent_id"`
	Size     int64     `json:"size"`
	ModTime  time.Time `json:"mod_time"`
	MIMEType string    `json:"mime_type"`
}

// ListAllFiles lists every file in the session workspace.
func (w *Workspace) ListAllFiles(sessionID string) (map[string][]string, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	sessionDir := w.SessionDir(sessionID)
	agents, err := os.ReadDir(sessionDir)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string][]string{}, nil
		}
		return nil, err
	}

	out := make(map[string][]string)
	for _, agentDir := range agents {
		if !agentDir.IsDir() {
			continue
		}
		entries, err := os.ReadDir(filepath.Join(sessionDir, agentDir.Name()))
		if err != nil {
			continue
		}
		var files []string
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			files = append(files, filepath.Join(agentDir.Name(), e.Name()))
		}
		out[agentDir.Name()] = files
	}
	return out, nil
}

// ListFileMeta lists every file in the session workspace with metadata.
func (w *Workspace) ListFileMeta(sessionID string) ([]FileMeta, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	sessionDir := w.SessionDir(sessionID)
	agents, err := os.ReadDir(sessionDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []FileMeta{}, nil
		}
		return nil, err
	}

	var out []FileMeta
	for _, agentDir := range agents {
		if !agentDir.IsDir() {
			continue
		}
		agentPath := filepath.Join(sessionDir, agentDir.Name())
		entries, err := os.ReadDir(agentPath)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			name := e.Name()
			out = append(out, FileMeta{
				Name:     name,
				AgentID:  agentDir.Name(),
				Size:     info.Size(),
				ModTime:  info.ModTime(),
				MIMEType: detectMIMEType(name),
			})
		}
	}
	return out, nil
}

func detectMIMEType(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".svg":
		return "image/svg+xml"
	case ".webp":
		return "image/webp"
	case ".md":
		return "text/markdown"
	case ".json":
		return "application/json"
	case ".html", ".htm":
		return "text/html"
	case ".css":
		return "text/css"
	case ".js":
		return "application/javascript"
	case ".ts":
		return "application/typescript"
	case ".go":
		return "text/x-go"
	case ".py":
		return "text/x-python"
	case ".txt":
		return "text/plain"
	case ".csv":
		return "text/csv"
	case ".xml":
		return "application/xml"
	case ".yaml", ".yml":
		return "application/yaml"
	default:
		return "application/octet-stream"
	}
}

// ServeFile returns the absolute path for a session-relative reference,
// validating it stays within the workspace.
func (w *Workspace) ServeFile(sessionID, refPath string) (string, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	clean := filepath.Clean(refPath)
	if strings.Contains(clean, "..") {
		return "", fmt.Errorf("invalid path")
	}
	absPath := filepath.Join(w.SessionDir(sessionID), clean)
	absPath = filepath.Clean(absPath)
	if !strings.HasPrefix(absPath, filepath.Clean(w.baseDir)) {
		return "", fmt.Errorf("path escapes workspace")
	}
	return absPath, nil
}
