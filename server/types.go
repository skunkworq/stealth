// Package server provides an HTTP/WebSocket server for chatbot-driven
// nested-agent research. It streams real-time events (thoughts, tool calls,
// sub-agent spawns) to connected clients.
package server

import (
	"time"

	"github.com/skunkworq/stealth/brws/llm/completions"
)

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

// Session is a single chat conversation that may spawn one or more agents.
type Session struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Messages  []Message `json:"messages"`
	RootAgent string    `json:"root_agent,omitempty"`
	Status    string    `json:"status"` // idle, running, completed, error
}

// Message is a single turn in a session.
type Message struct {
	ID        string    `json:"id"`
	Role      string    `json:"role"` // user, assistant, system
	Content   string    `json:"content"`
	AgentID   string    `json:"agent_id,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// ---------------------------------------------------------------------------
// Events (WebSocket protocol)
// ---------------------------------------------------------------------------

// EventType categorizes real-time events streamed to the UI.
type EventType string

const (
	EventSessionCreated  EventType = "session_created"
	EventSessionUpdated  EventType = "session_updated"
	EventMessage         EventType = "message"
	EventAgentSpawned    EventType = "agent_spawned"
	EventAgentCompleted  EventType = "agent_completed"
	EventThought         EventType = "thought"
	EventToolCall        EventType = "tool_call"
	EventToolResult      EventType = "tool_result"
	EventStream          EventType = "stream"
	EventFileCreated     EventType = "file_created"
	EventError           EventType = "error"
)

// Event is the universal envelope streamed over WebSocket.
type Event struct {
	Type      EventType `json:"type"`
	SessionID string    `json:"session_id"`
	AgentID   string    `json:"agent_id,omitempty"`
	ParentID  string    `json:"parent_id,omitempty"`
	Depth     int       `json:"depth,omitempty"`
	Timestamp int64     `json:"timestamp"`

	// Type-specific payload fields (use whichever applies)
	Content   string                 `json:"content,omitempty"`
	Role      string                 `json:"role,omitempty"` // for message events
	ToolName  string                 `json:"tool_name,omitempty"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
	Result    interface{}            `json:"result,omitempty"`
	Goal      string                 `json:"goal,omitempty"`
	AgentType string                 `json:"agent_type,omitempty"`
	Status    string                 `json:"status,omitempty"`
	Error     string                 `json:"error,omitempty"`
	Step      string                 `json:"step,omitempty"` // thought sub-category
	Duration  int64                  `json:"duration_ms,omitempty"`
}

// NewEvent creates an Event with the current timestamp.
func NewEvent(et EventType, sessionID string) Event {
	return Event{
		Type:      et,
		SessionID: sessionID,
		Timestamp: time.Now().UnixMilli(),
	}
}

// ---------------------------------------------------------------------------
// HTTP API types
// ---------------------------------------------------------------------------

// CreateSessionRequest starts a new chat session.
type CreateSessionRequest struct {
	Title string `json:"title"`
}

// CreateSessionResponse returns the created session.
type CreateSessionResponse struct {
	Session Session `json:"session"`
}

// SendMessageRequest appends a user message and optionally starts agent work.
type SendMessageRequest struct {
	Content  string            `json:"content"`
	Provider string            `json:"provider,omitempty"` // openai, anthropic, openrouter...
	Model    string            `json:"model,omitempty"`
	APIKey   string            `json:"api_key,omitempty"`
	Tools    []string          `json:"tools,omitempty"`    // subset of available tools
	Config   map[string]string `json:"config,omitempty"`   // extra agent config
}

// ListSessionsResponse returns all sessions.
type ListSessionsResponse struct {
	Sessions []Session `json:"sessions"`
}

// GetSessionResponse returns a single session with messages.
type GetSessionResponse struct {
	Session Session `json:"session"`
}

// AgentInfo describes an agent in the tree.
type AgentInfo struct {
	ID        string      `json:"id"`
	ParentID  string      `json:"parent_id,omitempty"`
	Depth     int         `json:"depth"`
	Type      string      `json:"type"`
	Goal      string      `json:"goal"`
	Status    string      `json:"status"`
	CreatedAt time.Time   `json:"created_at"`
	Children  []AgentInfo `json:"children,omitempty"`
}

// GetAgentTreeResponse returns the nested agent tree for a session.
type GetAgentTreeResponse struct {
	SessionID string    `json:"session_id"`
	Tree      AgentInfo `json:"tree"`
}

// ---------------------------------------------------------------------------
// Server Config
// ---------------------------------------------------------------------------

// Config holds server-wide settings.
type Config struct {
	Addr         string `json:"addr"`          // HTTP listen address, default :8080
	WSPath       string `json:"ws_path"`       // WebSocket path, default /ws
	APIPath      string `json:"api_path"`      // API prefix, default /api
	DefaultLLM   string `json:"default_llm"`   // default provider name
	DefaultModel string `json:"default_model"` // default model name
	// APIKey is an optional shared secret. When non-empty, all API and WebSocket
	// requests must include Authorization: Bearer <key> or X-API-Key: <key>.
	APIKey string `json:"api_key,omitempty"`
	// LLMAPIKey is the server-side LLM provider API key. When set, callers do not
	// need to supply api_key in SendMessageRequest — the server uses this value.
	// This avoids sending LLM keys over HTTP in request bodies.
	LLMAPIKey string `json:"llm_api_key,omitempty"`
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		Addr:         ":8080",
		WSPath:       "/ws",
		APIPath:      "/api",
		DefaultLLM:   "openrouter",
		DefaultModel: "anthropic/claude-sonnet-4",
	}
}

// LLMProvider is a factory for LLM instances.
type LLMProvider func(provider, model, apiKey string) (completions.LLM, error)

// DefaultLLMProvider uses the completions package.
func DefaultLLMProvider(provider, model, apiKey string) (completions.LLM, error) {
	if apiKey == "" {
		return completions.FromEnv(provider, model)
	}
	return completions.New(provider, model, apiKey)
}
