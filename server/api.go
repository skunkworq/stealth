package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/skunkworq/stealth/brws/llm/completions"
)

// AgentOrchestrator is the interface the API uses to control agents.
type AgentOrchestrator interface {
	SpawnRoot(sessionID, goal string, llm completions.LLM, tools []string) string
	Run(agentID string) error
	Result(agentID string) string
	AgentTree(rootID string) AgentInfo
	DefaultProvider() string
	DefaultModel() string
}

// APIHandler serves the REST API.
type APIHandler struct {
	sessions     *SessionManager
	hub          *Hub
	orch         AgentOrchestrator
	llmProv      LLMProvider
	workspace    *Workspace
	serverLLMKey string // server-side LLM key; overrides per-request key when set
}

// NewAPIHandler creates the handler.
func NewAPIHandler(sessions *SessionManager, hub *Hub, orch AgentOrchestrator, llmProv LLMProvider, ws *Workspace, serverLLMKey string) *APIHandler {
	return &APIHandler{
		sessions:     sessions,
		hub:          hub,
		orch:         orch,
		llmProv:      llmProv,
		workspace:    ws,
		serverLLMKey: serverLLMKey,
	}
}

// Router returns the HTTP mux with all API routes.
func (a *APIHandler) Router(prefix string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(prefix+"/sessions", a.handleSessions)
	mux.HandleFunc(prefix+"/sessions/", a.handleSessionDetail)
	mux.HandleFunc(prefix+"/agents/tree/", a.handleAgentTree)
	mux.HandleFunc(prefix+"/files/", a.handleFiles)
	mux.HandleFunc(prefix+"/files-meta/", a.handleFileMeta)
	return mux
}

func (a *APIHandler) handleSessions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.listSessions(w, r)
	case http.MethodPost:
		a.createSession(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *APIHandler) handleSessionDetail(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/sessions/")
	parts := strings.SplitN(path, "/", 2)
	sessionID := parts[0]

	switch r.Method {
	case http.MethodGet:
		a.getSession(w, r, sessionID)
	case http.MethodPost:
		if len(parts) > 1 && parts[1] == "messages" {
			a.sendMessage(w, r, sessionID)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *APIHandler) createSession(w http.ResponseWriter, r *http.Request) {
	var req CreateSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Title == "" {
		req.Title = "New Session"
	}
	s := a.sessions.Create(req.Title)

	ev := NewEvent(EventSessionCreated, s.ID)
	a.hub.BroadcastSession(s.ID, ev)

	respondJSON(w, CreateSessionResponse{Session: *s})
}

func (a *APIHandler) listSessions(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, ListSessionsResponse{Sessions: a.sessions.List()})
}

func (a *APIHandler) getSession(w http.ResponseWriter, r *http.Request, id string) {
	s, ok := a.sessions.Get(id)
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	respondJSON(w, GetSessionResponse{Session: *s})
}

func (a *APIHandler) sendMessage(w http.ResponseWriter, r *http.Request, sessionID string) {
	var req SendMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s, ok := a.sessions.Get(sessionID)
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	// Record user message.
	userMsg := Message{
		ID:      uuid.New().String(),
		Role:    "user",
		Content: req.Content,
	}
	a.sessions.AppendMessage(sessionID, userMsg)
	a.hub.BroadcastSession(sessionID, Event{
		Type:      EventMessage,
		SessionID: sessionID,
		Role:      "user",
		Content:   req.Content,
		Timestamp: timeNow(),
	})

	// Start agent work asynchronously.
	go a.runAgentForMessage(sessionID, req, s.RootAgent)

	w.WriteHeader(http.StatusAccepted)
	respondJSON(w, map[string]string{"status": "accepted"})
}

func (a *APIHandler) runAgentForMessage(sessionID string, req SendMessageRequest, existingRoot string) {
	a.sessions.SetStatus(sessionID, "running")
	a.hub.BroadcastSession(sessionID, Event{
		Type:      EventSessionUpdated,
		SessionID: sessionID,
		Status:    "running",
		Timestamp: timeNow(),
	})

	// Resolve LLM with fallback to orchestrator defaults.
	provider := req.Provider
	if provider == "" {
		provider = a.orch.DefaultProvider()
	}
	model := req.Model
	if model == "" {
		model = a.orch.DefaultModel()
	}
	llmKey := req.APIKey
	if a.serverLLMKey != "" {
		llmKey = a.serverLLMKey
	}
	llm, err := a.llmProv(provider, model, llmKey)
	if err != nil {
		slog.Error("failed to create llm", "err", err)
		a.emitError(sessionID, "", "failed to create LLM: "+err.Error())
		a.sessions.SetStatus(sessionID, "error")
		return
	}

	// Spawn or reuse root agent.
	var rootID string
	if existingRoot != "" {
		rootID = existingRoot
	} else {
		rootID = a.orch.SpawnRoot(sessionID, req.Content, llm, req.Tools)
		a.sessions.SetRootAgent(sessionID, rootID)
	}

	// Run the agent to completion.
	if err := a.orch.Run(rootID); err != nil {
		slog.Error("agent run failed", "agent", rootID, "err", err)
		a.emitError(sessionID, rootID, err.Error())
		a.sessions.SetStatus(sessionID, "error")
		return
	}

	// Append final assistant message.
	result := a.orch.Result(rootID)
	if result != "" {
		a.sessions.AppendMessage(sessionID, Message{
			ID:      uuid.New().String(),
			Role:    "assistant",
			Content: result,
			AgentID: rootID,
		})
		a.hub.BroadcastSession(sessionID, Event{
			Type:      EventMessage,
			SessionID: sessionID,
			AgentID:   rootID,
			Role:      "assistant",
			Content:   result,
			Timestamp: timeNow(),
		})
	}

	a.sessions.SetStatus(sessionID, "completed")
	a.hub.BroadcastSession(sessionID, Event{
		Type:      EventSessionUpdated,
		SessionID: sessionID,
		Status:    "completed",
		Timestamp: timeNow(),
	})
}

func (a *APIHandler) emitError(sessionID, agentID, msg string) {
	a.hub.BroadcastSession(sessionID, Event{
		Type:      EventError,
		SessionID: sessionID,
		AgentID:   agentID,
		Error:     msg,
		Timestamp: timeNow(),
	})
}

func (a *APIHandler) handleAgentTree(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/agents/tree/")
	sessionID := strings.TrimSpace(path)
	if sessionID == "" {
		http.Error(w, "session id required", http.StatusBadRequest)
		return
	}
	s, ok := a.sessions.Get(sessionID)
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	if s.RootAgent == "" {
		respondJSON(w, GetAgentTreeResponse{SessionID: sessionID})
		return
	}
	tree := a.orch.AgentTree(s.RootAgent)
	respondJSON(w, GetAgentTreeResponse{SessionID: sessionID, Tree: tree})
}

func (a *APIHandler) handleFileMeta(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/files-meta/")
	parts := strings.Split(path, "/")
	if len(parts) < 1 {
		http.Error(w, "session id required", http.StatusBadRequest)
		return
	}
	sessionID := strings.TrimSpace(parts[0])
	meta, err := a.workspace.ListFileMeta(sessionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, map[string]interface{}{"session_id": sessionID, "files": meta})
}

func (a *APIHandler) handleFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/files/")
	parts := strings.Split(path, "/")

	// List all files: /api/files/{session_id}
	if len(parts) == 1 {
		sessionID := strings.TrimSpace(parts[0])
		files, err := a.workspace.ListAllFiles(sessionID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		respondJSON(w, map[string]interface{}{"session_id": sessionID, "files": files})
		return
	}

	// Serve single file: /api/files/{session_id}/{agent_id}/{filename...}
	if len(parts) < 3 {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	sessionID, agentID := parts[0], parts[1]
	filename := strings.Join(parts[2:], "/")
	refPath := filepath.Join(agentID, filename)
	absPath, err := a.workspace.ServeFile(sessionID, refPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	http.ServeFile(w, r, absPath)
}

func respondJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func timeNow() int64 {
	return time.Now().UnixMilli()
}
