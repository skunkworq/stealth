package server

import (
	"embed"
	"io/fs"
	"log/slog"
	"net/http"
)

//go:embed web/*
var webFS embed.FS

// Server is the top-level HTTP/WebSocket server.
type Server struct {
	cfg       Config
	hub       *Hub
	sessions  *SessionManager
	orch      *Orchestrator
	api       *APIHandler
	ws        *WebSocketHandler
	workspace *Workspace
}

// NewServer creates a server with default wiring.
func NewServer(cfg Config, llmProv LLMProvider) *Server {
	hub := NewHub()
	sessions := NewSessionManager()
	reg := NewRegistry()
	ws := NewWorkspace("./workspace")
	orch := NewOrchestrator(cfg, reg, hub, llmProv, ws)
	api := NewAPIHandler(sessions, hub, orch, llmProv, ws)
	wsh := NewWebSocketHandler(hub)

	return &Server{
		cfg:       cfg,
		hub:       hub,
		sessions:  sessions,
		orch:      orch,
		api:       api,
		ws:        wsh,
		workspace: ws,
	}
}

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// API routes.
	mux.Handle(s.cfg.APIPath+"/", s.api.Router(s.cfg.APIPath))

	// WebSocket route.
	mux.Handle(s.cfg.WSPath, s.ws.Handler())

	// Static web UI.
	static, err := fs.Sub(webFS, "web")
	if err != nil {
		slog.Error("failed to create static subfs", "err", err)
		static = webFS
	}
	mux.Handle("/", http.FileServer(http.FS(static)))

	return mux
}

// ListenAndServe starts the server.
func (s *Server) ListenAndServe() error {
	slog.Info("server starting", "addr", s.cfg.Addr)
	return http.ListenAndServe(s.cfg.Addr, s.Handler())
}
