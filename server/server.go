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

// spaFileServer wraps a file server to fallback to index.html for SPA routing.
type spaFileServer struct {
	root http.FileSystem
}

func (s *spaFileServer) Open(name string) (http.File, error) {
	f, err := s.root.Open(name)
	if err != nil {
		return s.root.Open("index.html")
	}
	return f, nil
}

// requireAPIKey returns a middleware that checks Authorization: Bearer <key>
// or X-API-Key: <key>. Only active when cfg.APIKey is non-empty.
func (s *Server) requireAPIKey(next http.Handler) http.Handler {
	if s.cfg.APIKey == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		if key == "" {
			if auth := r.Header.Get("Authorization"); len(auth) > 7 && auth[:7] == "Bearer " {
				key = auth[7:]
			}
		}
		if key != s.cfg.APIKey {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// API routes — gated by API key when configured.
	mux.Handle(s.cfg.APIPath+"/", s.requireAPIKey(s.api.Router(s.cfg.APIPath)))

	// WebSocket route — gated by API key when configured.
	mux.Handle(s.cfg.WSPath, s.requireAPIKey(s.ws.Handler()))

	// Static web UI with SPA fallback (unauthenticated — serves only bundled assets).
	static, err := fs.Sub(webFS, "web")
	if err != nil {
		slog.Error("failed to create static subfs", "err", err)
		static = webFS
	}
	spa := &spaFileServer{root: http.FS(static)}
	mux.Handle("/", http.FileServer(spa))

	return mux
}

// ListenAndServe starts the server.
func (s *Server) ListenAndServe() error {
	slog.Info("server starting", "addr", s.cfg.Addr)
	return http.ListenAndServe(s.cfg.Addr, s.Handler())
}
