package server

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// SessionManager stores and retrieves chat sessions.
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	order    []string // insertion order for listing
}

// NewSessionManager creates a manager.
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*Session),
		order:    make([]string, 0),
	}
}

// Create creates a new session.
func (sm *SessionManager) Create(title string) *Session {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	s := &Session{
		ID:        uuid.New().String(),
		Title:     title,
		CreatedAt: now,
		UpdatedAt: now,
		Messages:  make([]Message, 0),
		Status:    "idle",
	}
	sm.sessions[s.ID] = s
	sm.order = append(sm.order, s.ID)
	return s
}

// Get retrieves a session by ID.
func (sm *SessionManager) Get(id string) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	s, ok := sm.sessions[id]
	return s, ok
}

// List returns all sessions in creation order (newest last).
func (sm *SessionManager) List() []Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	out := make([]Session, 0, len(sm.order))
	for _, id := range sm.order {
		if s, ok := sm.sessions[id]; ok {
			out = append(out, *s)
		}
	}
	return out
}

// AppendMessage adds a message to a session.
func (sm *SessionManager) AppendMessage(sessionID string, msg Message) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	s, ok := sm.sessions[sessionID]
	if !ok {
		return false
	}
	if msg.ID == "" {
		msg.ID = uuid.New().String()
	}
	if msg.Timestamp.IsZero() {
		msg.Timestamp = time.Now()
	}
	s.Messages = append(s.Messages, msg)
	s.UpdatedAt = time.Now()
	return true
}

// SetStatus updates session status.
func (sm *SessionManager) SetStatus(sessionID, status string) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	s, ok := sm.sessions[sessionID]
	if !ok {
		return false
	}
	s.Status = status
	s.UpdatedAt = time.Now()
	return true
}

// SetRootAgent records which agent owns the session.
func (sm *SessionManager) SetRootAgent(sessionID, agentID string) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	s, ok := sm.sessions[sessionID]
	if !ok {
		return false
	}
	s.RootAgent = agentID
	return true
}
