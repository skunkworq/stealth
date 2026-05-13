package server

import (
	"sync"

	"golang.org/x/net/websocket"
)

// Hub manages WebSocket clients and broadcasts events to them.
type Hub struct {
	mu      sync.RWMutex
	clients map[*websocket.Conn]bool
	// sessionSubscriptions maps session ID -> set of clients interested in it.
	sessionSubs map[string]map[*websocket.Conn]bool
}

// NewHub creates a new Hub.
func NewHub() *Hub {
	return &Hub{
		clients:     make(map[*websocket.Conn]bool),
		sessionSubs: make(map[string]map[*websocket.Conn]bool),
	}
}

// Register adds a client to the hub.
func (h *Hub) Register(ws *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[ws] = true
}

// Unregister removes a client and all its subscriptions.
func (h *Hub) Unregister(ws *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.clients, ws)
	for sid, subs := range h.sessionSubs {
		delete(subs, ws)
		if len(subs) == 0 {
			delete(h.sessionSubs, sid)
		}
	}
}

// SubscribeSession marks a client as interested in a specific session.
func (h *Hub) SubscribeSession(ws *websocket.Conn, sessionID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.sessionSubs[sessionID] == nil {
		h.sessionSubs[sessionID] = make(map[*websocket.Conn]bool)
	}
	h.sessionSubs[sessionID][ws] = true
}

// Broadcast sends an event to all connected clients.
func (h *Hub) Broadcast(ev Event) {
	h.mu.RLock()
	clients := make([]*websocket.Conn, 0, len(h.clients))
	for c := range h.clients {
		clients = append(clients, c)
	}
	h.mu.RUnlock()

	for _, c := range clients {
		_ = websocket.JSON.Send(c, ev)
	}
}

// BroadcastSession sends an event only to clients subscribed to a session.
// Falls back to broadcasting to all clients if no subscriptions exist.
func (h *Hub) BroadcastSession(sessionID string, ev Event) {
	h.mu.RLock()
	subs := h.sessionSubs[sessionID]
	if len(subs) == 0 {
		h.mu.RUnlock()
		h.Broadcast(ev)
		return
	}
	clients := make([]*websocket.Conn, 0, len(subs))
	for c := range subs {
		clients = append(clients, c)
	}
	h.mu.RUnlock()

	for _, c := range clients {
		_ = websocket.JSON.Send(c, ev)
	}
}
