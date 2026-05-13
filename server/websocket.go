package server

import (
	"log/slog"
	"net/http"

	"golang.org/x/net/websocket"
)

// WebSocketHandler wraps the Hub to handle WebSocket connections.
type WebSocketHandler struct {
	hub *Hub
}

// NewWebSocketHandler creates a handler.
func NewWebSocketHandler(hub *Hub) *WebSocketHandler {
	return &WebSocketHandler{hub: hub}
}

// Handler returns an http.Handler for the WebSocket endpoint.
func (wsh *WebSocketHandler) Handler() http.Handler {
	return websocket.Handler(func(ws *websocket.Conn) {
		wsh.hub.Register(ws)
		defer wsh.hub.Unregister(ws)

		slog.Info("websocket client connected", "remote", ws.RemoteAddr())
		defer slog.Info("websocket client disconnected", "remote", ws.RemoteAddr())

		for {
			var msg struct {
				Type      string `json:"type"`
				SessionID string `json:"session_id"`
			}
			if err := websocket.JSON.Receive(ws, &msg); err != nil {
				// Client disconnect or malformed message.
				return
			}

			switch msg.Type {
			case "subscribe":
				if msg.SessionID != "" {
					wsh.hub.SubscribeSession(ws, msg.SessionID)
					slog.Info("client subscribed to session", "session", msg.SessionID)
				}
			default:
				// Unknown control messages are ignored.
			}
		}
	})
}
