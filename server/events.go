package server

import (
	"context"
)

// EventBus carries events from agents to the Hub.
type EventBus struct {
	hub       *Hub
	sessionID string
}

// NewEventBus creates a bus scoped to a session.
func NewEventBus(hub *Hub, sessionID string) *EventBus {
	return &EventBus{hub: hub, sessionID: sessionID}
}

// Emit sends an event to all subscribers of the session.
func (eb *EventBus) Emit(ev Event) {
	if eb == nil || eb.hub == nil {
		return
	}
	eb.hub.BroadcastSession(eb.sessionID, ev)
}

// EmitThought sends a thought event.
func (eb *EventBus) EmitThought(agentID, parentID string, depth int, step, content string) {
	eb.Emit(Event{
		Type:      EventThought,
		SessionID: eb.sessionID,
		AgentID:   agentID,
		ParentID:  parentID,
		Depth:     depth,
		Step:      step,
		Content:   content,
		Timestamp: timeNow(),
	})
}

// EmitToolCall sends a tool invocation event.
func (eb *EventBus) EmitToolCall(agentID, parentID string, depth int, toolName string, args map[string]interface{}) {
	eb.Emit(Event{
		Type:      EventToolCall,
		SessionID: eb.sessionID,
		AgentID:   agentID,
		ParentID:  parentID,
		Depth:     depth,
		ToolName:  toolName,
		Arguments: args,
		Timestamp: timeNow(),
	})
}

// EmitToolResult sends a tool return event.
func (eb *EventBus) EmitToolResult(agentID, parentID string, depth int, toolName string, result interface{}, dur int64) {
	eb.Emit(Event{
		Type:      EventToolResult,
		SessionID: eb.sessionID,
		AgentID:   agentID,
		ParentID:  parentID,
		Depth:     depth,
		ToolName:  toolName,
		Result:    result,
		Duration:  dur,
		Timestamp: timeNow(),
	})
}

// EmitAgentSpawned notifies that a sub-agent was created.
func (eb *EventBus) EmitAgentSpawned(agentID, parentID string, depth int, agentType, goal, status string) {
	eb.Emit(Event{
		Type:      EventAgentSpawned,
		SessionID: eb.sessionID,
		AgentID:   agentID,
		ParentID:  parentID,
		Depth:     depth,
		AgentType: agentType,
		Goal:      goal,
		Status:    status,
		Timestamp: timeNow(),
	})
}

// EmitAgentCompleted notifies that an agent finished.
func (eb *EventBus) EmitAgentCompleted(agentID, parentID string, depth int, status string) {
	eb.Emit(Event{
		Type:      EventAgentCompleted,
		SessionID: eb.sessionID,
		AgentID:   agentID,
		ParentID:  parentID,
		Depth:     depth,
		Status:    status,
		Timestamp: timeNow(),
	})
}

// EmitStream sends a partial text chunk (for streaming assistant responses).
func (eb *EventBus) EmitStream(agentID, parentID string, depth int, chunk string) {
	eb.Emit(Event{
		Type:      EventStream,
		SessionID: eb.sessionID,
		AgentID:   agentID,
		ParentID:  parentID,
		Depth:     depth,
		Content:   chunk,
		Timestamp: timeNow(),
	})
}

// CtxWithBus injects the event bus into a context.
func CtxWithBus(ctx context.Context, bus *EventBus) context.Context {
	return context.WithValue(ctx, busKey{}, bus)
}

// BusFromCtx retrieves the event bus from a context.
func BusFromCtx(ctx context.Context) *EventBus {
	v, _ := ctx.Value(busKey{}).(*EventBus)
	return v
}

type busKey struct{}
