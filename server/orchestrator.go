package server

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/skunkworq/stealth/brws/llm/completions"
)

// Orchestrator manages all agents across all sessions.
type Orchestrator struct {
	mu      sync.RWMutex
	agents  map[string]*Agent
	cfg     Config
	reg     *Registry
	hub       *Hub
	llmProv   LLMProvider
	workspace *Workspace
}

// DefaultProvider returns the default LLM provider name.
func (o *Orchestrator) DefaultProvider() string { return o.cfg.DefaultLLM }

// DefaultModel returns the default model name.
func (o *Orchestrator) DefaultModel() string { return o.cfg.DefaultModel }

// NewOrchestrator creates an orchestrator.
func NewOrchestrator(cfg Config, reg *Registry, hub *Hub, llmProv LLMProvider, ws *Workspace) *Orchestrator {
	return &Orchestrator{
		agents:    make(map[string]*Agent),
		cfg:       cfg,
		reg:       reg,
		hub:       hub,
		llmProv:   llmProv,
		workspace: ws,
	}
}

// SpawnRoot creates the root agent for a session.
func (o *Orchestrator) SpawnRoot(sessionID, goal string, llm completions.LLM, tools []string) string {
	bus := NewEventBus(o.hub, sessionID)
	if tools == nil {
		tools = o.reg.List()
	}
	agent := NewAgent(sessionID, "", goal, "root", 0, llm, tools, o.reg, bus, o.workspace)

	// Override spawn_agent tool to route through this orchestrator.
	o.reg.Register(Tool{
		Name:        "spawn_agent",
		Description: "Spawn a sub-agent to handle a specific subtask. Use this when the task can be broken into independent pieces.",
		Parameters: ToolSchema{
			Type: "object",
			Properties: map[string]ToolProperty{
				"goal":       {Type: "string", Description: "What the sub-agent should accomplish"},
				"agent_type": {Type: "string", Description: "Type of agent: research, browser, analysis"},
			},
			Required: []string{"goal"},
		},
		Execute: func(ctx context.Context, args map[string]interface{}) (interface{}, error) {
			return o.toolSpawnAgent(ctx, agent, args)
		},
	})

	o.mu.Lock()
	o.agents[agent.ID] = agent
	o.mu.Unlock()

	bus.EmitAgentSpawned(agent.ID, "", 0, "root", goal, "idle")
	return agent.ID
}

// SpawnChild creates a sub-agent under a parent.
func (o *Orchestrator) SpawnChild(parent *Agent, goal, agentType string) string {
	bus := NewEventBus(o.hub, parent.SessionID)
	child := NewAgent(parent.SessionID, parent.ID, goal, agentType, parent.Depth+1, parent.LLM, parent.Tools, o.reg, bus, o.workspace)

	o.mu.Lock()
	o.agents[child.ID] = child
	parent.AddChild(child.ID)
	o.mu.Unlock()

	bus.EmitAgentSpawned(child.ID, parent.ID, child.Depth, agentType, goal, "idle")
	return child.ID
}

// Run executes an agent to completion.
func (o *Orchestrator) Run(agentID string) error {
	o.mu.RLock()
	agent, ok := o.agents[agentID]
	o.mu.RUnlock()
	if !ok {
		return fmt.Errorf("agent %s not found", agentID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	return agent.Run(ctx)
}

// Result returns the final result of an agent.
func (o *Orchestrator) Result(agentID string) string {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if agent, ok := o.agents[agentID]; ok {
		return agent.Result()
	}
	return ""
}

// AgentTree builds a nested tree view starting from a root agent.
func (o *Orchestrator) AgentTree(rootID string) AgentInfo {
	o.mu.RLock()
	defer o.mu.RUnlock()

	root, ok := o.agents[rootID]
	if !ok {
		return AgentInfo{}
	}
	return o.buildAgentInfo(root)
}

func (o *Orchestrator) buildAgentInfo(a *Agent) AgentInfo {
	info := AgentInfo{
		ID:        a.ID,
		ParentID:  a.ParentID,
		Depth:     a.Depth,
		Type:      a.AgentType,
		Goal:      a.Goal,
		Status:    a.Status(),
		CreatedAt: time.Now(), // ideally stored on Agent; using now as proxy
		Children:  make([]AgentInfo, 0, len(a.Children())),
	}
	for _, cid := range a.Children() {
		if child, ok := o.agents[cid]; ok {
			info.Children = append(info.Children, o.buildAgentInfo(child))
		}
	}
	return info
}

// toolSpawnAgent is the runtime implementation of the spawn_agent tool.
func (o *Orchestrator) toolSpawnAgent(ctx context.Context, parent *Agent, args map[string]interface{}) (interface{}, error) {
	goal, _ := args["goal"].(string)
	agentType, _ := args["agent_type"].(string)
	if goal == "" {
		return nil, fmt.Errorf("goal is required")
	}
	if agentType == "" {
		agentType = "research"
	}

	childID := o.SpawnChild(parent, goal, agentType)

	// Run child asynchronously so parent can continue if desired,
	// but for predictable UX we run synchronously here and emit events.
	if err := o.Run(childID); err != nil {
		return map[string]string{"error": err.Error()}, nil
	}

	return map[string]interface{}{
		"agent_id": childID,
		"result":   o.Result(childID),
		"status":   "completed",
	}, nil
}
