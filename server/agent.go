package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/skunkworq/stealth/brws/llm/completions"
)

// Agent is a single autonomous worker that can use tools and spawn children.
type Agent struct {
	ID       string
	ParentID string
	Depth    int

	SessionID string
	Goal      string
	AgentType string // research, browser, analysis, root

	LLM   completions.LLM
	Tools []string // subset of registry tool names

	Registry  *Registry
	Bus       *EventBus
	Workspace *Workspace

	result   string
	status   string
	children []string // child agent IDs
}

// NewAgent creates an agent.
func NewAgent(sessionID, parentID, goal, agentType string, depth int, llm completions.LLM, tools []string, reg *Registry, bus *EventBus, ws *Workspace) *Agent {
	return &Agent{
		ID:        uuid.New().String(),
		ParentID:  parentID,
		Depth:     depth,
		SessionID: sessionID,
		Goal:      goal,
		AgentType: agentType,
		LLM:       llm,
		Tools:     tools,
		Registry:  reg,
		Bus:       bus,
		Workspace: ws,
		status:    "idle",
		children:  make([]string, 0),
	}
}

// Status returns the agent status.
func (a *Agent) Status() string { return a.status }

// Result returns the final output.
func (a *Agent) Result() string { return a.result }

// Children returns child agent IDs.
func (a *Agent) Children() []string { return a.children }

// AddChild records a child agent.
func (a *Agent) AddChild(id string) { a.children = append(a.children, id) }

// Run executes the agent's goal.
func (a *Agent) Run(ctx context.Context) error {
	a.status = "running"
	if a.Bus != nil {
		a.Bus.EmitAgentSpawned(a.ID, a.ParentID, a.Depth, a.AgentType, a.Goal, "running")
	}

	// Build system prompt.
	system := a.buildSystemPrompt()

	// Phase 1: Planning / reasoning.
	if a.Bus != nil {
		a.Bus.EmitThought(a.ID, a.ParentID, a.Depth, "planning",
			fmt.Sprintf("Agent %s (%s) planning approach for: %s", a.ID[:8], a.AgentType, a.Goal))
	}

	plan, err := a.llmComplete(ctx, system, a.planningPrompt())
	if err != nil {
		a.status = "error"
		if a.Bus != nil {
			a.Bus.EmitAgentCompleted(a.ID, a.ParentID, a.Depth, "error")
		}
		return fmt.Errorf("planning failed: %w", err)
	}

	if a.Bus != nil {
		a.Bus.EmitThought(a.ID, a.ParentID, a.Depth, "plan", plan)
	}

	// Phase 2: Execution loop (up to 10 steps).
	maxSteps := 10
	var sb strings.Builder
	for i := 0; i < maxSteps; i++ {
		if err := ctx.Err(); err != nil {
			a.status = "cancelled"
			return err
		}

		stepPrompt := a.executionPrompt(plan, sb.String(), i)
		resp, err := a.llmComplete(ctx, system, stepPrompt)
		if err != nil {
			a.status = "error"
			return fmt.Errorf("step %d failed: %w", i, err)
		}

		// Parse response for tool calls or completion.
		action, payload := a.parseAction(resp)
		switch action {
		case "done":
			a.result = payload
			a.status = "completed"
			if a.Bus != nil {
				a.Bus.EmitAgentCompleted(a.ID, a.ParentID, a.Depth, "completed")
			}
			return nil

		case "think":
			if a.Bus != nil {
				a.Bus.EmitThought(a.ID, a.ParentID, a.Depth, "reasoning", payload)
			}
			sb.WriteString("\nThought: ")
			sb.WriteString(payload)

		case "tool":
			var tc struct {
				Name string                 `json:"name"`
				Args map[string]interface{} `json:"args"`
			}
			if err := json.Unmarshal([]byte(payload), &tc); err != nil {
				if a.Bus != nil {
					a.Bus.EmitThought(a.ID, a.ParentID, a.Depth, "error", "failed to parse tool call: "+err.Error())
				}
				continue
			}
			a.executeTool(ctx, tc.Name, tc.Args)

		default:
			// Treat as intermediate output.
			if a.Bus != nil {
				a.Bus.EmitStream(a.ID, a.ParentID, a.Depth, resp)
			}
			sb.WriteString("\n")
			sb.WriteString(resp)
		}
	}

	a.result = sb.String()
	a.status = "completed"
	if a.Bus != nil {
		a.Bus.EmitAgentCompleted(a.ID, a.ParentID, a.Depth, "completed")
	}
	return nil
}

func (a *Agent) buildSystemPrompt() string {
	toolsDesc := ""
	if len(a.Tools) > 0 {
		toolsDesc = "\nAvailable tools:\n"
		for _, name := range a.Tools {
			t, ok := a.Registry.Get(name)
			if !ok {
				continue
			}
			toolsDesc += fmt.Sprintf("- %s: %s\n", t.Name, t.Description)
		}
	}

	return fmt.Sprintf(`You are a "%s" agent. Your goal is: %s
Respond using one of these formats on each turn:
1. THINK: <your reasoning>
2. TOOL: {"name": "<tool_name>", "args": {...}}
3. DONE: <final answer>
%s`, a.AgentType, a.Goal, toolsDesc)
}

func (a *Agent) planningPrompt() string {
	return fmt.Sprintf("Plan your approach to achieve this goal. Be concise.\nGoal: %s", a.Goal)
}

func (a *Agent) executionPrompt(plan, history string, step int) string {
	return fmt.Sprintf("Step %d/%d\nPlan: %s\nHistory so far:\n%s\nWhat do you do next? Respond with THINK:, TOOL:, or DONE:",
		step+1, 10, plan, history)
}

func (a *Agent) parseAction(resp string) (string, string) {
	resp = strings.TrimSpace(resp)
	if strings.HasPrefix(resp, "DONE:") {
		return "done", strings.TrimSpace(strings.TrimPrefix(resp, "DONE:"))
	}
	if strings.HasPrefix(resp, "THINK:") {
		return "think", strings.TrimSpace(strings.TrimPrefix(resp, "THINK:"))
	}
	if strings.HasPrefix(resp, "TOOL:") {
		return "tool", strings.TrimSpace(strings.TrimPrefix(resp, "TOOL:"))
	}
	// Try JSON tool call directly.
	var tc struct {
		Name string                 `json:"name"`
		Args map[string]interface{} `json:"args"`
	}
	if err := json.Unmarshal([]byte(resp), &tc); err == nil && tc.Name != "" {
		b, _ := json.Marshal(tc)
		return "tool", string(b)
	}
	return "text", resp
}

func (a *Agent) executeTool(ctx context.Context, name string, args map[string]interface{}) {
	if a.Bus != nil {
		a.Bus.EmitToolCall(a.ID, a.ParentID, a.Depth, name, args)
	}

	tool, ok := a.Registry.Get(name)
	if !ok {
		if a.Bus != nil {
			a.Bus.EmitToolResult(a.ID, a.ParentID, a.Depth, name, map[string]string{"error": "unknown tool"}, 0)
		}
		return
	}

	start := time.Now()
	ctx = WithLLM(ctx, a.LLM)
	ctx = CtxWithSessionID(ctx, a.SessionID)
	ctx = CtxWithAgentID(ctx, a.ID)
	if a.Workspace != nil {
		ctx = CtxWithWorkspace(ctx, a.Workspace)
	}
	result, err := tool.Execute(ctx, args)
	dur := time.Since(start).Milliseconds()

	if err != nil {
		if a.Bus != nil {
			a.Bus.EmitToolResult(a.ID, a.ParentID, a.Depth, name, map[string]string{"error": err.Error()}, dur)
		}
		return
	}

	if a.Bus != nil {
		a.Bus.EmitToolResult(a.ID, a.ParentID, a.Depth, name, result, dur)
	}

	// Emit file_created for tools that produce files.
	if a.Bus != nil && err == nil && (name == "write_file" || name == "screenshot") {
		if m, ok := result.(map[string]string); ok {
			if ref := m["reference"]; ref != "" {
				a.Bus.Emit(Event{
					Type:      EventFileCreated,
					SessionID: a.SessionID,
					AgentID:   a.ID,
					ParentID:  a.ParentID,
					Depth:     a.Depth,
					Content:   ref,
					ToolName:  name,
					Timestamp: timeNow(),
				})
			}
		}
		if m, ok := result.(map[string]interface{}); ok {
			if ref, _ := m["reference"].(string); ref != "" {
				a.Bus.Emit(Event{
					Type:      EventFileCreated,
					SessionID: a.SessionID,
					AgentID:   a.ID,
					ParentID:  a.ParentID,
					Depth:     a.Depth,
					Content:   ref,
					ToolName:  name,
					Timestamp: timeNow(),
				})
			}
		}
	}
}

func (a *Agent) llmComplete(ctx context.Context, system, user string) (string, error) {
	if a.LLM == nil {
		return "", fmt.Errorf("no LLM configured")
	}
	return a.LLM.Complete(ctx, system, user)
}
