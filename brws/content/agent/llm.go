package agent

import (
	"context"
	"fmt"
	"strings"

	"github.com/skunkworq/stealth/brws/llm/completions"
)

// DefaultLLMSystem is the system prompt used by LLMDecideFn when the caller
// passes an empty systemPrompt.
const DefaultLLMSystem = `You are a browser automation agent. Given the current page state and a list of available actions, choose exactly one action to take next.

Output rules:
- Output only the action ID on a single line. No explanation, no markdown.
- For type/select inputs: <action_id>: <value to enter>
- For navigation: navigate: <full URL>
- When the task is complete: done`

// LLMDecideFn returns a decideFn that asks the given LLM to choose the next
// action. The returned function is safe to use as the callback in Agent.Step.
//
// systemPrompt overrides the default prompt; pass "" to use DefaultLLMSystem.
//
// The LLM sees the formatted page context, the list of action IDs with their
// descriptions, and a short history of the last three steps. It must reply
// with a single action ID (optionally followed by ": value" for type/select/
// navigate actions). Unrecognised replies fall through to ActionNone.
func LLMDecideFn(ctx context.Context, l completions.LLM, systemPrompt string) func(*Context, []Action, string, []Step) (Action, error) {
	if systemPrompt == "" {
		systemPrompt = DefaultLLMSystem
	}
	return func(pageCtx *Context, actions []Action, formatted string, hist []Step) (Action, error) {
		user := buildLLMPrompt(formatted, actions, hist)
		reply, err := l.Complete(ctx, systemPrompt, user)
		if err != nil {
			return Action{Type: ActionNone}, fmt.Errorf("llm: %w", err)
		}
		return parseActionReply(reply, actions)
	}
}

// buildLLMPrompt assembles the user-facing prompt from the formatted page,
// available actions, and the tail of the history.
func buildLLMPrompt(formatted string, actions []Action, hist []Step) string {
	var b strings.Builder

	b.WriteString("## Current page\n")
	b.WriteString(formatted)
	b.WriteString("\n\n## Available actions\n")
	for _, a := range actions {
		b.WriteString(a.ID)
		if a.Description != "" {
			b.WriteString(" — ")
			b.WriteString(a.Description)
		}
		b.WriteByte('\n')
	}

	// Append the last three steps so the LLM has short-term context.
	tail := hist
	if len(tail) > 3 {
		tail = tail[len(tail)-3:]
	}
	if len(tail) > 0 {
		b.WriteString("\n## Recent steps\n")
		for _, s := range tail {
			status := "ok"
			if s.Result != nil && !s.Result.Success {
				status = "failed"
			}
			b.WriteString(fmt.Sprintf("  %s → %s\n", s.Decision.ID, status))
		}
	}

	b.WriteString("\nChoose one action:")
	return b.String()
}

// parseActionReply converts a raw LLM reply string into an Action selected
// from the provided action space.
//
// Accepted formats:
//
//	click_E1               — exact action ID
//	[click_E1]             — bracketed ID (some models add these)
//	type_E3: hello world   — action ID followed by a value
//	navigate: https://...  — navigate action with a URL
//	done                   — explicit task completion
func parseActionReply(raw string, actions []Action) (Action, error) {
	s := strings.TrimSpace(raw)

	// Strip leading/trailing brackets that some LLMs emit.
	s = strings.Trim(s, "[]")
	s = strings.TrimSpace(s)

	// Split on the first ": " to separate ID from optional value.
	id, value, _ := strings.Cut(s, ": ")
	id = strings.TrimSpace(id)
	value = strings.TrimSpace(value)

	// Look up by ID in the action space.
	for _, a := range actions {
		if a.ID == id {
			if value != "" {
				a = setActionValue(a, value)
			}
			return a, nil
		}
	}

	// "navigate" with a URL that isn't in the action space as a pre-built entry.
	if id == "navigate" && value != "" {
		return Action{
			ID:          "navigate",
			Type:        ActionNavigate,
			Description: "Navigate to URL",
			Parameters:  &NavigateParams{URL: value},
		}, nil
	}

	return Action{Type: ActionNone}, fmt.Errorf("unrecognised action %q from LLM", raw)
}

// setActionValue attaches a parameter value to a type/select/navigate action.
func setActionValue(a Action, value string) Action {
	switch a.Type {
	case ActionTypeText:
		if p, ok := a.Parameters.(*TypeParams); ok {
			p.Text = value
		} else {
			a.Parameters = &TypeParams{Text: value}
		}
	case ActionSelect, ActionToggle:
		if p, ok := a.Parameters.(*SelectParams); ok {
			p.Value = value
		} else {
			a.Parameters = &SelectParams{Value: value}
		}
	case ActionNavigate:
		if p, ok := a.Parameters.(*NavigateParams); ok {
			p.URL = value
		} else {
			a.Parameters = &NavigateParams{URL: value}
		}
	}
	return a
}
