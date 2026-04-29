// Package agent — Orchestrator
//
// The Agent is the top-level coordinator. It ties together:
//   - Observer   (perception / page context)
//   - Formatter  (LLM-friendly context representation)
//   - ActionSpace (possible next actions)
//   - Executor   (runs chosen actions on the browser)
//
// Designed for two primary workflows:
//  1. Reactive loop: observe → format → wait for external decision → execute → repeat
//  2. Autonomous loop: observe → format → decide (via LLM / policy) → execute → repeat
package agent

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/skunkworq/stealth/brws/content/semantic"
)

// Default configuration values.
const (
	DefaultMaxRetries    = 3
	DefaultSettleDelay   = 500 * time.Millisecond
	DefaultActionTimeout = 30 * time.Second
	DefaultHistorySize   = 50
)

// Config controls agent behavior.
type Config struct {
	MaxRetries    int           // How many times to retry a failed action
	SettleDelay   time.Duration // Wait after page changes before re-observing
	ActionTimeout time.Duration // Timeout for any single action
	HistorySize   int           // Max steps to keep in memory
	IncludeMedia  bool          // Include <img>/<video> in context (token-heavy)
	IncludeForms  bool          // Include <form> details in context
	CompactLinks  bool          // One-line link format vs full struct
	ScrollFirst   bool          // Prioritize scroll actions when building action space
	StealthMode   bool          // Use stealth-appropriate defaults (human delays, etc.)

	// SemanticMode enables semantic enrichment of observations.
	// When true, the observer will build a semantic tree and extract
	// page metadata, images, social links, colors, and fonts.
	SemanticMode bool
	// SemanticTreeLLM enables LLM-based semantic tree compression.
	// Requires OPENROUTER_API_KEY or an explicit PipelineConfig.
	SemanticTreeLLM bool
	// DescribeImages enables vision-based image descriptions.
	// Requires OPENROUTER_API_KEY or an explicit PipelineConfig.
	DescribeImages bool
	// PipelineConfig provides the semantic pipeline configuration.
	// If nil and LLM features are enabled, the agent attempts to
	// build a config from environment variables.
	PipelineConfig *semantic.PipelineConfig
	// Representation controls which page representation drives the
	// formatted prompt and action space.  "dom" (default) uses raw
	// CDP-extracted elements; "semantic" uses the semantic tree.
	Representation Representation
}

// DefaultConfig returns production-ready defaults.
func DefaultConfig() Config {
	return Config{
		MaxRetries:     DefaultMaxRetries,
		SettleDelay:    DefaultSettleDelay,
		ActionTimeout:  DefaultActionTimeout,
		HistorySize:    DefaultHistorySize,
		IncludeMedia:   false,
		IncludeForms:   true,
		CompactLinks:   true,
		ScrollFirst:    true,
		StealthMode:    true,
		Representation: RepresentationDOM,
	}
}

// ---------------------------------------------------------------------------
// Agent — main orchestrator
// ---------------------------------------------------------------------------

// Agent orchestrates the observe → decide → execute loop.
type Agent struct {
	cfg       Config
	observer  *Observer
	formatter *Formatter
	executor  *Executor

	mu        sync.RWMutex
	history   []Step   // Executed steps (oldest → newest)
	lastCtx   *Context // Most recent page context
	lastSpace []Action // Most recent action space
}

// Step represents one full cycle of the agent loop.
type Step struct {
	Timestamp   time.Time      `json:"timestamp"`
	Observation *Context       `json:"observation"`
	ActionSpace []Action       `json:"action_space"`
	Decision    Action         `json:"decision"`
	Result      *ExecuteResult `json:"result"`
	Formatted   string         `json:"formatted,omitempty"`
}

// NewAgent creates an agent with the given components.
// Any nil component gets a default instance.
func NewAgent(cfg Config, obs *Observer, fmttr *Formatter, exec *Executor) *Agent {
	if obs == nil {
		obs = DefaultObserver()
	}
	if fmttr == nil {
		fmttr = DefaultFormatter()
	}
	if exec == nil {
		exec = &Executor{}
	}

	// Wire semantic enhancer into the observer when semantic mode is on.
	if cfg.SemanticMode && obs.SemanticEnhancer == nil {
		obs.SemanticEnhancer = &SemanticEnhancer{
			EnableTree:     true,
			EnableTreeLLM:  cfg.SemanticTreeLLM,
			EnableMeta:     true,
			EnableImages:   true,
			EnableSocial:   true,
			EnableColors:   true,
			EnableFonts:    true,
			DescribeImages: cfg.DescribeImages,
			PipelineConfig: cfg.PipelineConfig,
		}
	}
	if cfg.SemanticMode {
		fmttr.IncludeMeta = true
		fmttr.IncludeImages = true
		fmttr.IncludeSemanticTree = true
	}
	fmttr.Representation = cfg.Representation

	return &Agent{
		cfg:       cfg,
		observer:  obs,
		formatter: fmttr,
		executor:  exec,
		history:   make([]Step, 0, cfg.HistorySize),
	}
}

// ---------------------------------------------------------------------------
// Core loop primitives
// ---------------------------------------------------------------------------

// Observe captures a fresh snapshot of the page, builds the action space,
// formats it for consumption, and returns everything.
func (a *Agent) Observe(ctx context.Context) (*Context, []Action, string, error) {
	// 1. Capture page state
	snap, err := a.observer.Observe(ctx)
	if err != nil {
		return nil, nil, "", fmt.Errorf("observe: %w", err)
	}

	// 2. Build context with both DOM and semantic action spaces
	agCtx := NewContext(snap)
	if snap.SemanticTree != nil {
		agCtx.SemanticActionSpace = BuildSemanticActionSpace(snap)
	}
	agCtx.Representation = a.cfg.Representation

	// 3. Choose active action space based on representation
	activeSpace := agCtx.ActionSpace
	if a.cfg.Representation == RepresentationSemantic && agCtx.SemanticActionSpace != nil {
		activeSpace = agCtx.SemanticActionSpace
	}

	// 4. Store for later
	a.mu.Lock()
	a.lastCtx = agCtx
	a.lastSpace = activeSpace.All()
	a.mu.Unlock()

	// 5. Format using the chosen representation
	var formatted string
	switch a.cfg.Representation {
	case RepresentationSemantic:
		formatted = a.formatter.FormatSemanticCompact(agCtx)
	default:
		formatted = a.formatter.FormatCompact(agCtx)
	}

	return agCtx, activeSpace.All(), formatted, nil
}

// Execute runs a single action and records the step in history.
func (a *Agent) Execute(ctx context.Context, action Action) (*ExecuteResult, error) {
	// Ensure timeout
	execCtx, cancel := context.WithTimeout(ctx, a.cfg.ActionTimeout)
	defer cancel()

	res, err := a.executor.Execute(execCtx, action)

	// Record step regardless of success/failure
	step := Step{
		Timestamp:   time.Now(),
		Observation: a.lastCtx,
		ActionSpace: a.lastSpace,
		Decision:    action,
		Result:      res,
	}
	if res != nil {
		step.Result = res
	}

	a.mu.Lock()
	a.history = append(a.history, step)
	if len(a.history) > a.cfg.HistorySize {
		a.history = a.history[len(a.history)-a.cfg.HistorySize:]
	}
	a.mu.Unlock()

	if err != nil {
		return res, fmt.Errorf("execute %s: %w", action.ID, err)
	}

	// Settle: wait for page to stabilize before next observation
	if a.cfg.SettleDelay > 0 {
		time.Sleep(a.cfg.SettleDelay)
	}

	return res, nil
}

// Step runs one full observe → execute cycle with the given decision function.
// The decideFn receives (context, actionSpace, formatted, history) and returns
// the chosen action. This is the primary integration point for LLMs or policies.
func (a *Agent) Step(ctx context.Context, decideFn func(*Context, []Action, string, []Step) (Action, error)) (*Step, error) {
	// 1. Observe
	pageCtx, actionSpace, formatted, err := a.Observe(ctx)
	if err != nil {
		return nil, err
	}

	// 2. Decide
	a.mu.RLock()
	hist := make([]Step, len(a.history))
	copy(hist, a.history)
	a.mu.RUnlock()

	action, err := decideFn(pageCtx, actionSpace, formatted, hist)
	if err != nil {
		return nil, fmt.Errorf("decide: %w", err)
	}

	// 3. Execute
	res, execErr := a.Execute(ctx, action)

	// 4. Build step record
	step := Step{
		Timestamp:   time.Now(),
		Observation: pageCtx,
		ActionSpace: actionSpace,
		Decision:    action,
		Result:      res,
		Formatted:   formatted,
	}

	return &step, execErr
}

// ---------------------------------------------------------------------------
// Convenience decision helpers (for non-LLM callers)
// ---------------------------------------------------------------------------

// Decisions returns a set of ready-made decision functions for common cases.
var Decisions = struct {
	// ClickFirstLink chooses the first available link action.
	ClickFirstLink func(*Context, []Action, string, []Step) (Action, error)

	// ScrollThenClick scrolls down once, then clicks the first link.
	ScrollThenClick func(*Context, []Action, string, []Step) (Action, error)

	// ScrollToBottom keeps scrolling until no more scroll actions remain.
	ScrollToBottom func(*Context, []Action, string, []Step) (Action, error)

	// SubmitFirstForm fills and submits the first form found.
	SubmitFirstForm func(*Context, []Action, string, []Step) (Action, error)
}{
	ClickFirstLink: func(ctx *Context, actions []Action, formatted string, hist []Step) (Action, error) {
		for _, a := range actions {
			if a.Type == ActionClick && a.IsLink {
				return a, nil
			}
		}
		return Action{Type: ActionNone}, fmt.Errorf("no link actions available")
	},

	ScrollThenClick: func(ctx *Context, actions []Action, formatted string, hist []Step) (Action, error) {
		// If we haven't scrolled yet in this session, scroll down first
		for _, s := range hist {
			if s.Decision.Type == ActionScrollDown || s.Decision.Type == ActionScrollTo {
				// Already scrolled, now click first link
				for _, a := range actions {
					if a.Type == ActionClick && a.IsLink {
						return a, nil
					}
				}
				return Action{Type: ActionNone}, fmt.Errorf("no link actions available after scroll")
			}
		}
		// First action: scroll down
		for _, a := range actions {
			if a.Type == ActionScrollDown {
				return a, nil
			}
		}
		return Action{Type: ActionNone}, fmt.Errorf("no scroll action available")
	},

	ScrollToBottom: func(ctx *Context, actions []Action, formatted string, hist []Step) (Action, error) {
		for _, a := range actions {
			if a.Type == ActionScrollDown {
				return a, nil
			}
		}
		// No more scroll actions — we're at the bottom
		return Action{Type: ActionNone}, fmt.Errorf("at bottom of page")
	},

	SubmitFirstForm: func(ctx *Context, actions []Action, formatted string, hist []Step) (Action, error) {
		for _, a := range actions {
			if a.Type == ActionTypeText || a.Type == ActionSelect {
				// Fill the first input, then look for submit
				return a, nil
			}
			if a.Type == ActionClick && a.IsFormSubmit {
				return a, nil
			}
		}
		return Action{Type: ActionNone}, fmt.Errorf("no form actions available")
	},
}

// ---------------------------------------------------------------------------
// History & state access
// ---------------------------------------------------------------------------

// History returns a copy of the step history.
func (a *Agent) History() []Step {
	a.mu.RLock()
	defer a.mu.RUnlock()
	h := make([]Step, len(a.history))
	copy(h, a.history)
	return h
}

// LastContext returns the most recently observed page context.
func (a *Agent) LastContext() *Context {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.lastCtx == nil {
		return nil
	}
	// Return copy to prevent external mutation
	c := *a.lastCtx
	return &c
}

// LastActionSpace returns the most recently built action space.
func (a *Agent) LastActionSpace() []Action {
	a.mu.RLock()
	defer a.mu.RUnlock()
	acts := make([]Action, len(a.lastSpace))
	copy(acts, a.lastSpace)
	return acts
}

// Summary returns a one-line status of the agent.
func (a *Agent) Summary() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	url := "(none)"
	if a.lastCtx != nil && a.lastCtx.Snapshot != nil {
		url = a.lastCtx.Snapshot.URL
	}
	return fmt.Sprintf("Agent[%d steps] @ %s | %d actions available",
		len(a.history), url, len(a.lastSpace))
}
