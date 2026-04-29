// Package instrumentation provides hooks for extensible stealth behavior.
package instrumentation

import (
	"context"
	"sync"
)

// Hook is a function that can be called at specific points.
type Hook func(ctx context.Context) error

// HookRegistry is a registry for hooks.
type HookRegistry struct {
	mu    sync.RWMutex
	hooks map[string][]Hook
}

// NewHookRegistry creates a new hook registry.
func NewHookRegistry() *HookRegistry {
	return &HookRegistry{
		hooks: make(map[string][]Hook),
	}
}

// Register registers a hook for a given name.
func (r *HookRegistry) Register(name string, hook Hook) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hooks[name] = append(r.hooks[name], hook)
}

// Execute executes all hooks for a given name.
func (r *HookRegistry) Execute(ctx context.Context, name string) error {
	r.mu.RLock()
	hooks, ok := r.hooks[name]
	r.mu.RUnlock()

	if !ok {
		return nil
	}

	for _, hook := range hooks {
		if err := hook(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Unregister removes all hooks for a given name.
func (r *HookRegistry) Unregister(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.hooks, name)
}

// List returns all registered hook names.
func (r *HookRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.hooks))
	for name := range r.hooks {
		names = append(names, name)
	}
	return names
}

// HookNames defines the available hook names for the stealth engine.
var HookNames = struct {
	// Browser hooks
	OnBrowserStart string
	OnBrowserClose string
	OnTabCreate    string
	OnTabClose     string

	// Request hooks
	OnRequestStart   string
	OnRequestEnd     string
	OnBeforeNavigate string
	OnAfterNavigate  string

	// Stealth hooks
	OnStealthInject string
	OnCanvasNoise   string
	OnWebGLSpoof    string

	// Challenge hooks
	OnChallengeDetect string
	OnChallengeSolve  string
	OnChallengeSolved string

	// Behavior hooks
	OnMouseMove string
	OnType      string
	OnScroll    string

	// Error hooks
	OnError string
}{
	OnBrowserStart:    "browser.start",
	OnBrowserClose:    "browser.close",
	OnTabCreate:       "tab.create",
	OnTabClose:        "tab.close",
	OnRequestStart:    "request.start",
	OnRequestEnd:      "request.end",
	OnBeforeNavigate:  "navigate.before",
	OnAfterNavigate:   "navigate.after",
	OnStealthInject:   "stealth.inject",
	OnCanvasNoise:     "stealth.canvas",
	OnWebGLSpoof:      "stealth.webgl",
	OnChallengeDetect: "challenge.detect",
	OnChallengeSolve:  "challenge.solve",
	OnChallengeSolved: "challenge.solved",
	OnMouseMove:       "behavior.mouse",
	OnType:            "behavior.type",
	OnScroll:          "behavior.scroll",
	OnError:           "error",
}

// DefaultHookRegistry returns a default hook registry with standard hooks.
func DefaultHookRegistry() *HookRegistry {
	registry := NewHookRegistry()

	// Add default no-op hooks for all names
	for _, name := range []string{
		HookNames.OnBrowserStart,
		HookNames.OnBrowserClose,
		HookNames.OnTabCreate,
		HookNames.OnTabClose,
		HookNames.OnRequestStart,
		HookNames.OnRequestEnd,
		HookNames.OnBeforeNavigate,
		HookNames.OnAfterNavigate,
		HookNames.OnStealthInject,
		HookNames.OnCanvasNoise,
		HookNames.OnWebGLSpoof,
		HookNames.OnChallengeDetect,
		HookNames.OnChallengeSolve,
		HookNames.OnChallengeSolved,
		HookNames.OnMouseMove,
		HookNames.OnType,
		HookNames.OnScroll,
		HookNames.OnError,
	} {
		registry.Register(name, func(_ context.Context) error { return nil })
	}

	return registry
}
