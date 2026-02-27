// Package instrumentation provides hooks for extensible stealth behavior.
package instrumentation

import (
	"context"
	"fmt"
	"sync"
)

// State represents a state in the FSM.
type State string

// Event represents an event that triggers state transitions.
type Event string

// FSM represents a finite state machine for request handling.
type FSM struct {
	name         string
	states       map[State]*StateConfig
	currentState State
	mu           sync.RWMutex
	transitionFn TransitionFunc
	stats        *FSMStats
}

// StateConfig holds configuration for a state.
type StateConfig struct {
	State         State
	Name          string
	Description   string
	EntryHooks    []Hook
	ExitHooks     []Hook
	TransitionMap map[Event]State
	OnEvent       func(ctx context.Context, event Event) error
}

// TransitionFunc is called when a transition occurs.
type TransitionFunc func(ctx context.Context, from, to State, event Event) error

// FSMStats holds FSM statistics.
type FSMStats struct {
	TransitionCount int
	StateCounts     map[State]int
	EventCounts     map[Event]int
	mu              sync.RWMutex
}

// NewFSM creates a new FSM.
func NewFSM(name string, initialState State) *FSM {
	return &FSM{
		name:         name,
		currentState: initialState,
		states:       make(map[State]*StateConfig),
		stats: &FSMStats{
			StateCounts: make(map[State]int),
			EventCounts: make(map[Event]int),
		},
	}
}

// AddState adds a state to the FSM.
func (f *FSM) AddState(config *StateConfig) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.states[config.State] = config
}

// SetTransitionFunc sets the transition callback function.
func (f *FSM) SetTransitionFunc(fn TransitionFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.transitionFn = fn
}

// GetState returns the current state.
func (f *FSM) GetState() State {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.currentState
}

// Transition performs a state transition.
func (f *FSM) Transition(ctx context.Context, event Event) error {
	f.mu.Lock()
	currentConfig, ok := f.states[f.currentState]
	if !ok {
		f.mu.Unlock()
		return fmt.Errorf("no config for state: %s", f.currentState)
	}

	nextState, ok := currentConfig.TransitionMap[event]
	if !ok {
		f.mu.Unlock()
		return fmt.Errorf("no transition from %s on event %s", f.currentState, event)
	}

	// Run exit hooks
	for _, hook := range currentConfig.ExitHooks {
		if err := hook(ctx); err != nil {
			f.mu.Unlock()
			return fmt.Errorf("exit hook failed: %w", err)
		}
	}

	// Call transition function
	if f.transitionFn != nil {
		if err := f.transitionFn(ctx, f.currentState, nextState, event); err != nil {
			f.mu.Unlock()
			return fmt.Errorf("transition fn failed: %w", err)
		}
	}

	// Update state
	f.currentState = nextState

	// Update stats
	f.stats.TransitionCount++
	f.stats.StateCounts[nextState]++
	f.stats.EventCounts[event]++
	f.mu.Unlock()

	// Run entry hooks for new state
	nextConfig, ok := f.states[nextState]
	if !ok {
		return nil
	}

	for _, hook := range nextConfig.EntryHooks {
		if err := hook(ctx); err != nil {
			return fmt.Errorf("entry hook failed: %w", err)
		}
	}

	// Run on-event handler
	if nextConfig.OnEvent != nil {
		return nextConfig.OnEvent(ctx, event)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	return nil
}

// GetStats returns FSM statistics.
func (f *FSM) GetStats() FSMStats {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return FSMStats{
		TransitionCount: f.stats.TransitionCount,
		StateCounts:     f.stats.StateCounts,
		EventCounts:     f.stats.EventCounts,
	}
}

// RequestStates defines the states for request handling.
var RequestStates = struct {
	Idle         State
	Initializing State
	Prepared     State
	Navigating   State
	Waiting      State
	Detecting    State
	Solving      State
	Extracting   State
	Complete     State
	Failed       State
}{
	Idle:         "idle",
	Initializing: "initializing",
	Prepared:     "prepared",
	Navigating:   "navigating",
	Waiting:      "waiting",
	Detecting:    "detecting",
	Solving:      "solving",
	Extracting:   "extracting",
	Complete:     "complete",
	Failed:       "failed",
}

// RequestEvents defines the events for request handling.
var RequestEvents = struct {
	Start             Event
	Prepared          Event
	Navigate          Event
	PageLoaded        Event
	ChallengeDetected Event
	ChallengeSolved   Event
	Extract           Event
	Complete          Event
	Retry             Event
	Fail              Event
}{
	Start:             "start",
	Prepared:          "prepared",
	Navigate:          "navigate",
	PageLoaded:        "page_loaded",
	ChallengeDetected: "challenge_detected",
	ChallengeSolved:   "challenge_solved",
	Extract:           "extract",
	Complete:          "complete",
	Retry:             "retry",
	Fail:              "fail",
}

// NewRequestFSM creates a new request FSM.
func NewRequestFSM() *FSM {
	fsm := NewFSM("request", RequestStates.Idle)

	// Idle state
	fsm.AddState(&StateConfig{
		State:       RequestStates.Idle,
		Name:        "Idle",
		Description: "FSM is idle, ready to start",
		TransitionMap: map[Event]State{
			RequestEvents.Start: RequestStates.Initializing,
		},
	})

	// Initializing state
	fsm.AddState(&StateConfig{
		State:       RequestStates.Initializing,
		Name:        "Initializing",
		Description: "Preparing browser and stealth scripts",
		TransitionMap: map[Event]State{
			RequestEvents.Prepared: RequestStates.Prepared,
			RequestEvents.Fail:     RequestStates.Failed,
		},
	})

	// Prepared state
	fsm.AddState(&StateConfig{
		State:       RequestStates.Prepared,
		Name:        "Prepared",
		Description: "Browser ready, can navigate",
		TransitionMap: map[Event]State{
			RequestEvents.Navigate: RequestStates.Navigating,
			RequestEvents.Fail:     RequestStates.Failed,
		},
	})

	// Navigating state
	fsm.AddState(&StateConfig{
		State:       RequestStates.Navigating,
		Name:        "Navigating",
		Description: "Navigating to URL",
		TransitionMap: map[Event]State{
			RequestEvents.PageLoaded:        RequestStates.Waiting,
			RequestEvents.Extract:           RequestStates.Extracting,
			RequestEvents.Complete:          RequestStates.Complete,
			RequestEvents.ChallengeDetected: RequestStates.Detecting,
			RequestEvents.Fail:              RequestStates.Failed,
		},
	})

	// Waiting state
	fsm.AddState(&StateConfig{
		State:       RequestStates.Waiting,
		Name:        "Waiting",
		Description: "Waiting for page to settle",
		TransitionMap: map[Event]State{
			RequestEvents.Extract:           RequestStates.Extracting,
			RequestEvents.Complete:          RequestStates.Complete,
			RequestEvents.ChallengeDetected: RequestStates.Detecting,
			RequestEvents.Fail:              RequestStates.Failed,
		},
	})

	// Detecting state
	fsm.AddState(&StateConfig{
		State:       RequestStates.Detecting,
		Name:        "Detecting",
		Description: "Detecting challenge type",
		TransitionMap: map[Event]State{
			RequestEvents.ChallengeSolved: RequestStates.Waiting,
			RequestEvents.Retry:           RequestStates.Navigating,
			RequestEvents.Fail:            RequestStates.Failed,
		},
	})

	// Solving state
	fsm.AddState(&StateConfig{
		State:       RequestStates.Solving,
		Name:        "Solving",
		Description: "Solving challenge",
		TransitionMap: map[Event]State{
			RequestEvents.ChallengeSolved: RequestStates.Waiting,
			RequestEvents.Retry:           RequestStates.Navigating,
			RequestEvents.Fail:            RequestStates.Failed,
		},
	})

	// Extracting state
	fsm.AddState(&StateConfig{
		State:       RequestStates.Extracting,
		Name:        "Extracting",
		Description: "Extracting content from page",
		TransitionMap: map[Event]State{
			RequestEvents.Complete: RequestStates.Complete,
			RequestEvents.Fail:     RequestStates.Failed,
		},
	})

	// Complete state
	fsm.AddState(&StateConfig{
		State:       RequestStates.Complete,
		Name:        "Complete",
		Description: "Request completed successfully",
		TransitionMap: map[Event]State{
			RequestEvents.Start: RequestStates.Initializing,
		},
	})

	// Failed state
	fsm.AddState(&StateConfig{
		State:       RequestStates.Failed,
		Name:        "Failed",
		Description: "Request failed",
		TransitionMap: map[Event]State{
			RequestEvents.Retry: RequestStates.Initializing,
		},
	})

	return fsm
}
