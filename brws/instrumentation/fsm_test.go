package instrumentation

import (
	"context"
	"testing"
)

func TestFSM_NewFSM(t *testing.T) {
	fsm := NewFSM("test", RequestStates.Idle)
	if fsm == nil {
		t.Fatal("expected non-nil FSM")
	}

	if fsm.name != "test" {
		t.Errorf("expected name 'test', got %q", fsm.name)
	}

	if fsm.currentState != RequestStates.Idle {
		t.Errorf("expected initial state 'idle', got %q", fsm.currentState)
	}
}

func TestFSM_AddState(t *testing.T) {
	fsm := NewFSM("test", RequestStates.Idle)

	fsm.AddState(&StateConfig{
		State: RequestStates.Initializing,
		Name:  "Initializing",
		TransitionMap: map[Event]State{
			RequestEvents.Prepared: RequestStates.Prepared,
		},
	})

	if fsm.currentState != RequestStates.Idle {
		t.Error("AddState should not change current state")
	}
}

func TestFSM_Transition_Success(t *testing.T) {
	fsm := NewRequestFSM()
	ctx := context.Background()

	err := fsm.Transition(ctx, RequestEvents.Start)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if fsm.GetState() != RequestStates.Initializing {
		t.Errorf("expected state 'initializing', got %q", fsm.GetState())
	}
}

func TestFSM_Transition_InvalidEvent(t *testing.T) {
	fsm := NewFSM("test", RequestStates.Idle)
	ctx := context.Background()

	// No transition from idle on "prepared"
	err := fsm.Transition(ctx, RequestEvents.Prepared)
	if err == nil {
		t.Error("expected error for invalid transition")
	}
}

func TestFSM_Transition_InvalidState(t *testing.T) {
	fsm := NewFSM("test", State("invalid"))
	ctx := context.Background()

	err := fsm.Transition(ctx, RequestEvents.Start)
	if err == nil {
		t.Error("expected error for invalid initial state")
	}
}

func TestFSM_GetStats(t *testing.T) {
	fsm := NewRequestFSM()
	ctx := context.Background()

	fsm.Transition(ctx, RequestEvents.Start)
	fsm.Transition(ctx, RequestEvents.Prepared)
	fsm.Transition(ctx, RequestEvents.Navigate)

	stats := fsm.GetStats()

	if stats.TransitionCount != 3 {
		t.Errorf("expected 3 transitions, got %d", stats.TransitionCount)
	}

	if stats.StateCounts[RequestStates.Navigating] != 1 {
		t.Errorf("expected 1 visit to navigating state, got %d", stats.StateCounts[RequestStates.Navigating])
	}
}

func TestFSM_SetTransitionFunc(t *testing.T) {
	fsm := NewRequestFSM()
	ctx := context.Background()

	called := false
	fsm.SetTransitionFunc(func(ctx context.Context, from, to State, event Event) error {
		called = true
		return nil
	})

	fsm.Transition(ctx, RequestEvents.Start)

	if !called {
		t.Error("expected transition func to be called")
	}
}

func TestRequestFSM_FullFlow(t *testing.T) {
	fsm := NewRequestFSM()
	ctx := context.Background()

	// Full happy path: idle -> initializing -> prepared -> navigating -> waiting -> extracting -> complete
	transitions := []Event{
		RequestEvents.Start,      // idle -> initializing
		RequestEvents.Prepared,   // initializing -> prepared
		RequestEvents.Navigate,   // prepared -> navigating
		RequestEvents.PageLoaded, // navigating -> waiting
		RequestEvents.Extract,    // waiting -> extracting
		RequestEvents.Complete,   // extracting -> complete
	}

	for _, event := range transitions {
		err := fsm.Transition(ctx, event)
		if err != nil {
			t.Fatalf("transition %q failed: %v", event, err)
		}
	}

	if fsm.GetState() != RequestStates.Complete {
		t.Errorf("expected final state 'complete', got %q", fsm.GetState())
	}
}

func TestRequestFSM_RetryFlow(t *testing.T) {
	fsm := NewRequestFSM()
	ctx := context.Background()

	// idle -> initializing -> prepared -> navigating
	fsm.Transition(ctx, RequestEvents.Start)
	fsm.Transition(ctx, RequestEvents.Prepared)
	fsm.Transition(ctx, RequestEvents.Navigate)

	// Simulate failure and retry
	err := fsm.Transition(ctx, RequestEvents.Fail)
	if err != nil {
		t.Fatalf("transition fail failed: %v", err)
	}

	if fsm.GetState() != RequestStates.Failed {
		t.Errorf("expected state 'failed', got %q", fsm.GetState())
	}

	// Retry
	err = fsm.Transition(ctx, RequestEvents.Retry)
	if err != nil {
		t.Fatalf("transition retry failed: %v", err)
	}

	if fsm.GetState() != RequestStates.Initializing {
		t.Errorf("expected state 'initializing' after retry, got %q", fsm.GetState())
	}
}
