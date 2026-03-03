package challengefsm

import (
	"context"
	"testing"
)

func TestNewChallengeFSM(t *testing.T) {
	fsm := NewChallengeFSM("test")

	if fsm.GetState() != ChallengeStates.Idle {
		t.Fatalf("expected initial state Idle, got %s", fsm.GetState())
	}

	// Should transition Idle → Detecting
	err := fsm.Transition(context.Background(), ChallengeEvents.Detect)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fsm.GetState() != ChallengeStates.Detecting {
		t.Fatalf("expected Detecting, got %s", fsm.GetState())
	}

	// Detecting → Initializing
	err = fsm.Transition(context.Background(), ChallengeEvents.Init)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fsm.GetState() != ChallengeStates.Initializing {
		t.Fatalf("expected Initializing, got %s", fsm.GetState())
	}

	// Initializing → Solving
	err = fsm.Transition(context.Background(), ChallengeEvents.Solve)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fsm.GetState() != ChallengeStates.Solving {
		t.Fatalf("expected Solving, got %s", fsm.GetState())
	}

	// Solving → Submitting
	err = fsm.Transition(context.Background(), ChallengeEvents.Submit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fsm.GetState() != ChallengeStates.Submitting {
		t.Fatalf("expected Submitting, got %s", fsm.GetState())
	}

	// Submitting → Verifying
	err = fsm.Transition(context.Background(), ChallengeEvents.Verify)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fsm.GetState() != ChallengeStates.Verifying {
		t.Fatalf("expected Verifying, got %s", fsm.GetState())
	}

	// Verifying → Solved
	err = fsm.Transition(context.Background(), ChallengeEvents.Success)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fsm.GetState() != ChallengeStates.Solved {
		t.Fatalf("expected Solved, got %s", fsm.GetState())
	}
}

func TestChallengeFSMFailPath(t *testing.T) {
	fsm := NewChallengeFSM("test-fail")

	_ = fsm.Transition(context.Background(), ChallengeEvents.Detect)
	_ = fsm.Transition(context.Background(), ChallengeEvents.Init)
	_ = fsm.Transition(context.Background(), ChallengeEvents.Solve)

	// Solving → Failed
	err := fsm.Transition(context.Background(), ChallengeEvents.Fail)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fsm.GetState() != ChallengeStates.Failed {
		t.Fatalf("expected Failed, got %s", fsm.GetState())
	}
}

func TestChallengeFSMRetryPath(t *testing.T) {
	fsm := NewChallengeFSM("test-retry")

	_ = fsm.Transition(context.Background(), ChallengeEvents.Detect)
	_ = fsm.Transition(context.Background(), ChallengeEvents.Init)
	_ = fsm.Transition(context.Background(), ChallengeEvents.Solve)

	// Solving → Retrying
	err := fsm.Transition(context.Background(), ChallengeEvents.Retry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fsm.GetState() != ChallengeStates.Retrying {
		t.Fatalf("expected Retrying, got %s", fsm.GetState())
	}

	// Retrying → Solving (retry again)
	err = fsm.Transition(context.Background(), ChallengeEvents.Solve)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fsm.GetState() != ChallengeStates.Solving {
		t.Fatalf("expected Solving, got %s", fsm.GetState())
	}
}

func TestChallengeFSMEscalatePath(t *testing.T) {
	fsm := NewChallengeFSM("test-escalate")

	_ = fsm.Transition(context.Background(), ChallengeEvents.Detect)
	_ = fsm.Transition(context.Background(), ChallengeEvents.Init)
	_ = fsm.Transition(context.Background(), ChallengeEvents.Solve)

	// Solving → Escalating
	err := fsm.Transition(context.Background(), ChallengeEvents.Escalate)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fsm.GetState() != ChallengeStates.Escalating {
		t.Fatalf("expected Escalating, got %s", fsm.GetState())
	}

	// Escalating → Initializing
	err = fsm.Transition(context.Background(), ChallengeEvents.Init)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fsm.GetState() != ChallengeStates.Initializing {
		t.Fatalf("expected Initializing, got %s", fsm.GetState())
	}
}

func TestChallengeFSMInvalidTransition(t *testing.T) {
	fsm := NewChallengeFSM("test-invalid")

	// Idle → Solve should fail (invalid transition)
	err := fsm.Transition(context.Background(), ChallengeEvents.Solve)
	if err == nil {
		t.Fatal("expected error for invalid transition from Idle on Solve event")
	}
}

func TestCloudflareFSMSubStates(t *testing.T) {
	fsm := NewCloudflareFSM()

	if fsm.GetState() != ChallengeStates.Idle {
		t.Fatalf("expected initial state Idle, got %s", fsm.GetState())
	}

	// Cloudflare-specific sub-states should be registered
	stats := fsm.GetStats()
	if stats.TransitionCount != 0 {
		t.Fatalf("expected 0 transitions, got %d", stats.TransitionCount)
	}
}

func TestDataDomeFSMSubStates(t *testing.T) {
	fsm := NewDataDomeFSM()

	if fsm.GetState() != ChallengeStates.Idle {
		t.Fatalf("expected initial state Idle, got %s", fsm.GetState())
	}
}

func TestNewChallengeFSMStats(t *testing.T) {
	fsm := NewChallengeFSM("test-stats")

	_ = fsm.Transition(context.Background(), ChallengeEvents.Detect)
	_ = fsm.Transition(context.Background(), ChallengeEvents.Init)

	stats := fsm.GetStats()
	if stats.TransitionCount != 2 {
		t.Fatalf("expected 2 transitions, got %d", stats.TransitionCount)
	}
}
