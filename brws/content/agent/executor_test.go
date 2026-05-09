package agent

import (
	"testing"

	"github.com/skunkworq/stealth/brws/stealth"
)

func TestExecutorStealthClientField(t *testing.T) {
	exec := &Executor{}
	if exec.StealthClient != nil {
		t.Fatal("expected nil StealthClient by default")
	}

	// Compile-time check that StealthClient field exists and has correct type.
	var _ *stealth.Client = exec.StealthClient
}

func TestExecuteResultChallengeSolvedField(t *testing.T) {
	res := &ExecuteResult{ChallengeSolved: true}
	if !res.ChallengeSolved {
		t.Fatal("expected ChallengeSolved to be true")
	}
}
