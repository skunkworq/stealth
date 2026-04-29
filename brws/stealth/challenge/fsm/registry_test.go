package fsm

import (
	"testing"

	"github.com/skunkworq/stealth/brws/stealth/challenge"
)

func TestRegistryEmpty(t *testing.T) {
	registry := NewSolverRegistry()

	ch := &challenge.Challenge{Type: challenge.ChallengeCloudflare}
	solver := registry.FindSolver(ch)
	if solver != nil {
		t.Fatal("expected nil solver from empty registry")
	}

	solvers := registry.Solvers()
	if len(solvers) != 0 {
		t.Fatalf("expected 0 solvers, got %d", len(solvers))
	}
}

func TestRegistryFindSolver(t *testing.T) {
	registry := NewSolverRegistry()

	cfSolver := &mockSolver{provider: "cloudflare", canSolve: false}
	ddSolver := &mockSolver{provider: "datadome", canSolve: true}

	registry.Register(cfSolver)
	registry.Register(ddSolver)

	ch := &challenge.Challenge{Type: challenge.ChallengeDataDome}
	solver := registry.FindSolver(ch)
	if solver == nil {
		t.Fatal("expected solver to be found")
	}
	if solver.Provider() != "datadome" {
		t.Fatalf("expected datadome provider, got %s", solver.Provider())
	}
}

func TestRegistryPriority(t *testing.T) {
	registry := NewSolverRegistry()

	first := &mockSolver{provider: "first", canSolve: true}
	second := &mockSolver{provider: "second", canSolve: true}

	registry.Register(first)
	registry.Register(second)

	ch := &challenge.Challenge{Type: challenge.ChallengeGeneric}
	solver := registry.FindSolver(ch)
	if solver.Provider() != "first" {
		t.Fatalf("expected first solver (priority), got %s", solver.Provider())
	}
}

func TestRegistrySolversCopy(t *testing.T) {
	registry := NewSolverRegistry()
	registry.Register(&mockSolver{provider: "a"})
	registry.Register(&mockSolver{provider: "b"})

	solvers := registry.Solvers()
	if len(solvers) != 2 {
		t.Fatalf("expected 2 solvers, got %d", len(solvers))
	}

	// Modifying the returned slice shouldn't affect the registry
	solvers[0] = nil
	original := registry.Solvers()
	if original[0] == nil {
		t.Fatal("modifying returned slice should not affect registry")
	}
}
