package challengefsm

import (
	"sync"

	"github.com/stealth/brwslab/brws/challenge"
)

// SolverRegistry maps challenge types to solvers. Solvers are checked in
// priority order (first registered = highest priority).
type SolverRegistry struct {
	mu      sync.RWMutex
	solvers []ChallengeSolver
}

// NewSolverRegistry creates an empty solver registry.
func NewSolverRegistry() *SolverRegistry {
	return &SolverRegistry{}
}

// Register adds a solver to the registry. Solvers added first have higher priority.
func (r *SolverRegistry) Register(solver ChallengeSolver) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.solvers = append(r.solvers, solver)
}

// FindSolver returns the first registered solver that can handle the given
// challenge, or nil if no solver matches.
func (r *SolverRegistry) FindSolver(ch *challenge.Challenge) ChallengeSolver {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.solvers {
		if s.CanSolve(ch) {
			return s
		}
	}
	return nil
}

// Solvers returns a copy of all registered solvers.
func (r *SolverRegistry) Solvers() []ChallengeSolver {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]ChallengeSolver, len(r.solvers))
	copy(result, r.solvers)
	return result
}
