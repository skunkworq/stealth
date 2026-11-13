package solver

import (
	"fmt"

	"github.com/skunkworq/stealth/brws/engine"
)

// The solver engines register themselves so a chain can name them.
func init() {
	engine.Register("flaresolverr", NewFlareSolverr)
	engine.Register("scrapling", func(opts engine.Options) (engine.Engine, error) {
		return NewHTTPSolver("scrapling", "STEALTH_SOLVER_SCRAPLING_URL", opts)
	})
	engine.Register("browseruse", func(opts engine.Options) (engine.Engine, error) {
		return NewHTTPSolver("browseruse", "STEALTH_SOLVER_BROWSERUSE_URL", opts)
	})
}

// EnvVarFor returns the environment variable that carries a solver's
// endpoint, so a caller can report where to point a tier.
func EnvVarFor(name string) string {
	switch name {
	case "flaresolverr":
		return DefaultFlareSolverrEnvVar
	case "scrapling":
		return "STEALTH_SOLVER_SCRAPLING_URL"
	case "browseruse":
		return "STEALTH_SOLVER_BROWSERUSE_URL"
	default:
		return fmt.Sprintf("STEALTH_SOLVER_%s_URL", name)
	}
}
