package tracing

// Type aliases and var forwards so research/detection/tracing uses the
// canonical TraceLibrary from brws/stealth/challenge.
import "github.com/skunkworq/stealth/brws/stealth/challenge"

type (
	TraceLibrary        = challenge.TraceLibrary
	TraceLibrarySummary = challenge.TraceLibrarySummary
	ReplayParams        = challenge.ReplayParams
)

var (
	NewTraceLibrary     = challenge.NewTraceLibrary
	DefaultReplayParams = challenge.DefaultReplayParams
	Replay              = challenge.Replay
	Interpolate         = challenge.Interpolate
	TraceFingerprint    = challenge.TraceFingerprint
)
