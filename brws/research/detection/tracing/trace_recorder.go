package tracing

// Type aliases so research/detection/tracing uses the canonical definitions
// from brws/stealth/challenge without duplicating them.
import "github.com/skunkworq/stealth/brws/stealth/challenge"

type (
	CaptchaEvent          = challenge.CaptchaEvent
	ChallengeType         = challenge.ChallengeType
	TraceSession          = challenge.TraceSession
	TraceEnvironment      = challenge.TraceEnvironment
	TraceRecording        = challenge.TraceRecording
	TracePhase            = challenge.TracePhase
	WidgetBounds          = challenge.WidgetBounds
	TraceRecordingMetrics = challenge.TraceRecordingMetrics
	TraceRecorder         = challenge.TraceRecorder
)

var NewTraceRecorder = challenge.NewTraceRecorder
