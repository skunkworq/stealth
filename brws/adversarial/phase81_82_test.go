package adversarial_test

import (
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
)

func TestPhases81_82Integration(t *testing.T) {
	detector := adversarial.NewStealthDetector()

	// Use Mac profile to trigger renderer mismatch (ForceDetections will inject NVIDIA on Mac)
	config := &behavior.RequestGeneratorConfig{
		Profile:         behavior.ChromeMacOSProfile(),
		ForceDetections: true,
	}
	ag := behavior.NewAdaptiveRequestGenerator(config)

	// Round 1: No evasion
	ag.GetConfig().EvadeWebGLRendererDeep = false
	ag.GetConfig().EvadeAudioContextDeep = false

	req1 := ag.GenerateRequest("https://example.com")
	det1 := detector.AnalyzeRequest(req1, nil)
	report1 := det1.ToDetectionReport()
	fired1 := report1.FiredCheckNames()
	t.Logf("Round 1: Fired checks: %v", fired1)

	hasRendererMismatch := false
	hasAudioStateMismatch := false
	hasAudioLatencyMismatch := false
	for _, name := range fired1 {
		if name == "renderer_platform_mismatch" {
			hasRendererMismatch = true
		}
		if name == "audio_context_static_state" {
			hasAudioStateMismatch = true
		}
		if name == "audio_latency_improbable" {
			hasAudioLatencyMismatch = true
		}
	}

	if !hasRendererMismatch {
		t.Errorf("Phase 81 detection failed: missing renderer_platform_mismatch")
	}
	if !hasAudioStateMismatch {
		t.Errorf("Phase 82 detection failed: missing audio_context_static_state")
	}
	if !hasAudioLatencyMismatch {
		t.Errorf("Phase 82 detection failed: missing audio_latency_improbable")
	}

	// Round 2: Apply feedback
	ag.ApplyFeedback(report1)

	req2 := ag.GenerateRequest("https://example.com")
	det2 := detector.AnalyzeRequest(req2, nil)
	report2 := det2.ToDetectionReport()
	fired2 := report2.FiredCheckNames()
	t.Logf("Round 2: Fired checks: %v", fired2)

	for _, name := range fired2 {
		if name == "renderer_platform_mismatch" || name == "audio_context_static_state" || name == "audio_latency_improbable" {
			t.Errorf("Detection leakage in round 2: %s", name)
		}
	}
}
