package adversarial

import (
	"fmt"
	"time"
)

// --- Cloudflare Challenge Types ---

// CloudflareJSChallengeMode enumerates the Cloudflare challenge types.
const (
	CFChallengeJS        = "js_challenge"      // 5-second JS compute challenge
	CFChallengeManaged   = "managed_challenge" // Cloudflare-managed (may or may not show Turnstile)
	CFChallengeTurnstile = "turnstile"         // explicit Turnstile widget
)

// CloudflareLabChallenge models a Cloudflare challenge in the lab.
type CloudflareLabChallenge struct {
	Type              string                 `json:"type"`           // js_challenge, managed_challenge, turnstile
	SecurityLevel     string                 `json:"security_level"` // low, medium, high, under_attack
	RayID             string                 `json:"ray_id,omitempty"`
	Widget            *TurnstileWidgetConfig `json:"widget,omitempty"`   // for managed/turnstile types
	JSComputeMs       int64                  `json:"js_compute_ms"`      // expected JS compute duration
	ExpectedCallbacks []string               `json:"expected_callbacks"` // expected callback order
	CreatedAt         time.Time              `json:"created_at"`
	ExpiresAt         time.Time              `json:"expires_at"`
}

// CloudflareLabProof captures the solve attempt for a Cloudflare challenge.
type CloudflareLabProof struct {
	Type              string                     `json:"type"`
	Events            []CaptchaEvent             `json:"events"`
	WidgetTelemetry   *WidgetTelemetry           `json:"widget_telemetry,omitempty"`
	InteractionProof  *TurnstileInteractionProof `json:"interaction_proof,omitempty"`
	JSComputeActualMs int64                      `json:"js_compute_actual_ms"`
	CallbackOrder     []string                   `json:"callback_order"`
	TotalDurationMs   int64                      `json:"total_duration_ms"`
	Token             string                     `json:"token,omitempty"`
}

// DefaultCloudflareJSChallenge returns a standard JS challenge config.
func DefaultCloudflareJSChallenge() CloudflareLabChallenge {
	now := time.Now().UTC()
	return CloudflareLabChallenge{
		Type:          CFChallengeJS,
		SecurityLevel: "medium",
		JSComputeMs:   3000, // ~3 second compute
		ExpectedCallbacks: []string{
			"challenge_start",
			"js_compute_begin",
			"js_compute_end",
			"challenge_complete",
		},
		CreatedAt: now,
		ExpiresAt: now.Add(30 * time.Second),
	}
}

// DefaultCloudflareManagedChallenge returns a managed challenge with a Turnstile widget.
func DefaultCloudflareManagedChallenge(sessionID string, detectionScore float64) CloudflareLabChallenge {
	now := time.Now().UTC()
	widget := turnstileWidgetConfigForRisk(sessionID, detectionScore)
	return CloudflareLabChallenge{
		Type:          CFChallengeManaged,
		SecurityLevel: widget.RiskLevel,
		Widget:        &widget,
		JSComputeMs:   1500, // managed has shorter JS phase
		ExpectedCallbacks: []string{
			"challenge_start",
			"before-interactive",
			"after-interactive",
			"interaction",
			"success",
		},
		CreatedAt: now,
		ExpiresAt: now.Add(5 * time.Minute),
	}
}

// DefaultCloudflareTurnstile returns a standalone Turnstile challenge.
func DefaultCloudflareTurnstile(sessionID string, detectionScore float64) CloudflareLabChallenge {
	now := time.Now().UTC()
	widget := turnstileWidgetConfigForRisk(sessionID, detectionScore)
	return CloudflareLabChallenge{
		Type:          CFChallengeTurnstile,
		SecurityLevel: widget.RiskLevel,
		Widget:        &widget,
		ExpectedCallbacks: []string{
			"before-interactive",
			"after-interactive",
			"success",
		},
		CreatedAt: now,
		ExpiresAt: now.Add(5 * time.Minute),
	}
}

// ValidateCloudflareProof checks if the solve attempt matches expected behavior.
func ValidateCloudflareProof(ch CloudflareLabChallenge, proof CloudflareLabProof) (bool, []TurnstileHeuristicSignal) {
	var signals []TurnstileHeuristicSignal

	switch ch.Type {
	case CFChallengeJS:
		return validateJSChallenge(ch, proof, &signals)
	case CFChallengeManaged:
		return validateManagedChallenge(ch, proof, &signals)
	case CFChallengeTurnstile:
		return validateTurnstileChallenge(ch, proof, &signals)
	default:
		signals = append(signals, TurnstileHeuristicSignal{
			Name: "unknown_challenge_type", Weight: 1.0,
			Detail: fmt.Sprintf("type=%s", ch.Type),
		})
		return false, signals
	}
}

func validateJSChallenge(ch CloudflareLabChallenge, proof CloudflareLabProof, signals *[]TurnstileHeuristicSignal) (bool, []TurnstileHeuristicSignal) {
	// 1. JS compute time should be realistic
	if proof.JSComputeActualMs > 0 {
		ratio := float64(proof.JSComputeActualMs) / float64(ch.JSComputeMs)
		if ratio < 0.3 {
			// Way too fast — likely skipped the compute
			*signals = append(*signals, TurnstileHeuristicSignal{
				Name: "js_compute_too_fast", Weight: 0.6,
				Detail: fmt.Sprintf("computed in %dms, expected ~%dms (%.0f%%)", proof.JSComputeActualMs, ch.JSComputeMs, ratio*100),
			})
		}
		if ratio > 5.0 {
			// Very slow — might be debugging or VM
			*signals = append(*signals, TurnstileHeuristicSignal{
				Name: "js_compute_too_slow", Weight: 0.3,
				Detail: fmt.Sprintf("computed in %dms, expected ~%dms", proof.JSComputeActualMs, ch.JSComputeMs),
			})
		}
	}

	// 2. Callback ordering
	if !callbackOrderValid(ch.ExpectedCallbacks, proof.CallbackOrder) {
		*signals = append(*signals, TurnstileHeuristicSignal{
			Name: "callback_order_violation", Weight: 0.4,
			Detail: fmt.Sprintf("expected %v, got %v", ch.ExpectedCallbacks, proof.CallbackOrder),
		})
	}

	// 3. Some mouse activity expected during JS challenge (user waits on page)
	mouseEvents := 0
	for _, e := range proof.Events {
		if e.Type == "mousemove" {
			mouseEvents++
		}
	}
	if mouseEvents == 0 && proof.TotalDurationMs > 2000 {
		*signals = append(*signals, TurnstileHeuristicSignal{
			Name: "no_mouse_during_wait", Weight: 0.2,
			Detail: "no mouse movement during JS challenge wait period",
		})
	}

	score := signalScore(*signals)
	return score < 0.75, *signals
}

func validateManagedChallenge(ch CloudflareLabChallenge, proof CloudflareLabProof, signals *[]TurnstileHeuristicSignal) (bool, []TurnstileHeuristicSignal) {
	// Managed challenge = JS compute + optional Turnstile interaction

	// 1. JS phase timing
	if proof.JSComputeActualMs > 0 && proof.JSComputeActualMs < int64(float64(ch.JSComputeMs)*0.3) {
		*signals = append(*signals, TurnstileHeuristicSignal{
			Name: "js_phase_too_fast", Weight: 0.4,
			Detail: fmt.Sprintf("%dms (expected ~%dms)", proof.JSComputeActualMs, ch.JSComputeMs),
		})
	}

	// 2. Callback ordering
	if !callbackOrderValid(ch.ExpectedCallbacks, proof.CallbackOrder) {
		*signals = append(*signals, TurnstileHeuristicSignal{
			Name: "managed_callback_violation", Weight: 0.3,
			Detail: fmt.Sprintf("got %v", proof.CallbackOrder),
		})
	}

	// 3. Widget telemetry checks
	if proof.WidgetTelemetry != nil {
		wt := proof.WidgetTelemetry
		// before-interactive should come before after-interactive
		if !wt.BeforeAt.IsZero() && !wt.AfterAt.IsZero() && wt.AfterAt.Before(wt.BeforeAt) {
			*signals = append(*signals, TurnstileHeuristicSignal{
				Name: "callback_temporal_anomaly", Weight: 0.5,
				Detail: "after-interactive fired before before-interactive",
			})
		}
		// Duplicate callbacks suggest replay
		if wt.DuplicateCallbacks > 2 {
			*signals = append(*signals, TurnstileHeuristicSignal{
				Name: "excessive_duplicate_callbacks", Weight: 0.3,
				Detail: fmt.Sprintf("%d duplicates", wt.DuplicateCallbacks),
			})
		}
	}

	// 4. Interaction proof validation (if widget requires interaction)
	if ch.Widget != nil && proof.InteractionProof != nil {
		switch ch.Widget.Interaction.Type {
		case turnstileInteractionRotate:
			passed, interactionSignals := ValidateRotateProof(ch.Widget.Interaction, *proof.InteractionProof)
			*signals = append(*signals, interactionSignals...)
			if !passed {
				return false, *signals
			}
		case turnstileInteractionSlidePuzzle:
			passed, interactionSignals := ValidateSlidePuzzleProof(ch.Widget.Interaction, *proof.InteractionProof)
			*signals = append(*signals, interactionSignals...)
			if !passed {
				return false, *signals
			}
		}
	}

	score := signalScore(*signals)
	return score < 0.75, *signals
}

func validateTurnstileChallenge(ch CloudflareLabChallenge, proof CloudflareLabProof, signals *[]TurnstileHeuristicSignal) (bool, []TurnstileHeuristicSignal) {
	// Standalone Turnstile: callback order + interaction

	// 1. Callback ordering
	if !callbackOrderValid(ch.ExpectedCallbacks, proof.CallbackOrder) {
		*signals = append(*signals, TurnstileHeuristicSignal{
			Name: "turnstile_callback_violation", Weight: 0.3,
			Detail: fmt.Sprintf("got %v", proof.CallbackOrder),
		})
	}

	// 2. Widget telemetry
	if proof.WidgetTelemetry != nil {
		wt := proof.WidgetTelemetry
		if !wt.CallbackState.BeforeInteractive {
			*signals = append(*signals, TurnstileHeuristicSignal{
				Name: "missing_before_interactive", Weight: 0.4,
				Detail: "before-interactive callback never fired",
			})
		}
		if !wt.CallbackState.Success && proof.Token != "" {
			*signals = append(*signals, TurnstileHeuristicSignal{
				Name: "token_without_success_callback", Weight: 0.5,
				Detail: "token issued but success callback never fired",
			})
		}
	}

	// 3. Interaction proof
	if ch.Widget != nil && proof.InteractionProof != nil {
		switch ch.Widget.Interaction.Type {
		case turnstileInteractionRotate:
			passed, interactionSignals := ValidateRotateProof(ch.Widget.Interaction, *proof.InteractionProof)
			*signals = append(*signals, interactionSignals...)
			if !passed {
				return false, *signals
			}
		case turnstileInteractionSlidePuzzle:
			passed, interactionSignals := ValidateSlidePuzzleProof(ch.Widget.Interaction, *proof.InteractionProof)
			*signals = append(*signals, interactionSignals...)
			if !passed {
				return false, *signals
			}
		case turnstileInteractionCheckbox:
			// Checkbox is simple but should have natural timing
			if proof.TotalDurationMs < 200 {
				*signals = append(*signals, TurnstileHeuristicSignal{
					Name: "checkbox_too_fast", Weight: 0.4,
					Detail: fmt.Sprintf("checked in %dms", proof.TotalDurationMs),
				})
			}
		case turnstileInteractionHold:
			if proof.InteractionProof.HoldDurationMs > 0 && ch.Widget.Interaction.RequiredHoldMs > 0 {
				if proof.InteractionProof.HoldDurationMs < ch.Widget.Interaction.RequiredHoldMs {
					*signals = append(*signals, TurnstileHeuristicSignal{
						Name: "hold_too_short", Weight: 0.5,
						Detail: fmt.Sprintf("held %dms, need %dms", proof.InteractionProof.HoldDurationMs, ch.Widget.Interaction.RequiredHoldMs),
					})
				}
			}
		case turnstileInteractionDrag:
			if proof.InteractionProof.DragDistancePx < ch.Widget.Interaction.RequiredDragDistancePx {
				*signals = append(*signals, TurnstileHeuristicSignal{
					Name: "drag_too_short", Weight: 0.5,
					Detail: fmt.Sprintf("dragged %dpx, need %dpx", proof.InteractionProof.DragDistancePx, ch.Widget.Interaction.RequiredDragDistancePx),
				})
			}
		}
	}

	// 4. Event stream behavioral check
	if len(proof.Events) > 0 {
		metrics := computeRecordingMetrics(proof.Events)
		if metrics.Straightness > 0.98 && metrics.MouseMoves > 5 {
			*signals = append(*signals, TurnstileHeuristicSignal{
				Name: "linear_mouse_trajectory", Weight: 0.3,
				Detail: fmt.Sprintf("straightness=%.3f", metrics.Straightness),
			})
		}
	}

	score := signalScore(*signals)
	return score < 0.75, *signals
}

// --- Cloudflare Solvers ---

// SolveCloudflareJSChallenge generates events mimicking a user waiting through a JS challenge.
func SolveCloudflareJSChallenge(ch CloudflareLabChallenge, rng func() float64) CloudflareLabProof {
	proof := CloudflareLabProof{
		Type: CFChallengeJS,
	}

	baseMs := int64(0)

	// Phase 1: User arrives at page, moves mouse idly while waiting
	idleMoves := 5 + int(rng()*8)
	for range idleMoves {
		baseMs += int64(200 + rng()*600)
		proof.Events = append(proof.Events, CaptchaEvent{
			Type:      "mousemove",
			ElapsedMs: baseMs,
			X:         200 + rng()*600,
			Y:         200 + rng()*400,
		})
	}

	// Maybe a scroll while waiting
	if rng() > 0.4 {
		baseMs += int64(300 + rng()*500)
		proof.Events = append(proof.Events, CaptchaEvent{
			Type:      "scroll",
			ElapsedMs: baseMs,
			Delta:     50 + rng()*150,
		})
	}

	// Phase 2: JS compute happens
	computeStart := baseMs
	computeDuration := int64(float64(ch.JSComputeMs) * (0.8 + rng()*0.4)) // 80-120% of expected
	baseMs += computeDuration
	proof.JSComputeActualMs = baseMs - computeStart

	// Phase 3: Challenge resolves
	proof.CallbackOrder = ch.ExpectedCallbacks
	proof.TotalDurationMs = baseMs

	return proof
}

// SolveCloudflareManagedChallenge generates a full managed challenge solve.
func SolveCloudflareManagedChallenge(ch CloudflareLabChallenge, rng func() float64) CloudflareLabProof {
	proof := CloudflareLabProof{
		Type: CFChallengeManaged,
	}

	baseMs := int64(0)

	// JS phase: idle mouse activity
	idleMoves := 3 + int(rng()*5)
	for range idleMoves {
		baseMs += int64(150 + rng()*400)
		proof.Events = append(proof.Events, CaptchaEvent{
			Type: "mousemove", ElapsedMs: baseMs,
			X: 300 + rng()*400, Y: 200 + rng()*300,
		})
	}

	computeDuration := int64(float64(ch.JSComputeMs) * (0.85 + rng()*0.30))
	baseMs += computeDuration
	proof.JSComputeActualMs = computeDuration

	// Widget telemetry
	wt := &WidgetTelemetry{}
	now := time.Now().UTC()
	wt.recordCallback("before-interactive")
	wt.BeforeAt = now

	// Interaction phase
	if ch.Widget != nil {
		baseMs += int64(200 + rng()*300)
		wt.recordCallback("after-interactive")

		switch ch.Widget.Interaction.Type {
		case turnstileInteractionRotate:
			result := SolveRotateChallenge(RotateSolveParams{
				TargetAngleDeg:    ch.Widget.Interaction.TargetAngleDeg,
				DialRadiusPx:      ch.Widget.Interaction.DialRadiusPx,
				RequiredOvershoot: ch.Widget.Interaction.RequiredOvershootDeg,
			}, rng)
			// Offset event times
			for i := range result.Events {
				result.Events[i].ElapsedMs += baseMs
			}
			proof.Events = append(proof.Events, result.Events...)
			proof.InteractionProof = &result.Proof
			baseMs += int64(result.Proof.RotationDurationMs)

		case turnstileInteractionSlidePuzzle:
			slideCfg := ch.Widget.Interaction
			result := SolveSlidePuzzle(SlidePuzzleSolveParams{
				TargetXPx:    slideCfg.TargetSlideXPx,
				TrackWidthPx: slideCfg.SlideTrackWidthPx,
			}, rng)
			for i := range result.Events {
				result.Events[i].ElapsedMs += baseMs
			}
			proof.Events = append(proof.Events, result.Events...)
			proof.InteractionProof = &result.Proof
			baseMs += int64(result.Proof.SlideDurationMs)

		case turnstileInteractionCheckbox:
			baseMs += int64(400 + rng()*600)
			proof.Events = append(proof.Events, CaptchaEvent{
				Type: "click", ElapsedMs: baseMs,
				X: 420 + rng()*10, Y: 310 + rng()*10,
			})
			proof.InteractionProof = &TurnstileInteractionProof{
				Type: turnstileInteractionCheckbox, Completed: true, CheckboxClicks: 1,
			}

		case turnstileInteractionHold:
			holdMs := ch.Widget.Interaction.RequiredHoldMs + int(rng()*300)
			baseMs += int64(holdMs)
			proof.InteractionProof = &TurnstileInteractionProof{
				Type: turnstileInteractionHold, Completed: true, HoldDurationMs: holdMs,
			}

		case turnstileInteractionDrag:
			dragDist := ch.Widget.Interaction.RequiredDragDistancePx + int(rng()*30)
			baseMs += int64(600 + rng()*400)
			proof.InteractionProof = &TurnstileInteractionProof{
				Type: turnstileInteractionDrag, Completed: true,
				DragDistancePx: dragDist,
				DragEventCount: ch.Widget.Interaction.RequiredDragEventCount + int(rng()*4),
			}
		}

		wt.recordInteraction(proof.InteractionProof)
	}

	wt.recordCallback("success")
	proof.WidgetTelemetry = wt
	proof.CallbackOrder = wt.CallbackOrder
	proof.TotalDurationMs = baseMs

	return proof
}

// --- Helpers ---

// callbackOrderValid checks that all expected callbacks appear in order (allowing extras between).
func callbackOrderValid(expected, actual []string) bool {
	if len(expected) == 0 {
		return true
	}
	ei := 0
	for _, cb := range actual {
		if ei < len(expected) && cb == expected[ei] {
			ei++
		}
	}
	return ei == len(expected)
}

func signalScore(signals []TurnstileHeuristicSignal) float64 {
	score := 0.0
	for _, s := range signals {
		score += s.Weight
	}
	return score
}
