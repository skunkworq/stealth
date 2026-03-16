package adversarial

import (
	"fmt"
	"math"
)

// --- Rotate Challenge Validation ---

// ValidateRotateProof checks if a rotate interaction proof satisfies the config.
func ValidateRotateProof(cfg TurnstileInteractionConfig, proof TurnstileInteractionProof) (bool, []TurnstileHeuristicSignal) {
	var signals []TurnstileHeuristicSignal

	if proof.Type != turnstileInteractionRotate {
		signals = append(signals, TurnstileHeuristicSignal{
			Name: "wrong_interaction_type", Weight: 1.0,
			Detail: fmt.Sprintf("expected rotate, got %s", proof.Type),
		})
		return false, signals
	}

	// Check angle within tolerance
	angleDiff := angleDifference(proof.FinalAngleDeg, cfg.TargetAngleDeg)
	tolerance := cfg.AngleToleranceDeg
	if tolerance == 0 {
		tolerance = 15
	}
	if angleDiff > tolerance {
		signals = append(signals, TurnstileHeuristicSignal{
			Name: "angle_outside_tolerance", Weight: 0.8,
			Detail: fmt.Sprintf("final=%d° target=%d° diff=%d° tolerance=±%d°",
				proof.FinalAngleDeg, cfg.TargetAngleDeg, angleDiff, tolerance),
		})
		return false, signals
	}

	// Check minimum rotation events
	minEvents := cfg.MinRotationEvents
	if minEvents == 0 {
		minEvents = 10
	}
	if proof.RotationEventCount < minEvents {
		signals = append(signals, TurnstileHeuristicSignal{
			Name: "insufficient_rotation_events", Weight: 0.5,
			Detail: fmt.Sprintf("got %d events, need %d", proof.RotationEventCount, minEvents),
		})
	}

	// Check overshoot requirement
	if cfg.RequiredOvershootDeg > 0 && proof.OvershootDeg < cfg.RequiredOvershootDeg {
		signals = append(signals, TurnstileHeuristicSignal{
			Name: "insufficient_overshoot", Weight: 0.3,
			Detail: fmt.Sprintf("overshoot=%d° need=%d°", proof.OvershootDeg, cfg.RequiredOvershootDeg),
		})
	}

	// Heuristic: constant angular velocity is bot-like
	if proof.AngularVelocityAvg > 0 && proof.RotationDurationMs > 0 {
		// Bots rotate at constant speed; humans accelerate, plateau, then decelerate
		// A very fast rotation (> 720°/s) is suspicious
		if proof.AngularVelocityAvg > 720 {
			signals = append(signals, TurnstileHeuristicSignal{
				Name: "superhuman_rotation_speed", Weight: 0.6,
				Detail: fmt.Sprintf("%.0f°/s exceeds human threshold", proof.AngularVelocityAvg),
			})
		}
	}

	// Heuristic: too fast overall (< 300ms for a 270° rotation)
	if proof.RotationDurationMs > 0 && proof.RotationDurationMs < 300 {
		signals = append(signals, TurnstileHeuristicSignal{
			Name: "rotation_too_fast", Weight: 0.5,
			Detail: fmt.Sprintf("%dms for rotation", proof.RotationDurationMs),
		})
	}

	// Calculate score
	score := 0.0
	for _, s := range signals {
		score += s.Weight
	}
	passed := angleDiff <= tolerance && score < 0.75
	return passed, signals
}

// --- Slide Puzzle Validation ---

// ValidateSlidePuzzleProof checks if a slide puzzle proof satisfies the config.
func ValidateSlidePuzzleProof(cfg TurnstileInteractionConfig, proof TurnstileInteractionProof) (bool, []TurnstileHeuristicSignal) {
	var signals []TurnstileHeuristicSignal

	if proof.Type != turnstileInteractionSlidePuzzle {
		signals = append(signals, TurnstileHeuristicSignal{
			Name: "wrong_interaction_type", Weight: 1.0,
			Detail: fmt.Sprintf("expected slide_puzzle, got %s", proof.Type),
		})
		return false, signals
	}

	// Check X position within tolerance
	xDiff := abs(proof.FinalSlideXPx - cfg.TargetSlideXPx)
	tolerance := cfg.SlideTolerancePx
	if tolerance == 0 {
		tolerance = 8
	}
	if xDiff > tolerance {
		signals = append(signals, TurnstileHeuristicSignal{
			Name: "slide_outside_tolerance", Weight: 0.8,
			Detail: fmt.Sprintf("final=%dpx target=%dpx diff=%dpx tolerance=±%dpx",
				proof.FinalSlideXPx, cfg.TargetSlideXPx, xDiff, tolerance),
		})
		return false, signals
	}

	// Check minimum slide events
	minEvents := cfg.MinSlideEvents
	if minEvents == 0 {
		minEvents = 12
	}
	if proof.SlideEventCount < minEvents {
		signals = append(signals, TurnstileHeuristicSignal{
			Name: "insufficient_slide_events", Weight: 0.4,
			Detail: fmt.Sprintf("got %d events, need %d", proof.SlideEventCount, minEvents),
		})
	}

	// Check Y-axis jitter (humans wobble during horizontal drag)
	minYJitter := cfg.RequiredSlideYJitter
	if minYJitter == 0 {
		minYJitter = 3
	}
	if proof.SlideYVariancePx < float64(minYJitter) {
		signals = append(signals, TurnstileHeuristicSignal{
			Name: "no_y_axis_wobble", Weight: 0.5,
			Detail: fmt.Sprintf("Y variance=%.1fpx, need ≥%dpx (humans wobble)", proof.SlideYVariancePx, minYJitter),
		})
	}

	// Heuristic: too fast (< 400ms for 200px slide)
	if proof.SlideDurationMs > 0 && proof.SlideDurationMs < 400 {
		signals = append(signals, TurnstileHeuristicSignal{
			Name: "slide_too_fast", Weight: 0.5,
			Detail: fmt.Sprintf("%dms for slide", proof.SlideDurationMs),
		})
	}

	// Heuristic: perfectly straight line (zero Y variance) is robotic
	if proof.SlideYVariancePx == 0 && proof.SlideEventCount > 3 {
		signals = append(signals, TurnstileHeuristicSignal{
			Name: "perfectly_straight_slide", Weight: 0.6,
			Detail: "zero Y-axis variance across slide events indicates automation",
		})
	}

	// Heuristic: overshoot indicates human (but not required)
	// No penalty for having overshoot — only penalty for suspicious patterns

	score := 0.0
	for _, s := range signals {
		score += s.Weight
	}
	passed := xDiff <= tolerance && score < 0.75
	return passed, signals
}

// --- Helpers ---

// angleDifference returns the shortest angular distance between two angles in degrees.
func angleDifference(a, b int) int {
	diff := ((a-b)%360 + 360) % 360
	if diff > 180 {
		diff = 360 - diff
	}
	return diff
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// --- Rotate Solver (Sword) ---

// RotateSolveParams holds the parameters needed to solve a rotate challenge.
type RotateSolveParams struct {
	TargetAngleDeg    int
	DialRadiusPx      int
	DialCenterX       float64
	DialCenterY       float64
	RequiredOvershoot int
}

// RotateSolveResult holds the events and proof from solving a rotate challenge.
type RotateSolveResult struct {
	Events []CaptchaEvent
	Proof  TurnstileInteractionProof
}

// SolveRotateChallenge generates human-like rotation events to solve a rotate challenge.
// The rotation follows a natural arc: accelerate → cruise → overshoot → correct.
func SolveRotateChallenge(params RotateSolveParams, rng func() float64) RotateSolveResult {
	radius := float64(params.DialRadiusPx)
	if radius == 0 {
		radius = 80
	}
	cx, cy := params.DialCenterX, params.DialCenterY
	if cx == 0 && cy == 0 {
		cx, cy = 150, 150 // default center
	}

	target := float64(params.TargetAngleDeg)
	overshootDeg := float64(params.RequiredOvershoot)
	if overshootDeg == 0 {
		overshootDeg = 12
	}

	// Generate rotation path: 0° → target+overshoot → target
	// Using 3 phases: accelerate (30%), cruise (40%), decelerate+correct (30%)
	totalSteps := 14 + int(rng()*8) // 14-22 steps
	events := make([]CaptchaEvent, 0, totalSteps+4)

	baseTs := int64(1000) // start at 1000ms elapsed

	// Phase 0: approach — move to dial edge from nearby
	approachX := cx + radius*0.7
	approachY := cy + rng()*10 - 5
	events = append(events, CaptchaEvent{
		Type: "mousemove", ElapsedMs: baseTs, X: approachX, Y: approachY,
	})
	baseTs += 80 + int64(rng()*60)

	// Mousedown on dial
	startAngle := 0.0
	startX := cx + radius*math.Cos(startAngle*math.Pi/180)
	startY := cy + radius*math.Sin(startAngle*math.Pi/180)
	events = append(events, CaptchaEvent{
		Type: "mousedown", ElapsedMs: baseTs, X: startX, Y: startY,
	})
	baseTs += 30 + int64(rng()*20)

	// Rotation movement
	maxAngle := target + overshootDeg + rng()*5 // overshoot past target
	var peakAngle float64

	for i := 0; i < totalSteps; i++ {
		t := float64(i) / float64(totalSteps-1) // 0 to 1

		// Ease-in-out cubic for natural acceleration
		var easedT float64
		if t < 0.5 {
			easedT = 4 * t * t * t
		} else {
			easedT = 1 - math.Pow(-2*t+2, 3)/2
		}

		// Angle progresses to overshoot peak at ~80% then corrects
		var angle float64
		if t < 0.8 {
			// Progress to overshoot
			angle = easedT / 0.95 * maxAngle
		} else {
			// Correct back toward target
			correctionT := (t - 0.8) / 0.2
			angle = maxAngle - correctionT*(maxAngle-target)
		}

		if angle > peakAngle {
			peakAngle = angle
		}

		// Convert angle to XY on dial circumference
		rad := angle * math.Pi / 180
		x := cx + radius*math.Cos(rad)
		y := cy + radius*math.Sin(rad)

		// Add human jitter (±1-3px)
		jitter := 1.0 + rng()*2
		x += (rng()*2 - 1) * jitter
		y += (rng()*2 - 1) * jitter

		// Timing: faster in middle, slower at start/end
		interval := int64(40 + rng()*60) // 40-100ms
		if t < 0.15 || t > 0.85 {
			interval += 30 // slower at extremes
		}
		baseTs += interval

		events = append(events, CaptchaEvent{
			Type: "mousemove", ElapsedMs: baseTs, X: x, Y: y,
		})
	}

	// Mouseup at final position
	finalRad := target * math.Pi / 180
	finalX := cx + radius*math.Cos(finalRad)
	finalY := cy + radius*math.Sin(finalRad)
	baseTs += 50 + int64(rng()*30)
	events = append(events, CaptchaEvent{
		Type: "mouseup", ElapsedMs: baseTs, X: finalX, Y: finalY,
	})

	// Calculate proof
	totalDuration := int(baseTs - 1000)
	overshoot := int(peakAngle - target)
	if overshoot < 0 {
		overshoot = 0
	}
	avgVelocity := 0.0
	if totalDuration > 0 {
		avgVelocity = target / (float64(totalDuration) / 1000)
	}

	return RotateSolveResult{
		Events: events,
		Proof: TurnstileInteractionProof{
			Type:               turnstileInteractionRotate,
			Completed:          true,
			FinalAngleDeg:      params.TargetAngleDeg,
			RotationEventCount: totalSteps,
			OvershootDeg:       overshoot,
			RotationDurationMs: totalDuration,
			AngularVelocityAvg: avgVelocity,
		},
	}
}

// --- Slide Puzzle Solver (Sword) ---

// SlidePuzzleSolveParams holds the parameters needed to solve a slide puzzle.
type SlidePuzzleSolveParams struct {
	TargetXPx    int
	TrackWidthPx int
	TrackY       float64 // Y position of the track center
	PieceStartX  float64
	PieceStartY  float64
}

// SlidePuzzleSolveResult holds the events and proof from solving a slide puzzle.
type SlidePuzzleSolveResult struct {
	Events []CaptchaEvent
	Proof  TurnstileInteractionProof
}

// SolveSlidePuzzle generates human-like slide events to solve a slide puzzle.
// Path: approach → grab piece → slide with Y wobble → overshoot → correct → release.
func SolveSlidePuzzle(params SlidePuzzleSolveParams, rng func() float64) SlidePuzzleSolveResult {
	targetX := float64(params.TargetXPx)
	trackY := params.TrackY
	if trackY == 0 {
		trackY = 200
	}
	startX := params.PieceStartX
	if startX == 0 {
		startX = 20 // piece starts near left edge
	}
	startY := params.PieceStartY
	if startY == 0 {
		startY = trackY
	}

	totalSteps := 14 + int(rng()*10) // 14-24 steps
	events := make([]CaptchaEvent, 0, totalSteps+6)
	baseTs := int64(800)

	// Approach: move to piece
	events = append(events, CaptchaEvent{
		Type: "mousemove", ElapsedMs: baseTs,
		X: startX - 15 + rng()*10, Y: startY - 20 + rng()*10,
	})
	baseTs += 100 + int64(rng()*80)

	events = append(events, CaptchaEvent{
		Type: "mousemove", ElapsedMs: baseTs,
		X: startX + rng()*5, Y: startY + rng()*5 - 2.5,
	})
	baseTs += 60 + int64(rng()*40)

	// Grab piece
	events = append(events, CaptchaEvent{
		Type: "mousedown", ElapsedMs: baseTs,
		X: startX, Y: startY,
	})
	baseTs += 30 + int64(rng()*20)

	// Slide with Y wobble and natural speed curve
	overshootPx := 8 + rng()*15 // 8-23px overshoot
	maxX := targetX + overshootPx
	distance := maxX - startX

	var yValues []float64
	var peakX float64

	for i := 0; i < totalSteps; i++ {
		t := float64(i) / float64(totalSteps-1)

		// Ease curve
		var easedT float64
		if t < 0.5 {
			easedT = 2 * t * t
		} else {
			easedT = 1 - math.Pow(-2*t+2, 2)/2
		}

		// X progresses to overshoot at ~85%, then corrects
		var x float64
		if t < 0.85 {
			x = startX + easedT/0.95*distance
		} else {
			corrT := (t - 0.85) / 0.15
			x = maxX - corrT*(maxX-targetX)
		}
		if x > peakX {
			peakX = x
		}

		// Y wobble: sinusoidal with noise (humans can't keep perfectly straight)
		yWobble := math.Sin(t*math.Pi*3) * (3 + rng()*4) // ±3-7px wobble
		y := trackY + yWobble + (rng()*2 - 1)
		yValues = append(yValues, y)

		// Timing
		interval := int64(35 + rng()*55) // 35-90ms
		if t < 0.1 || t > 0.9 {
			interval += 25
		}
		baseTs += interval

		events = append(events, CaptchaEvent{
			Type: "mousemove", ElapsedMs: baseTs,
			X: x, Y: y,
		})
	}

	// Release at target
	baseTs += 40 + int64(rng()*30)
	events = append(events, CaptchaEvent{
		Type: "mouseup", ElapsedMs: baseTs,
		X: targetX + rng()*3 - 1.5, Y: trackY + rng()*2 - 1,
	})

	// Calculate Y variance
	yVariance := calculateVariance(yValues)

	totalDuration := int(baseTs - 800)
	slideOvershoot := int(peakX - targetX)
	if slideOvershoot < 0 {
		slideOvershoot = 0
	}

	return SlidePuzzleSolveResult{
		Events: events,
		Proof: TurnstileInteractionProof{
			Type:             turnstileInteractionSlidePuzzle,
			Completed:        true,
			FinalSlideXPx:    params.TargetXPx,
			SlideEventCount:  totalSteps,
			SlideYVariancePx: yVariance,
			SlideDurationMs:  totalDuration,
			SlideOvershootPx: slideOvershoot,
		},
	}
}

// calculateVariance computes the variance of a float64 slice.
func calculateVariance(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}
	mean := 0.0
	for _, v := range values {
		mean += v
	}
	mean /= float64(len(values))

	variance := 0.0
	for _, v := range values {
		diff := v - mean
		variance += diff * diff
	}
	return math.Sqrt(variance / float64(len(values)-1))
}
