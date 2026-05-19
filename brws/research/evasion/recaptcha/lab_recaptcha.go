package recaptcha

import (
	"fmt"
	"math"

	captchatraining "github.com/skunkworq/stealth/brws/research/captcha/training"
)

// TurnstileHeuristicSignal captures one heuristic bot-detection indicator.
// This local type mirrors the cloudflare package's signal for reCAPTCHA lab use.
type TurnstileHeuristicSignal struct {
	Name   string  `json:"name"`
	Weight float64 `json:"weight"`
	Detail string  `json:"detail,omitempty"`
}

// Ensure captchatraining is used (CaptchaEvent used via type alias below).
// --- reCAPTCHA v2 Lab Challenge ---

// ReCaptchaV2LabChallenge models a reCAPTCHA v2 image-grid challenge in the lab.
type ReCaptchaV2LabChallenge struct {
	GridRows     int    `json:"grid_rows"`    // typically 3 or 4
	GridCols     int    `json:"grid_cols"`    // typically 3 or 4
	CellSizePx   int    `json:"cell_size_px"` // typically 100-130px per cell
	TargetLabel  string `json:"target_label"` // "traffic lights", "crosswalks", etc.
	TargetCells  []int  `json:"target_cells"` // correct cell indices (0-based)
	TotalCells   int    `json:"total_cells"`
	HasNewImages bool   `json:"has_new_images"` // whether new images appear after selection
	MaxAttempts  int    `json:"max_attempts"`
}

// ReCaptchaV2LabProof captures the user's image grid selections.
type ReCaptchaV2LabProof struct {
	SelectedCells    []int          `json:"selected_cells"`
	SelectionOrder   []int          `json:"selection_order"`    // order cells were clicked
	SelectionTimesMs []int64        `json:"selection_times_ms"` // time of each click
	TotalDurationMs  int64          `json:"total_duration_ms"`
	ClickEvents      []captchatraining.CaptchaEvent `json:"click_events"`
	Correct          bool           `json:"correct"`
	AttemptNumber    int            `json:"attempt_number"`
}

// DefaultReCaptchaV2Lab returns a standard 3x3 grid challenge.
func DefaultReCaptchaV2Lab(targetLabel string, targetCells []int) ReCaptchaV2LabChallenge {
	return ReCaptchaV2LabChallenge{
		GridRows:    3,
		GridCols:    3,
		CellSizePx:  130,
		TargetLabel: targetLabel,
		TargetCells: targetCells,
		TotalCells:  9,
		MaxAttempts: 3,
	}
}

// ValidateReCaptchaV2Proof checks if the selections are correct and behavioral signals are human-like.
func ValidateReCaptchaV2Proof(ch ReCaptchaV2LabChallenge, proof ReCaptchaV2LabProof) (bool, []TurnstileHeuristicSignal) {
	var signals []TurnstileHeuristicSignal

	// Check correctness: selected must match targets
	targetSet := make(map[int]bool)
	for _, t := range ch.TargetCells {
		targetSet[t] = true
	}
	selectedSet := make(map[int]bool)
	for _, s := range proof.SelectedCells {
		selectedSet[s] = true
	}

	missed := 0
	extra := 0
	for t := range targetSet {
		if !selectedSet[t] {
			missed++
		}
	}
	for s := range selectedSet {
		if !targetSet[s] {
			extra++
		}
	}
	if missed > 0 || extra > 0 {
		signals = append(signals, TurnstileHeuristicSignal{
			Name: "incorrect_selection", Weight: 1.0,
			Detail: fmt.Sprintf("missed=%d extra=%d", missed, extra),
		})
		return false, signals
	}

	// Heuristic: click timing should show natural variation
	if len(proof.SelectionTimesMs) > 1 {
		intervals := make([]float64, 0, len(proof.SelectionTimesMs)-1)
		for i := 1; i < len(proof.SelectionTimesMs); i++ {
			intervals = append(intervals, float64(proof.SelectionTimesMs[i]-proof.SelectionTimesMs[i-1]))
		}

		// Too fast: all clicks in <200ms each
		allFast := true
		for _, iv := range intervals {
			if iv > 200 {
				allFast = false
				break
			}
		}
		if allFast {
			signals = append(signals, TurnstileHeuristicSignal{
				Name: "selections_too_fast", Weight: 0.5,
				Detail: "all inter-click intervals <200ms",
			})
		}

		// Constant intervals: CV < 0.15 is robotic
		if len(intervals) >= 3 {
			cv := coefficientOfVariation(intervals)
			if cv < 0.15 {
				signals = append(signals, TurnstileHeuristicSignal{
					Name: "constant_click_intervals", Weight: 0.4,
					Detail: fmt.Sprintf("CV=%.3f (too regular)", cv),
				})
			}
		}
	}

	// Heuristic: total duration too short
	if proof.TotalDurationMs > 0 && proof.TotalDurationMs < 800 {
		signals = append(signals, TurnstileHeuristicSignal{
			Name: "solve_too_fast", Weight: 0.5,
			Detail: fmt.Sprintf("%dms for %d selections", proof.TotalDurationMs, len(proof.SelectedCells)),
		})
	}

	// Heuristic: clicks perfectly centered in cells (bots target exact center)
	if len(proof.ClickEvents) > 0 && ch.CellSizePx > 0 {
		centeredCount := 0
		for _, ce := range proof.ClickEvents {
			cellX := math.Mod(ce.X, float64(ch.CellSizePx))
			cellY := math.Mod(ce.Y, float64(ch.CellSizePx))
			centerX := float64(ch.CellSizePx) / 2
			centerY := float64(ch.CellSizePx) / 2
			dist := math.Sqrt(math.Pow(cellX-centerX, 2) + math.Pow(cellY-centerY, 2))
			if dist < 5 { // within 5px of exact center
				centeredCount++
			}
		}
		if centeredCount == len(proof.ClickEvents) && len(proof.ClickEvents) > 2 {
			signals = append(signals, TurnstileHeuristicSignal{
				Name: "all_clicks_centered", Weight: 0.5,
				Detail: "every click hit exact cell center (bot signature)",
			})
		}
	}

	// Heuristic: selection order is perfectly sequential (top-left to bottom-right)
	if len(proof.SelectionOrder) > 2 {
		sequential := true
		for i := 1; i < len(proof.SelectionOrder); i++ {
			if proof.SelectionOrder[i] < proof.SelectionOrder[i-1] {
				sequential = false
				break
			}
		}
		if sequential {
			signals = append(signals, TurnstileHeuristicSignal{
				Name: "sequential_selection_order", Weight: 0.3,
				Detail: "cells selected in strict left-to-right top-to-bottom order",
			})
		}
	}

	score := 0.0
	for _, s := range signals {
		score += s.Weight
	}
	return score < 0.75, signals
}

// --- reCAPTCHA v3 Lab Behavioral Scoring ---

// ReCaptchaV3LabSession models a reCAPTCHA v3 behavioral scoring session.
// v3 has no visible challenge; it scores behavior in the background.
type ReCaptchaV3LabSession struct {
	Action        string  `json:"action"`         // page action (e.g. "login", "submit")
	MinScore      float64 `json:"min_score"`      // threshold (typically 0.5)
	ObservationMs int64   `json:"observation_ms"` // how long to observe (default 5000ms)
}

// ReCaptchaV3LabProof captures the behavioral data observed.
type ReCaptchaV3LabProof struct {
	Events     []captchatraining.CaptchaEvent `json:"events"`
	DurationMs int64          `json:"duration_ms"`
	Score      float64        `json:"score"` // computed 0.0-1.0 (1.0 = human)
	Action     string         `json:"action"`
}

// DefaultReCaptchaV3Lab returns a standard v3 session config.
func DefaultReCaptchaV3Lab(action string) ReCaptchaV3LabSession {
	return ReCaptchaV3LabSession{
		Action:        action,
		MinScore:      0.5,
		ObservationMs: 5000,
	}
}

// ScoreReCaptchaV3 computes a human-likeness score (0.0=bot, 1.0=human) from behavioral events.
func ScoreReCaptchaV3(session ReCaptchaV3LabSession, proof ReCaptchaV3LabProof) (float64, []TurnstileHeuristicSignal) {
	var signals []TurnstileHeuristicSignal
	score := 1.0 // start at 1.0, subtract for bot signals

	metrics := computeRecordingMetrics(proof.Events)

	// 1. Event volume: too few events in observation window
	expectedEventsPerSec := 5.0 // reasonable mouse activity
	observeSec := float64(proof.DurationMs) / 1000.0
	if observeSec < 1 {
		observeSec = 1
	}
	minExpected := int(expectedEventsPerSec * observeSec * 0.3) // 30% of expected
	if metrics.TotalEvents < minExpected {
		penalty := 0.25
		signals = append(signals, TurnstileHeuristicSignal{
			Name: "low_event_volume", Weight: penalty,
			Detail: fmt.Sprintf("%d events in %.0fs (expected ≥%d)", metrics.TotalEvents, observeSec, minExpected),
		})
		score -= penalty
	}

	// 2. Mouse velocity profile
	if metrics.AvgMouseVelocity > 0 {
		if metrics.AvgMouseVelocity > 2000 {
			penalty := 0.20
			signals = append(signals, TurnstileHeuristicSignal{
				Name: "superhuman_mouse_speed", Weight: penalty,
				Detail: fmt.Sprintf("%.0fpx/s avg velocity", metrics.AvgMouseVelocity),
			})
			score -= penalty
		}
		if metrics.AvgMouseVelocity < 5 {
			penalty := 0.15
			signals = append(signals, TurnstileHeuristicSignal{
				Name: "suspiciously_slow_mouse", Weight: penalty,
				Detail: fmt.Sprintf("%.1fpx/s avg velocity", metrics.AvgMouseVelocity),
			})
			score -= penalty
		}
	}

	// 3. Straightness: very high straightness (>0.95) suggests linear interpolation
	if metrics.Straightness > 0.95 && metrics.MouseMoves > 5 {
		penalty := 0.20
		signals = append(signals, TurnstileHeuristicSignal{
			Name: "linear_mouse_path", Weight: penalty,
			Detail: fmt.Sprintf("straightness=%.3f (too linear)", metrics.Straightness),
		})
		score -= penalty
	}

	// 4. No pauses: humans pause to read, think, orient
	if metrics.Pauses == 0 && metrics.TotalEvents > 20 {
		penalty := 0.15
		signals = append(signals, TurnstileHeuristicSignal{
			Name: "no_natural_pauses", Weight: penalty,
			Detail: "no pauses >200ms in event stream",
		})
		score -= penalty
	}

	// 5. No direction changes: humans don't move in one direction only
	if metrics.DirectionChanges == 0 && metrics.MouseMoves > 10 {
		penalty := 0.15
		signals = append(signals, TurnstileHeuristicSignal{
			Name: "no_direction_changes", Weight: penalty,
			Detail: "mouse never changed direction",
		})
		score -= penalty
	}

	// 6. Constant event intervals
	if metrics.TotalEvents > 5 && metrics.AvgEventInterval > 0 {
		// Check if intervals are suspiciously uniform
		var intervals []float64
		for i := 1; i < len(proof.Events); i++ {
			intervals = append(intervals, float64(proof.Events[i].ElapsedMs-proof.Events[i-1].ElapsedMs))
		}
		if len(intervals) >= 5 {
			cv := coefficientOfVariation(intervals)
			if cv < 0.10 {
				penalty := 0.20
				signals = append(signals, TurnstileHeuristicSignal{
					Name: "uniform_event_timing", Weight: penalty,
					Detail: fmt.Sprintf("CV=%.3f (machine-like regularity)", cv),
				})
				score -= penalty
			}
		}
	}

	if score < 0 {
		score = 0
	}

	return score, signals
}

// --- Solvers ---

// SolveReCaptchaV2Grid generates human-like click events for a v2 image grid.
func SolveReCaptchaV2Grid(ch ReCaptchaV2LabChallenge, widgetX, widgetY float64, rng func() float64) ReCaptchaV2LabProof {
	cellSize := float64(ch.CellSizePx)
	cols := ch.GridCols

	// Randomize selection order (humans don't always go L-R T-B)
	targets := make([]int, len(ch.TargetCells))
	copy(targets, ch.TargetCells)
	// Fisher-Yates shuffle
	for i := len(targets) - 1; i > 0; i-- {
		j := int(rng() * float64(i+1))
		targets[i], targets[j] = targets[j], targets[i]
	}

	proof := ReCaptchaV2LabProof{
		SelectedCells:  ch.TargetCells, // correct cells (unshuffled for correctness check)
		SelectionOrder: targets,        // shuffled order
		Correct:        true,
		AttemptNumber:  1,
	}

	var events []captchatraining.CaptchaEvent
	baseMs := int64(300 + rng()*500) // initial hesitation: 300-800ms

	for _, cellIdx := range targets {
		row := cellIdx / cols
		col := cellIdx % cols

		// Click position: cell center + human offset (not perfect center)
		cx := widgetX + float64(col)*cellSize + cellSize/2 + (rng()*2-1)*cellSize*0.25
		cy := widgetY + float64(row)*cellSize + cellSize/2 + (rng()*2-1)*cellSize*0.25

		// Approach mousemove
		baseMs += int64(100 + rng()*200)
		events = append(events, captchatraining.CaptchaEvent{
			Type: "mousemove", ElapsedMs: baseMs,
			X: cx + (rng()*2-1)*15, Y: cy + (rng()*2-1)*15,
		})

		// Settle
		baseMs += int64(40 + rng()*60)
		events = append(events, captchatraining.CaptchaEvent{
			Type: "mousemove", ElapsedMs: baseMs, X: cx, Y: cy,
		})

		// Click
		baseMs += int64(30 + rng()*40)
		events = append(events, captchatraining.CaptchaEvent{
			Type: "mousedown", ElapsedMs: baseMs, X: cx, Y: cy,
		})
		baseMs += int64(50 + rng()*80)
		events = append(events, captchatraining.CaptchaEvent{
			Type: "mouseup", ElapsedMs: baseMs, X: cx, Y: cy,
		})

		proof.SelectionTimesMs = append(proof.SelectionTimesMs, baseMs)

		// Pause between selections: 200-600ms (humans look at next image)
		baseMs += int64(200 + rng()*400)
	}

	// Click verify button
	verifyX := widgetX + float64(cols)*cellSize/2 + (rng()*2-1)*20
	verifyY := widgetY + float64(ch.GridRows)*cellSize + 40 + rng()*10
	baseMs += int64(300 + rng()*400)
	events = append(events, captchatraining.CaptchaEvent{
		Type: "click", ElapsedMs: baseMs, X: verifyX, Y: verifyY,
	})

	proof.TotalDurationMs = baseMs
	proof.ClickEvents = events

	return proof
}

// --- Helpers ---

func coefficientOfVariation(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}
	mean := 0.0
	for _, v := range values {
		mean += v
	}
	mean /= float64(len(values))
	if mean == 0 {
		return 0
	}

	variance := 0.0
	for _, v := range values {
		d := v - mean
		variance += d * d
	}
	stddev := math.Sqrt(variance / float64(len(values)-1))
	return stddev / mean
}

// labMetrics holds behavioral metrics for lab analysis.
type labMetrics struct {
	TotalEvents      int
	MouseMoves       int
	AvgMouseVelocity float64
	AvgEventInterval float64
	Pauses           int
	Straightness     float64
	DirectionChanges int
}

// computeRecordingMetrics computes basic behavioral metrics from a slice of CaptchaEvents.
func computeRecordingMetrics(events []captchatraining.CaptchaEvent) *labMetrics {
	m := &labMetrics{TotalEvents: len(events)}
	if len(events) == 0 {
		return m
	}

	var prevX, prevY, prevDx, prevDy float64
	var prevTime int64
	var totalDist float64
	var firstX, firstY, lastX, lastY float64
	var mouseCount int
	var velocities []float64

	for i, e := range events {
		switch e.Type {
		case "mousemove":
			m.MouseMoves++
			if mouseCount > 0 {
				dx := e.X - prevX
				dy := e.Y - prevY
				dist := math.Sqrt(dx*dx + dy*dy)
				totalDist += dist
				if mouseCount > 1 && dx*prevDx+dy*prevDy < 0 {
					m.DirectionChanges++
				}
				prevDx, prevDy = dx, dy
				if e.ElapsedMs > prevTime {
					dt := float64(e.ElapsedMs-prevTime) / 1000.0
					if dt > 0 {
						velocities = append(velocities, dist/dt)
					}
				}
			} else {
				firstX, firstY = e.X, e.Y
			}
			prevX, prevY = e.X, e.Y
			lastX, lastY = e.X, e.Y
			mouseCount++
		}
		if i > 0 && e.ElapsedMs > prevTime && e.ElapsedMs-prevTime > 200 {
			m.Pauses++
		}
		prevTime = e.ElapsedMs
	}

	if len(velocities) > 0 {
		sum := 0.0
		for _, v := range velocities {
			sum += v
		}
		m.AvgMouseVelocity = sum / float64(len(velocities))
	}
	if len(events) > 1 {
		span := events[len(events)-1].ElapsedMs - events[0].ElapsedMs
		m.AvgEventInterval = float64(span) / float64(len(events)-1)
	}
	if totalDist > 0 {
		dx := lastX - firstX
		dy := lastY - firstY
		displacement := math.Sqrt(dx*dx + dy*dy)
		m.Straightness = displacement / totalDist
	}
	return m
}

// coefficientOfVariation computes the coefficient of variation of a slice.
