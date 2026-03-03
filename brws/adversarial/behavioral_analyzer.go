package adversarial

import (
	"fmt"
	"math"
	"sort"
)

// BehavioralAnalyzerConfig configures the enhanced behavioral analysis engine.
type BehavioralAnalyzerConfig struct {
	MinIntervalEntropy    float64 // Below this = too uniform (bot)
	MaxIntervalEntropy    float64 // Above this = injected noise
	MinCurvatureVariance  float64 // Zero = straight lines (bot)
	MaxVelocity           float64 // px/s, above = impossible
	MinVelocity           float64 // px/s, below = impossibly slow
	MinMicroTremorRatio   float64 // Fraction of movements with micro-tremors
	MaxKeystrokeUniformCV float64 // CV below this = mechanical typing
}

// DefaultBehavioralAnalyzerConfig returns sensible defaults.
func DefaultBehavioralAnalyzerConfig() *BehavioralAnalyzerConfig {
	return &BehavioralAnalyzerConfig{
		MinIntervalEntropy:    1.5,
		MaxIntervalEntropy:    4.5,
		MinCurvatureVariance:  0.00001,
		MaxVelocity:           3000.0,
		MinVelocity:           5.0,
		MinMicroTremorRatio:   0.1,
		MaxKeystrokeUniformCV: 0.15,
	}
}

// BehavioralAnalyzer performs statistical analysis on user interaction events.
type BehavioralAnalyzer struct {
	config *BehavioralAnalyzerConfig
}

// NewBehavioralAnalyzer creates a new BehavioralAnalyzer with the given config.
func NewBehavioralAnalyzer(config *BehavioralAnalyzerConfig) *BehavioralAnalyzer {
	if config == nil {
		config = DefaultBehavioralAnalyzerConfig()
	}
	return &BehavioralAnalyzer{config: config}
}

// EnhancedBehavioralEvents extends BehavioralEvents with raw data for analysis.
type EnhancedBehavioralEvents struct {
	BehavioralEvents

	// Raw event timestamps (ms since epoch)
	MouseTimestamps  []int64
	ScrollTimestamps []int64
	TypingTimestamps []int64

	// Mouse positions for path analysis
	MousePositions []Position

	// Mouse velocities
	MouseVelocities []float64

	// Click data for precision analysis
	ClickTimestamps []int64
	ClickPositions  []Position

	// Scroll data for uniformity analysis
	ScrollDeltas []float64

	// Phase 10: Keystroke hold times (ms) — duration of keydown→keyup per keystroke
	KeystrokeHoldTimes []float64
	// Phase 10: Scroll directions — positive=down, negative=up
	ScrollDirections []float64
}

// Position represents an x,y coordinate.
type Position struct {
	X, Y float64
}

// Analyze runs the full behavioral analysis suite and returns a VectorResult.
func (ba *BehavioralAnalyzer) Analyze(events *EnhancedBehavioralEvents) *VectorResult {
	result := &VectorResult{
		Vector:     "Enhanced Behavioral Analysis",
		Category:   VectorBehavioral,
		Detected:   false,
		Score:      0,
		Indicators: make([]VectorIndicator, 0),
	}

	if events == nil {
		return result
	}

	// Check 1: Interval entropy analysis on mouse timestamps
	if len(events.MouseTimestamps) > 3 {
		entropy := ba.calculateIntervalEntropy(events.MouseTimestamps)

		if entropy < ba.config.MinIntervalEntropy {
			weight := 0.35
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "interval_entropy_low",
				Message: "Mouse event intervals are too uniform (bot-like)",
				Weight:  weight,
				Field:   "mouse_interval_entropy",
				Value:   formatFloat(entropy),
			})
			result.Score += weight
		}

		if entropy > ba.config.MaxIntervalEntropy {
			weight := 0.25
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "interval_entropy_high",
				Message: "Mouse event intervals show injected noise pattern",
				Weight:  weight,
				Field:   "mouse_interval_entropy",
				Value:   formatFloat(entropy),
			})
			result.Score += weight
		}
	}

	// Check 2: Mouse path curvature analysis
	if len(events.MousePositions) > 5 {
		curvatures, _, variance := ba.calculatePathCurvature(events.MousePositions)
		_ = curvatures

		if variance < ba.config.MinCurvatureVariance {
			weight := 0.35
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "zero_curvature_variance",
				Message: "Mouse moves in straight lines (no natural curve)",
				Weight:  weight,
				Field:   "curvature_variance",
				Value:   formatFloat(variance),
			})
			result.Score += weight
		}
	}

	// Check 3: Impossible velocity
	if len(events.MouseVelocities) > 0 {
		for _, v := range events.MouseVelocities {
			if v > ba.config.MaxVelocity {
				weight := 0.30
				result.Indicators = append(result.Indicators, VectorIndicator{
					Check:   "impossible_velocity_high",
					Message: "Mouse velocity exceeds human capability",
					Weight:  weight,
					Field:   "mouse_velocity",
					Value:   formatFloat(v),
				})
				result.Score += weight
				break
			}
			if v > 0 && v < ba.config.MinVelocity {
				weight := 0.30
				result.Indicators = append(result.Indicators, VectorIndicator{
					Check:   "impossible_velocity_low",
					Message: "Mouse velocity impossibly slow (pixel-perfect bot)",
					Weight:  weight,
					Field:   "mouse_velocity",
					Value:   formatFloat(v),
				})
				result.Score += weight
				break
			}
		}
	}

	// Check 4: Micro-tremor analysis
	if len(events.MousePositions) > 10 {
		tremorRatio := ba.analyzeMouseMicroMovements(events.MousePositions)
		if tremorRatio < ba.config.MinMicroTremorRatio {
			weight := 0.25
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "no_micro_tremors",
				Message: "Missing involuntary hand jitter in mouse movement",
				Weight:  weight,
				Field:   "micro_tremor_ratio",
				Value:   formatFloat(tremorRatio),
			})
			result.Score += weight
		}
	}

	// Check 5: Keystroke dynamics
	if len(events.TypingTimestamps) > 5 {
		cv := ba.analyzeKeystrokeDynamics(events.TypingTimestamps)
		if cv < ba.config.MaxKeystrokeUniformCV {
			weight := 0.35
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "uniform_keystroke_intervals",
				Message: "Typing rhythm is too regular (mechanical)",
				Weight:  weight,
				Field:   "keystroke_cv",
				Value:   formatFloat(cv),
			})
			result.Score += weight
		}
	}

	// Check 6: Uniform scroll deltas (bots often use scrollBy(0, N) with identical amounts)
	if len(events.ScrollDeltas) > 3 {
		allIdentical := true
		first := events.ScrollDeltas[0]
		for _, d := range events.ScrollDeltas[1:] {
			if d != first {
				allIdentical = false
				break
			}
		}
		if allIdentical {
			weight := 0.25
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "uniform_scroll_deltas",
				Message: fmt.Sprintf("All %d scroll deltas are identical (%.0fpx) — bot pattern", len(events.ScrollDeltas), first),
				Weight:  weight,
				Field:   "scroll_deltas",
				Value:   formatFloat(first),
			})
			result.Score += weight
		}
	}

	// Check 8: Missing scroll events despite mouse and typing activity.
	// Real human browsing involves scrolling when there's mouse movement and typing.
	// Zero scroll events with significant mouse + typing activity is suspicious.
	if len(events.ScrollTimestamps) == 0 && len(events.ScrollDeltas) == 0 &&
		len(events.MouseTimestamps) > 10 && len(events.TypingTimestamps) > 0 {
		weight := 0.30
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "missing_scroll_events",
			Message: fmt.Sprintf("No scroll events despite %d mouse events and %d typing events", len(events.MouseTimestamps), len(events.TypingTimestamps)),
			Weight:  weight,
			Field:   "scroll_events",
			Value:   "0",
		})
		result.Score += weight
	}

	// Check 7: Click position too precise (bots click exactly on integer coordinates at center)
	if len(events.ClickPositions) > 2 {
		preciseCount := 0
		for _, pos := range events.ClickPositions {
			// Check if position lands exactly on integer coordinates
			if pos.X == math.Floor(pos.X) && pos.Y == math.Floor(pos.Y) {
				preciseCount++
			}
		}
		// If ALL clicks are perfectly integer-positioned
		if preciseCount == len(events.ClickPositions) {
			weight := 0.20
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "click_position_too_precise",
				Message: fmt.Sprintf("All %d clicks land on exact integer coordinates — bot-like precision", len(events.ClickPositions)),
				Weight:  weight,
				Field:   "click_positions",
				Value:   fmt.Sprintf("%d/%d precise", preciseCount, len(events.ClickPositions)),
			})
			result.Score += weight
		}
	}

	// Check 9: Synthetic timestamp base detection.
	// Real browser timestamps use Date.now() (epoch ms, >1.6 trillion as of 2020).
	// Synthetic generators start from 0 or small values relative to epoch.
	if len(events.MouseTimestamps) > 0 {
		firstTs := events.MouseTimestamps[0]
		if firstTs >= 0 && firstTs < 1_000_000_000_000 {
			weight := 0.40
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "synthetic_timestamp_base",
				Message: fmt.Sprintf("First mouse timestamp %d is sub-epoch — synthetic generator detected", firstTs),
				Weight:  weight,
				Field:   "first_mouse_timestamp",
				Value:   fmt.Sprintf("%d", firstTs),
			})
			result.Score += weight
		}
	}

	// Check 10: Velocity distribution uniformity (chi-squared test).
	// Real humans have bimodal velocity (slow deliberate + fast ballistic).
	// Bots that clamp velocities to a uniform range produce a flat histogram.
	if len(events.MouseVelocities) > 8 {
		chiSq := ba.chiSquaredUniformity(events.MouseVelocities, 5)
		if chiSq < 1.5 {
			weight := 0.25
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "uniform_velocity_distribution",
				Message: fmt.Sprintf("Mouse velocity distribution is suspiciously uniform (chi²=%.2f < 1.5)", chiSq),
				Weight:  weight,
				Field:   "velocity_chi_squared",
				Value:   formatFloat(chiSq),
			})
			result.Score += weight
		}
	}

	// Check 11: Path efficiency consistency.
	// Real humans overshoot, correct, and have varying efficiency across segments.
	// A single Bézier curve with jitter has suspiciously consistent segment ratios.
	if len(events.MousePositions) > 5 {
		segRatios := ba.segmentEfficiencyRatios(events.MousePositions, 3)
		if len(segRatios) == 3 {
			mean, stddev := meanStddev(segRatios)
			overallRatio := ba.pathEfficiencyRatio(events.MousePositions)
			cv := 0.0
			if mean > 0 {
				cv = stddev / mean
			}
			if cv < 0.15 && overallRatio < 1.5 && overallRatio > 0 {
				weight := 0.20
				result.Indicators = append(result.Indicators, VectorIndicator{
					Check:   "path_efficiency_consistency",
					Message: fmt.Sprintf("Mouse path segments have suspiciously consistent efficiency (CV=%.3f, ratio=%.3f)", cv, overallRatio),
					Weight:  weight,
					Field:   "path_segment_cv",
					Value:   formatFloat(cv),
				})
				result.Score += weight
			}
		}
	}

	// Check 12: Missing click events.
	// Real users click 2-15 times during a session with mouse activity.
	// Zero clicks with significant mouse movement is highly suspicious.
	if len(events.ClickTimestamps) == 0 && len(events.MouseTimestamps) > 10 {
		weight := 0.25
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "missing_click_events",
			Message: fmt.Sprintf("No click events despite %d mouse events", len(events.MouseTimestamps)),
			Weight:  weight,
			Field:   "click_events",
			Value:   "0",
		})
		result.Score += weight
	}

	// Check 13: Sequential event type ordering.
	// Real users interleave mouse, typing, and scroll events throughout a session.
	// If ALL mouse events finish before ANY typing/scroll begins, events were
	// generated sequentially by type — a strong synthetic pattern.
	if len(events.MouseTimestamps) > 5 && len(events.ScrollTimestamps) > 0 && len(events.TypingTimestamps) > 0 {
		maxMouse := events.MouseTimestamps[len(events.MouseTimestamps)-1]
		minTyping := events.TypingTimestamps[0]
		minScroll := events.ScrollTimestamps[0]

		if maxMouse < minTyping && maxMouse < minScroll {
			weight := 0.30
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check: "sequential_event_ordering",
				Message: fmt.Sprintf("All mouse events (%d) finish before typing/scroll begin (mouse_end=%d < typing_start=%d, scroll_start=%d)",
					len(events.MouseTimestamps), maxMouse, minTyping, minScroll),
				Weight: weight,
				Field:  "event_ordering",
				Value:  "sequential",
			})
			result.Score += weight
		}
	}

	// Check 14: Micro-tremor angular uniformity (Rayleigh test).
	// Real involuntary hand tremor has directional bias (wrist anatomy).
	// Synthetic polar-coordinate generation produces uniformly distributed angles.
	// Rayleigh test: R = sqrt((Σcos(θ))² + (Σsin(θ))²) / n
	// Low R (<0.15) means uniform = bot. High R means directional bias = human.
	if len(events.MousePositions) > 10 {
		R := ba.rayleighTestMicroTremors(events.MousePositions)
		if R >= 0 && R < 0.15 {
			weight := 0.25
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "uniform_tremor_angles",
				Message: fmt.Sprintf("Micro-tremor angles are too uniform (Rayleigh R=%.3f < 0.15)", R),
				Weight:  weight,
				Field:   "rayleigh_R",
				Value:   formatFloat(R),
			})
			result.Score += weight
		}
	}

	// Check 15: Velocity floor clustering.
	// Soft-clamped velocity floors create a density spike at [5.0, 15.5].
	// Real human velocities distribute smoothly — no floor clustering.
	if len(events.MouseVelocities) > 8 {
		floorCount := 0
		for _, v := range events.MouseVelocities {
			if v >= 5.0 && v <= 15.5 {
				floorCount++
			}
		}
		ratio := float64(floorCount) / float64(len(events.MouseVelocities))
		if ratio > 0.20 {
			weight := 0.20
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "velocity_floor_clustering",
				Message: fmt.Sprintf("%.0f%% of velocities in floor band [5-15.5] (synthetic clamp pattern)", ratio*100),
				Weight:  weight,
				Field:   "floor_velocity_ratio",
				Value:   formatFloat(ratio),
			})
			result.Score += weight
		}
	}

	// Check 16: Click-timestamp synchronization.
	// Real browsers fire click events 1-5ms after the nearest mousemove.
	// Synthetic generators copy exact mouse timestamps for click events.
	if len(events.ClickTimestamps) >= 2 && len(events.MouseTimestamps) > 5 {
		mouseSet := make(map[int64]bool, len(events.MouseTimestamps))
		for _, mt := range events.MouseTimestamps {
			mouseSet[mt] = true
		}
		syncCount := 0
		for _, ct := range events.ClickTimestamps {
			if mouseSet[ct] {
				syncCount++
			}
		}
		syncRatio := float64(syncCount) / float64(len(events.ClickTimestamps))
		if syncRatio > 0.80 {
			weight := 0.30
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "click_timestamp_sync",
				Message: fmt.Sprintf("%.0f%% of clicks share exact timestamp with mouse events (synthetic copy)", syncRatio*100),
				Weight:  weight,
				Field:   "click_sync_ratio",
				Value:   formatFloat(syncRatio),
			})
			result.Score += weight
		}
	}

	// Check 17: Click-to-mouse position distance uniformity.
	// Synthetic generators place clicks near mouse positions with uniform small jitter
	// (all within ~1.3px). Real users have a wider distribution of click offsets —
	// some precise clicks (0px), some approximate (5-20px), and occasional misclicks.
	if len(events.ClickPositions) >= 2 && len(events.MousePositions) > 5 {
		narrowCount := 0
		for _, cp := range events.ClickPositions {
			minDist := math.MaxFloat64
			for _, mp := range events.MousePositions {
				dx := cp.X - mp.X
				dy := cp.Y - mp.Y
				d := math.Sqrt(dx*dx + dy*dy)
				if d < minDist {
					minDist = d
				}
			}
			if minDist < 2.0 {
				narrowCount++
			}
		}
		narrowRatio := float64(narrowCount) / float64(len(events.ClickPositions))
		if narrowRatio > 0.85 {
			weight := 0.25
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "click_mouse_distance_uniform",
				Message: fmt.Sprintf("%.0f%% of clicks within 2px of a mouse position (synthetic jitter pattern)", narrowRatio*100),
				Weight:  weight,
				Field:   "narrow_click_ratio",
				Value:   formatFloat(narrowRatio),
			})
			result.Score += weight
		}
	}

	// Check 18: Scroll interval uniformity.
	// Real scrolling has bimodal intervals: fast inertia (<100ms) and reading pauses (>500ms).
	// Synthetic generators produce intervals from a uniform range (e.g. [80-400ms]),
	// which has low coefficient of variation (~0.38) compared to real scrolling (>0.6).
	if len(events.ScrollTimestamps) > 4 {
		scrollIntervals := make([]float64, 0, len(events.ScrollTimestamps)-1)
		for i := 1; i < len(events.ScrollTimestamps); i++ {
			diff := float64(events.ScrollTimestamps[i] - events.ScrollTimestamps[i-1])
			if diff > 0 {
				scrollIntervals = append(scrollIntervals, diff)
			}
		}
		if len(scrollIntervals) > 2 {
			mean, stddev := meanStddev(scrollIntervals)
			scrollCV := 0.0
			if mean > 0 {
				scrollCV = stddev / mean
			}
			if scrollCV < 0.50 {
				weight := 0.25
				result.Indicators = append(result.Indicators, VectorIndicator{
					Check:   "scroll_interval_uniformity",
					Message: fmt.Sprintf("Scroll intervals too uniform (CV=%.3f < 0.50)", scrollCV),
					Weight:  weight,
					Field:   "scroll_interval_cv",
					Value:   formatFloat(scrollCV),
				})
				result.Score += weight
			}
		}
	}

	// Check 19: Scroll delta ratio consistency.
	// Synthetic scroll generators use linear deceleration (delta *= 0.92 per step + noise),
	// producing suspiciously consistent consecutive-delta ratios.
	// Real users accelerate and decelerate irregularly (ratio stddev > 0.15).
	if len(events.ScrollDeltas) > 4 {
		ratios := make([]float64, 0, len(events.ScrollDeltas)-1)
		for i := 1; i < len(events.ScrollDeltas); i++ {
			if events.ScrollDeltas[i-1] > 10 { // skip tiny deltas
				ratios = append(ratios, events.ScrollDeltas[i]/events.ScrollDeltas[i-1])
			}
		}
		if len(ratios) > 2 {
			_, ratioStddev := meanStddev(ratios)
			if ratioStddev < 0.15 {
				weight := 0.20
				result.Indicators = append(result.Indicators, VectorIndicator{
					Check:   "scroll_delta_linear_decel",
					Message: fmt.Sprintf("Scroll delta ratios too consistent (stddev=%.3f < 0.15)", ratioStddev),
					Weight:  weight,
					Field:   "scroll_ratio_stddev",
					Value:   formatFloat(ratioStddev),
				})
				result.Score += weight
			}
		}
	}

	// Check 20: Mouse interval temporal clustering (lag-1 autocorrelation).
	// Real human mouse movements have temporal clustering — bursts of fast movement
	// followed by slower deliberation. This creates positive lag-1 autocorrelation
	// in inter-event intervals (> 0.10). Synthetic generators with shuffled interval
	// modes produce near-zero autocorrelation.
	if len(events.MouseTimestamps) > 8 {
		mouseIntervals := make([]float64, 0, len(events.MouseTimestamps)-1)
		for i := 1; i < len(events.MouseTimestamps); i++ {
			mouseIntervals = append(mouseIntervals, float64(events.MouseTimestamps[i]-events.MouseTimestamps[i-1]))
		}
		if len(mouseIntervals) > 5 {
			autocorr := ba.lag1Autocorrelation(mouseIntervals)
			if autocorr < 0.10 {
				weight := 0.20
				result.Indicators = append(result.Indicators, VectorIndicator{
					Check:   "mouse_interval_no_clustering",
					Message: fmt.Sprintf("Mouse intervals lack temporal clustering (lag-1 autocorr=%.3f < 0.10)", autocorr),
					Weight:  weight,
					Field:   "mouse_interval_autocorr",
					Value:   formatFloat(autocorr),
				})
				result.Score += weight
			}
		}
	}

	// Check 21: Scroll delta-interval independence (Spearman rank correlation).
	// Real scrolling: short intervals (fast scrolling) correlate with larger deltas —
	// users who scroll quickly also scroll farther per event. Synthetic generators
	// pick delta and interval from independent distributions (|ρ| ≈ 0).
	if len(events.ScrollDeltas) > 2 && len(events.ScrollTimestamps) > 2 {
		spearN := len(events.ScrollTimestamps)
		if spearN > len(events.ScrollDeltas) {
			spearN = len(events.ScrollDeltas)
		}
		if spearN > 2 {
			spearIntervals := make([]float64, 0, spearN-1)
			spearDeltas := make([]float64, 0, spearN-1)
			for i := 1; i < spearN; i++ {
				diff := float64(events.ScrollTimestamps[i] - events.ScrollTimestamps[i-1])
				if diff > 0 {
					spearIntervals = append(spearIntervals, diff)
					spearDeltas = append(spearDeltas, events.ScrollDeltas[i])
				}
			}
			if len(spearIntervals) >= 2 {
				rho := ba.spearmanCorrelation(spearIntervals, spearDeltas)
				if math.Abs(rho) < 0.15 {
					weight := 0.25
					result.Indicators = append(result.Indicators, VectorIndicator{
						Check:   "scroll_delta_interval_independence",
						Message: fmt.Sprintf("Scroll deltas independent of intervals (Spearman ρ=%.3f)", rho),
						Weight:  weight,
						Field:   "scroll_spearman_rho",
						Value:   formatFloat(rho),
					})
					result.Score += weight
				}
			}
		}
	}

	// Check 22: Scroll delta momentum (lag-1 autocorrelation).
	// Real scrolling exhibits positive autocorrelation: consecutive deltas are
	// similar due to physical momentum (finger stays on wheel/trackpad).
	// Synthetic i.i.d. deltas from random distributions have autocorrelation ≈ 0.
	if len(events.ScrollDeltas) > 2 {
		scrollAutocorr := ba.lag1Autocorrelation(events.ScrollDeltas)
		if scrollAutocorr < 0.10 {
			weight := 0.20
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "scroll_delta_no_momentum",
				Message: fmt.Sprintf("Scroll deltas lack momentum (lag-1 autocorr=%.3f < 0.10)", scrollAutocorr),
				Weight:  weight,
				Field:   "scroll_delta_autocorr",
				Value:   formatFloat(scrollAutocorr),
			})
			result.Score += weight
		}
	}

	// Check 23: No velocity depression near click events (Fitts' law).
	// Humans decelerate before clicking — motor planning requires slowing to
	// acquire the target. If velocities near click timestamps are not lower than
	// the overall mean, clicks were placed without motor-planning deceleration.
	if len(events.ClickTimestamps) >= 2 && len(events.MouseVelocities) > 5 && len(events.MouseTimestamps) > 5 {
		overallMean, _ := meanStddev(events.MouseVelocities)
		if overallMean > 0 {
			var clickVelSum float64
			clickVelCount := 0

			for _, ct := range events.ClickTimestamps {
				bestIdx := -1
				bestDiff := int64(math.MaxInt64)
				for j, mt := range events.MouseTimestamps {
					diff := ct - mt
					if diff < 0 {
						diff = -diff
					}
					if diff < bestDiff {
						bestDiff = diff
						bestIdx = j
					}
				}
				if bestIdx >= 0 && bestIdx < len(events.MouseVelocities) {
					clickVelSum += events.MouseVelocities[bestIdx]
					clickVelCount++
				}
			}

			if clickVelCount >= 2 {
				clickVelMean := clickVelSum / float64(clickVelCount)
				decelRatio := clickVelMean / overallMean
				if decelRatio > 0.85 {
					weight := 0.25
					result.Indicators = append(result.Indicators, VectorIndicator{
						Check:   "no_click_deceleration",
						Message: fmt.Sprintf("No velocity depression near clicks (click_vel/mean=%.2f > 0.85)", decelRatio),
						Weight:  weight,
						Field:   "click_decel_ratio",
						Value:   formatFloat(decelRatio),
					})
					result.Score += weight
				}
			}
		}
	}

	// Check 24: Mouse event density unchanged during typing phase.
	// Real users reduce mouse movement when typing (hands move to keyboard).
	// Mouse event density should drop to < 70% of pre-typing density during
	// the typing phase. Synthetic generators produce mouse events independently
	// of typing, maintaining uniform density throughout.
	if len(events.MouseTimestamps) > 8 && len(events.TypingTimestamps) > 3 {
		typingStart := events.TypingTimestamps[0]
		typingEnd := events.TypingTimestamps[len(events.TypingTimestamps)-1]

		preTypingMouse := 0
		duringTypingMouse := 0
		var firstMouseTs int64
		var lastPreTypingTs int64

		for i, mt := range events.MouseTimestamps {
			if mt < typingStart {
				preTypingMouse++
				if i == 0 {
					firstMouseTs = mt
				}
				lastPreTypingTs = mt
			} else if mt <= typingEnd {
				duringTypingMouse++
			}
		}

		preDuration := float64(lastPreTypingTs - firstMouseTs)
		typingDuration := float64(typingEnd - typingStart)

		if preDuration > 0 && typingDuration > 0 && preTypingMouse > 3 && duringTypingMouse > 2 {
			preDensity := float64(preTypingMouse) / preDuration
			duringDensity := float64(duringTypingMouse) / typingDuration
			densityRatio := duringDensity / preDensity

			if densityRatio > 0.70 {
				weight := 0.20
				result.Indicators = append(result.Indicators, VectorIndicator{
					Check:   "mouse_density_during_typing",
					Message: fmt.Sprintf("Mouse density doesn't decrease during typing (ratio=%.2f > 0.70)", densityRatio),
					Weight:  weight,
					Field:   "typing_density_ratio",
					Value:   formatFloat(densityRatio),
				})
				result.Score += weight
			}
		}
	}

	// Check 25: Keystroke hold time coefficient of variation.
	// Human key hold times (keydown→keyup) vary significantly: fast taps (60-80ms),
	// moderate presses (100-150ms), and occasional long holds (200-400ms).
	// Bots that use fixed hold times or narrow uniform ranges have CV < 0.25.
	if len(events.KeystrokeHoldTimes) > 4 {
		holdMean, holdStddev := meanStddev(events.KeystrokeHoldTimes)
		holdCV := 0.0
		if holdMean > 0 {
			holdCV = holdStddev / holdMean
		}
		if holdCV < 0.25 {
			weight := 0.25
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "keystroke_hold_time_cv",
				Message: fmt.Sprintf("Keystroke hold times too uniform (CV=%.3f < 0.25)", holdCV),
				Weight:  weight,
				Field:   "hold_time_cv",
				Value:   formatFloat(holdCV),
			})
			result.Score += weight
		}
	}

	// Check 26: Digraph timing anomaly (inter-key interval variance across pairs).
	// Human typing shows digraph effects: certain key transitions are faster than
	// others due to finger proximity (e.g., "th" is fast, "qp" is slow).
	// If the variance of consecutive inter-key intervals is extremely low (CV < 0.20),
	// it means all pairs are typed at the same speed — no digraph effect.
	if len(events.TypingTimestamps) > 6 {
		intervals := make([]float64, 0, len(events.TypingTimestamps)-1)
		for i := 1; i < len(events.TypingTimestamps); i++ {
			diff := float64(events.TypingTimestamps[i] - events.TypingTimestamps[i-1])
			if diff > 0 {
				intervals = append(intervals, diff)
			}
		}
		if len(intervals) > 3 {
			// Check consecutive interval ratios: human typing has alternating
			// fast/slow pairs. Ratio CV > 0.30 is normal.
			pairRatios := make([]float64, 0, len(intervals)-1)
			for i := 1; i < len(intervals); i++ {
				if intervals[i-1] > 0 {
					pairRatios = append(pairRatios, intervals[i]/intervals[i-1])
				}
			}
			if len(pairRatios) > 2 {
				ratioMean, ratioStddev := meanStddev(pairRatios)
				ratioCV := 0.0
				if ratioMean > 0 {
					ratioCV = ratioStddev / ratioMean
				}
				if ratioCV < 0.20 {
					weight := 0.20
					result.Indicators = append(result.Indicators, VectorIndicator{
						Check:   "digraph_timing_anomaly",
						Message: fmt.Sprintf("Typing interval ratios too uniform (CV=%.3f < 0.20) — no digraph effect", ratioCV),
						Weight:  weight,
						Field:   "digraph_ratio_cv",
						Value:   formatFloat(ratioCV),
					})
					result.Score += weight
				}
			}
		}
	}

	// Check 30: Scroll direction entropy.
	// Real users predominantly scroll down (70-85%) with occasional up-scrolls.
	// Bots that scroll 100% in one direction or alternate perfectly are suspicious.
	// Low entropy = all same direction. Very high entropy with few events = alternating.
	if len(events.ScrollDirections) > 3 {
		downCount := 0
		for _, d := range events.ScrollDirections {
			if d > 0 {
				downCount++
			}
		}
		downRatio := float64(downCount) / float64(len(events.ScrollDirections))
		// Flag if 100% same direction (no up-scrolls at all) with enough events
		if (downRatio == 1.0 || downRatio == 0.0) && len(events.ScrollDirections) > 5 {
			weight := 0.15
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "scroll_direction_monotonic",
				Message: fmt.Sprintf("All %d scrolls in same direction (down_ratio=%.2f)", len(events.ScrollDirections), downRatio),
				Weight:  weight,
				Field:   "scroll_down_ratio",
				Value:   formatFloat(downRatio),
			})
			result.Score += weight
		}
		// Flag perfect alternation (up-down-up-down)
		if len(events.ScrollDirections) > 4 {
			alternations := 0
			for i := 1; i < len(events.ScrollDirections); i++ {
				if (events.ScrollDirections[i] > 0) != (events.ScrollDirections[i-1] > 0) {
					alternations++
				}
			}
			altRatio := float64(alternations) / float64(len(events.ScrollDirections)-1)
			if altRatio > 0.85 {
				weight := 0.20
				result.Indicators = append(result.Indicators, VectorIndicator{
					Check:   "scroll_direction_alternating",
					Message: fmt.Sprintf("Scroll direction alternates too regularly (%.0f%% changes)", altRatio*100),
					Weight:  weight,
					Field:   "scroll_alt_ratio",
					Value:   formatFloat(altRatio),
				})
				result.Score += weight
			}
		}
	}

	// Check 31: Scroll direction change velocity discontinuity.
	// When a human reverses scroll direction, velocity decreases to near-zero
	// before reversing. Bots that flip direction at full speed show high
	// velocity magnitude at direction-change points.
	if len(events.ScrollDirections) > 3 && len(events.ScrollDeltas) > 3 {
		n := len(events.ScrollDirections)
		if n > len(events.ScrollDeltas) {
			n = len(events.ScrollDeltas)
		}
		dirChangeCount := 0
		highVelChanges := 0
		for i := 1; i < n; i++ {
			if (events.ScrollDirections[i] > 0) != (events.ScrollDirections[i-1] > 0) {
				dirChangeCount++
				// Check if delta at change point is still large
				if math.Abs(events.ScrollDeltas[i]) > 150 {
					highVelChanges++
				}
			}
		}
		if dirChangeCount >= 2 && highVelChanges == dirChangeCount {
			weight := 0.20
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "scroll_direction_change_abrupt",
				Message: fmt.Sprintf("All %d direction changes at high velocity (no deceleration)", dirChangeCount),
				Weight:  weight,
				Field:   "abrupt_dir_changes",
				Value:   fmt.Sprintf("%d/%d", highVelChanges, dirChangeCount),
			})
			result.Score += weight
		}
	}

	// Check 27: Mouse velocity lag-2 autocorrelation anomaly.
	// Human mouse velocities exhibit moderate lag-2 autocorrelation (0.15-0.30)
	// due to motor planning: the hand accelerates and decelerates over multi-step
	// arcs. Bots produce near-zero lag-2 autocorrelation (i.i.d. velocities) or
	// very high values (>0.60) from overly smooth interpolation.
	if len(events.MouseVelocities) > 5 {
		lag2 := ba.lagNAutocorrelation(events.MouseVelocities, 2)
		if lag2 < 0.15 || lag2 > 0.60 {
			weight := 0.15
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "mouse_velocity_lag2_anomaly",
				Message: fmt.Sprintf("Mouse velocity lag-2 autocorrelation anomalous (%.3f, expected 0.15-0.30)", lag2),
				Weight:  weight,
				Field:   "velocity_lag2_autocorr",
				Value:   formatFloat(lag2),
			})
			result.Score += weight
		}
	}

	// Check 28: Mouse velocity lag-3 autocorrelation anomaly.
	// Human mouse velocities have weak but positive lag-3 autocorrelation (0.05-0.15)
	// from sustained movement phases. Bots have near-zero (no temporal structure)
	// or high values (>0.40) from deterministic velocity curves.
	if len(events.MouseVelocities) > 6 {
		lag3 := ba.lagNAutocorrelation(events.MouseVelocities, 3)
		if lag3 < 0.05 || lag3 > 0.40 {
			weight := 0.10
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "mouse_velocity_lag3_anomaly",
				Message: fmt.Sprintf("Mouse velocity lag-3 autocorrelation anomalous (%.3f, expected 0.05-0.15)", lag3),
				Weight:  weight,
				Field:   "velocity_lag3_autocorr",
				Value:   formatFloat(lag3),
			})
			result.Score += weight
		}
	}

	// Check 29: Fitts' law violation.
	// Fitts' law: movement time = a + b * log2(D/W + 1), where D = distance to target,
	// W = target width. For human clicks, the correlation between log2(D/W+1) and
	// actual movement time should be moderate (0.3-0.95). Random bots have low
	// correlation (<0.3); scripted bots with perfect timing have correlation >0.95.
	// Constants: a=150ms, b=100ms, targetWidth=40px (typical button).
	if len(events.ClickTimestamps) >= 3 && len(events.ClickPositions) >= 3 {
		// Fitts' law constants: a=150ms intercept, b=100ms slope (used in the
		// theoretical model; the check measures correlation of ID vs actual time).
		const targetWidth = 40.0 // px typical button width

		fittsIDs := make([]float64, 0, len(events.ClickTimestamps)-1)
		actualTimes := make([]float64, 0, len(events.ClickTimestamps)-1)

		for i := 1; i < len(events.ClickTimestamps) && i < len(events.ClickPositions); i++ {
			dx := events.ClickPositions[i].X - events.ClickPositions[i-1].X
			dy := events.ClickPositions[i].Y - events.ClickPositions[i-1].Y
			dist := math.Sqrt(dx*dx + dy*dy)
			if dist < 1.0 {
				continue // Skip clicks at same position
			}

			id := math.Log2(dist/targetWidth + 1) // Index of Difficulty
			actualTime := float64(events.ClickTimestamps[i] - events.ClickTimestamps[i-1])
			if actualTime <= 0 {
				continue
			}

			fittsIDs = append(fittsIDs, id)
			actualTimes = append(actualTimes, actualTime)
		}

		if len(fittsIDs) >= 3 {
			// Need at least 3 pairs for a meaningful Pearson correlation
			// (2 points always yields r = +/-1.0 which is degenerate).
			corr := ba.pearsonCorrelation(fittsIDs, actualTimes)
			if corr < 0.3 || corr > 0.95 {
				weight := 0.20
				result.Indicators = append(result.Indicators, VectorIndicator{
					Check:   "fitts_law_violation",
					Message: fmt.Sprintf("Click timing vs Fitts' law ID correlation anomalous (r=%.3f, expected 0.3-0.95)", corr),
					Weight:  weight,
					Field:   "fitts_correlation",
					Value:   formatFloat(corr),
				})
				result.Score += weight
			}
		}
	}

	result.Score = math.Min(1.0, result.Score)
	result.Detected = result.Score > 0.3

	return result
}

// rayleighTestMicroTremors computes the Rayleigh test statistic R for the
// angular distribution of micro-tremor displacements (0.5-3.0 px).
// Returns R in [0, 1] where 0 = uniform, 1 = all same direction.
// Returns -1 if insufficient micro-tremors for analysis.
func (ba *BehavioralAnalyzer) rayleighTestMicroTremors(positions []Position) float64 {
	var sumCos, sumSin float64
	var count int

	for i := 1; i < len(positions); i++ {
		dx := positions[i].X - positions[i-1].X
		dy := positions[i].Y - positions[i-1].Y
		dist := math.Sqrt(dx*dx + dy*dy)

		// Only analyze micro-tremors (0.5-3.0 px displacement)
		if dist >= 0.5 && dist <= 3.0 {
			angle := math.Atan2(dy, dx)
			sumCos += math.Cos(angle)
			sumSin += math.Sin(angle)
			count++
		}
	}

	if count < 5 {
		return -1 // Not enough data
	}

	R := math.Sqrt(sumCos*sumCos+sumSin*sumSin) / float64(count)
	return R
}

// calculateIntervalEntropy computes Shannon entropy of intervals between timestamps.
// Low entropy = uniform intervals (bot). High entropy = random noise injection.
func (ba *BehavioralAnalyzer) calculateIntervalEntropy(timestamps []int64) float64 {
	if len(timestamps) < 2 {
		return 0
	}

	intervals := make([]float64, 0, len(timestamps)-1)
	for i := 1; i < len(timestamps); i++ {
		diff := float64(timestamps[i] - timestamps[i-1])
		if diff > 0 {
			intervals = append(intervals, diff)
		}
	}

	if len(intervals) == 0 {
		return 0
	}

	// Bin intervals into buckets for entropy calculation
	numBins := 10
	minVal, maxVal := intervals[0], intervals[0]
	for _, v := range intervals {
		if v < minVal {
			minVal = v
		}
		if v > maxVal {
			maxVal = v
		}
	}

	if maxVal == minVal {
		return 0 // All identical = zero entropy
	}

	binWidth := (maxVal - minVal) / float64(numBins)
	bins := make([]int, numBins)
	for _, v := range intervals {
		bin := int((v - minVal) / binWidth)
		if bin >= numBins {
			bin = numBins - 1
		}
		bins[bin]++
	}

	// Shannon entropy
	total := float64(len(intervals))
	entropy := 0.0
	for _, count := range bins {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// analyzeDistribution checks if intervals follow a uniform distribution.
// Returns true if likely uniform, and a pseudo p-value.
func (ba *BehavioralAnalyzer) analyzeDistribution(intervals []float64) (isUniform bool, pValue float64) {
	if len(intervals) < 3 {
		return false, 1.0
	}

	mean, stddev := meanStddev(intervals)
	if mean == 0 {
		return true, 0.0
	}

	cv := stddev / mean
	// A uniform distribution has CV ≈ 0.577, but bots often have CV < 0.1
	isUniform = cv < 0.15
	pValue = cv / 0.577 // Normalize to expected uniform CV

	return isUniform, pValue
}

// calculatePathCurvature computes the curvature at each point of a mouse path.
func (ba *BehavioralAnalyzer) calculatePathCurvature(positions []Position) (curvatures []float64, mean, variance float64) {
	if len(positions) < 3 {
		return nil, 0, 0
	}

	curvatures = make([]float64, 0, len(positions)-2)
	for i := 1; i < len(positions)-1; i++ {
		p0 := positions[i-1]
		p1 := positions[i]
		p2 := positions[i+1]

		// Menger curvature using triangle area / (side lengths product)
		dx1, dy1 := p1.X-p0.X, p1.Y-p0.Y
		dx2, dy2 := p2.X-p1.X, p2.Y-p1.Y

		// Cross product magnitude (2x triangle area)
		cross := math.Abs(dx1*dy2 - dy1*dx2)

		// Side lengths
		a := math.Sqrt(dx1*dx1 + dy1*dy1)
		b := math.Sqrt(dx2*dx2 + dy2*dy2)
		dx3, dy3 := p2.X-p0.X, p2.Y-p0.Y
		c := math.Sqrt(dx3*dx3 + dy3*dy3)

		if a*b*c > 0 {
			curvature := 2 * cross / (a * b * c)
			curvatures = append(curvatures, curvature)
		}
	}

	if len(curvatures) == 0 {
		return curvatures, 0, 0
	}

	mean, variance = meanVariance(curvatures)
	return curvatures, mean, variance
}

// analyzeMouseMicroMovements detects the presence of involuntary micro-tremors
// (small jittery movements) that are characteristic of human mouse control.
func (ba *BehavioralAnalyzer) analyzeMouseMicroMovements(positions []Position) float64 {
	if len(positions) < 3 {
		return 0
	}

	microCount := 0
	total := 0

	for i := 1; i < len(positions); i++ {
		dx := positions[i].X - positions[i-1].X
		dy := positions[i].Y - positions[i-1].Y
		dist := math.Sqrt(dx*dx + dy*dy)

		// Micro-movement: very small displacement (1-3 pixels)
		if dist >= 0.5 && dist <= 3.0 {
			microCount++
		}
		total++
	}

	if total == 0 {
		return 0
	}

	return float64(microCount) / float64(total)
}

// analyzeKeystrokeDynamics computes the coefficient of variation of keystroke intervals.
// Very low CV = mechanical typing (bot).
func (ba *BehavioralAnalyzer) analyzeKeystrokeDynamics(timestamps []int64) float64 {
	if len(timestamps) < 2 {
		return 1.0
	}

	intervals := make([]float64, 0, len(timestamps)-1)
	for i := 1; i < len(timestamps); i++ {
		diff := float64(timestamps[i] - timestamps[i-1])
		if diff > 0 {
			intervals = append(intervals, diff)
		}
	}

	if len(intervals) == 0 {
		return 1.0
	}

	mean, stddev := meanStddev(intervals)
	if mean == 0 {
		return 0
	}

	return stddev / mean
}

// meanStddev computes mean and standard deviation.
func meanStddev(values []float64) (float64, float64) {
	if len(values) == 0 {
		return 0, 0
	}

	var sum float64
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))

	var variance float64
	for _, v := range values {
		diff := v - mean
		variance += diff * diff
	}
	variance /= float64(len(values))

	return mean, math.Sqrt(variance)
}

// meanVariance computes mean and variance.
func meanVariance(values []float64) (float64, float64) {
	if len(values) == 0 {
		return 0, 0
	}

	var sum float64
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))

	var variance float64
	for _, v := range values {
		diff := v - mean
		variance += diff * diff
	}
	variance /= float64(len(values))

	return mean, variance
}

// chiSquaredUniformity computes a chi-squared statistic testing whether values
// follow a uniform distribution. Low values indicate suspiciously uniform data.
func (ba *BehavioralAnalyzer) chiSquaredUniformity(values []float64, numBins int) float64 {
	if len(values) < numBins {
		return 100.0 // Not enough data, return high (non-uniform)
	}

	minVal, maxVal := values[0], values[0]
	for _, v := range values[1:] {
		if v < minVal {
			minVal = v
		}
		if v > maxVal {
			maxVal = v
		}
	}

	if maxVal == minVal {
		return 0.0 // All identical = perfectly uniform
	}

	binWidth := (maxVal - minVal) / float64(numBins)
	bins := make([]int, numBins)
	for _, v := range values {
		bin := int((v - minVal) / binWidth)
		if bin >= numBins {
			bin = numBins - 1
		}
		bins[bin]++
	}

	expected := float64(len(values)) / float64(numBins)
	chiSq := 0.0
	for _, count := range bins {
		diff := float64(count) - expected
		chiSq += (diff * diff) / expected
	}

	return chiSq
}

// segmentEfficiencyRatios splits positions into n equal segments and computes
// the efficiency ratio (path length / direct distance) for each.
func (ba *BehavioralAnalyzer) segmentEfficiencyRatios(positions []Position, n int) []float64 {
	if len(positions) < n+1 {
		return nil
	}

	segLen := len(positions) / n
	ratios := make([]float64, 0, n)

	for i := 0; i < n; i++ {
		start := i * segLen
		end := start + segLen
		if i == n-1 {
			end = len(positions)
		}
		if end-start < 2 {
			continue
		}

		segment := positions[start:end]
		ratio := ba.pathEfficiencyRatio(segment)
		if ratio > 0 {
			ratios = append(ratios, ratio)
		}
	}

	return ratios
}

// pathEfficiencyRatio computes the ratio of total path length to direct distance.
// A value of 1.0 = perfectly straight line. Higher = more meandering.
func (ba *BehavioralAnalyzer) pathEfficiencyRatio(positions []Position) float64 {
	if len(positions) < 2 {
		return 0
	}

	// Direct distance (start to end)
	dx := positions[len(positions)-1].X - positions[0].X
	dy := positions[len(positions)-1].Y - positions[0].Y
	directDist := math.Sqrt(dx*dx + dy*dy)

	if directDist < 1.0 {
		return 0 // Too short to measure
	}

	// Path length
	pathLen := 0.0
	for i := 1; i < len(positions); i++ {
		dx = positions[i].X - positions[i-1].X
		dy = positions[i].Y - positions[i-1].Y
		pathLen += math.Sqrt(dx*dx + dy*dy)
	}

	return pathLen / directDist
}

func formatFloat(f float64) string {
	return fmt.Sprintf("%.6f", f)
}

// lag1Autocorrelation computes the lag-1 autocorrelation of a sequence.
// Positive values indicate temporal clustering (consecutive values are similar).
// Zero indicates independence. Negative indicates alternating pattern.
func (ba *BehavioralAnalyzer) lag1Autocorrelation(values []float64) float64 {
	return ba.lagNAutocorrelation(values, 1)
}

// lagNAutocorrelation computes the autocorrelation of a sequence at arbitrary lag.
// Returns 0 if insufficient data (need at least lag+2 values).
func (ba *BehavioralAnalyzer) lagNAutocorrelation(values []float64, lag int) float64 {
	n := len(values)
	if n < lag+2 {
		return 0
	}

	mean := 0.0
	for _, v := range values {
		mean += v
	}
	mean /= float64(n)

	var num, den float64
	for i := 0; i < n-lag; i++ {
		num += (values[i] - mean) * (values[i+lag] - mean)
	}
	for i := 0; i < n; i++ {
		den += (values[i] - mean) * (values[i] - mean)
	}

	if den == 0 {
		return 0
	}
	return num / den
}

// pearsonCorrelation computes the Pearson product-moment correlation coefficient
// between two sequences. Returns a value in [-1, 1].
func (ba *BehavioralAnalyzer) pearsonCorrelation(x, y []float64) float64 {
	n := len(x)
	if n != len(y) || n < 2 {
		return 0
	}

	var sumX, sumY, sumXY, sumX2, sumY2 float64
	for i := 0; i < n; i++ {
		sumX += x[i]
		sumY += y[i]
		sumXY += x[i] * y[i]
		sumX2 += x[i] * x[i]
		sumY2 += y[i] * y[i]
	}

	nf := float64(n)
	num := nf*sumXY - sumX*sumY
	den := math.Sqrt((nf*sumX2 - sumX*sumX) * (nf*sumY2 - sumY*sumY))
	if den == 0 {
		return 0
	}
	return num / den
}

// spearmanCorrelation computes Spearman's rank correlation coefficient between
// two sequences. Values near +1 or -1 indicate monotonic relationship.
// Values near 0 indicate no monotonic relationship (independence).
func (ba *BehavioralAnalyzer) spearmanCorrelation(x, y []float64) float64 {
	n := len(x)
	if n != len(y) || n < 3 {
		return 0
	}

	rankX := ba.computeRanks(x)
	rankY := ba.computeRanks(y)

	// Pearson correlation of ranks
	var sumXY, sumX, sumY, sumX2, sumY2 float64
	for i := 0; i < n; i++ {
		sumXY += rankX[i] * rankY[i]
		sumX += rankX[i]
		sumY += rankY[i]
		sumX2 += rankX[i] * rankX[i]
		sumY2 += rankY[i] * rankY[i]
	}

	nf := float64(n)
	num := nf*sumXY - sumX*sumY
	den := math.Sqrt((nf*sumX2 - sumX*sumX) * (nf*sumY2 - sumY*sumY))
	if den == 0 {
		return 0
	}
	return num / den
}

// computeRanks assigns ranks to values (1-based, ascending).
func (ba *BehavioralAnalyzer) computeRanks(values []float64) []float64 {
	n := len(values)
	type indexedValue struct {
		val float64
		idx int
	}
	sorted := make([]indexedValue, n)
	for i, v := range values {
		sorted[i] = indexedValue{v, i}
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].val < sorted[j].val })

	result := make([]float64, n)
	for rank, s := range sorted {
		result[s.idx] = float64(rank + 1)
	}
	return result
}
