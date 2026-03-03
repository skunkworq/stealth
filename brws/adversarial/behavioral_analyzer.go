package adversarial

import (
	"fmt"
	"math"
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
