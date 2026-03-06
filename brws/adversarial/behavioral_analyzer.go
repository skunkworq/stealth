package adversarial

import "math"

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

// Note: VectorResult, VectorIndicator, and VectorCategory types are defined in vectors.go

// Analyze runs the full behavioral analysis suite and returns a VectorResult.
func (ba *BehavioralAnalyzer) Analyze(events *EnhancedBehavioralEvents) *VectorResult {
	result := &VectorResult{
		Vector:     "behavioral",
		Category:   VectorBehavioral,
		Detected:   false,
		Score:      0,
		Indicators: make([]VectorIndicator, 0),
	}

	if events == nil {
		return result
	}

	// If no raw events but summary stats are present, use fallback analysis
	if len(events.MouseTimestamps) == 0 && len(events.TypingTimestamps) == 0 && len(events.ScrollTimestamps) == 0 {
		return ba.analyzeFallback(events, result)
	}

	// Run all check categories
	ba.checkMouseEvents(events, result)
	ba.checkTypingEvents(events, result)
	ba.checkScrollEvents(events, result)
	ba.checkTimingPatterns(events, result)
	ba.checkClickPatterns(events, result)

	// Clamp score to maximum of 1.0
	if result.Score > 1.0 {
		result.Score = 1.0
	}
	result.Detected = result.Score > 0.5

	return result
}

// checkMouseEvents runs all mouse-related checks.
func (ba *BehavioralAnalyzer) checkMouseEvents(events *EnhancedBehavioralEvents, result *VectorResult) {
	if len(events.MouseTimestamps) < 3 {
		return
	}

	// Check 1: Interval entropy
	entropy := calculateIntervalEntropy(events.MouseTimestamps)
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

	// Check 2: Path curvature variance
	if len(events.MousePositions) >= 3 {
		_, _, variance := ba.calculatePathCurvature(events.MousePositions)
		if variance < ba.config.MinCurvatureVariance {
			weight := 0.25
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "path_too_straight",
				Message: "Mouse path is suspiciously straight (low curvature variance)",
				Weight:  weight,
				Field:   "path_curvature_variance",
				Value:   formatFloat(variance),
			})
			result.Score += weight
		}
	}

	// Check 3: Impossible velocity
	if len(events.MouseVelocities) > 0 {
		maxVel := 0.0
		for _, v := range events.MouseVelocities {
			if v > maxVel {
				maxVel = v
			}
		}
		if maxVel > ba.config.MaxVelocity {
			weight := 0.15
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "impossible_velocity",
				Message: "Mouse velocity exceeds human capability",
				Weight:  weight,
				Field:   "max_velocity",
				Value:   formatFloat(maxVel),
			})
			result.Score += weight
		}
	}

	// Check 4: Micro-tremor analysis
	if len(events.MousePositions) >= 3 {
		tremorRatio := ba.analyzeMouseMicroMovements(events.MousePositions)
		if tremorRatio < ba.config.MinMicroTremorRatio {
			weight := 0.20
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "missing_micro_tremors",
				Message: "No micro-tremors detected (human hands always have small jitter)",
				Weight:  weight,
				Field:   "micro_tremor_ratio",
				Value:   formatFloat(tremorRatio),
			})
			result.Score += weight
		}
	}
}

// checkTypingEvents runs all typing/keystroke checks.
func (ba *BehavioralAnalyzer) checkTypingEvents(events *EnhancedBehavioralEvents, result *VectorResult) {
	if len(events.TypingTimestamps) < 2 {
		return
	}

	// Check keystroke dynamics
	cv := ba.analyzeKeystrokeDynamics(events.TypingTimestamps)
	if cv < ba.config.MaxKeystrokeUniformCV {
		weight := 0.30
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "mechanical_typing",
			Message: "Typing intervals too uniform (mechanical/bot-like)",
			Weight:  weight,
			Field:   "typing_interval_cv",
			Value:   formatFloat(cv),
		})
		result.Score += weight
	}
}

// checkScrollEvents runs all scroll-related checks.
func (ba *BehavioralAnalyzer) checkScrollEvents(events *EnhancedBehavioralEvents, result *VectorResult) {
	if len(events.ScrollTimestamps) < 3 {
		return
	}

	// Check scroll interval entropy
	entropy := calculateIntervalEntropy(events.ScrollTimestamps)
	if entropy < ba.config.MinIntervalEntropy {
		weight := 0.25
		result.Indicators = append(result.Indicators, VectorIndicator{
			Check:   "scroll_interval_entropy_low",
			Message: "Scroll intervals are too uniform",
			Weight:  weight,
			Field:   "scroll_interval_entropy",
			Value:   formatFloat(entropy),
		})
		result.Score += weight
	}
}

// checkTimingPatterns runs timing-based checks.
func (ba *BehavioralAnalyzer) checkTimingPatterns(events *EnhancedBehavioralEvents, result *VectorResult) {
	// Combine all timestamps for event timing analysis
	allTimestamps := make([]int64, 0)
	allTimestamps = append(allTimestamps, events.MouseTimestamps...)
	allTimestamps = append(allTimestamps, events.TypingTimestamps...)
	allTimestamps = append(allTimestamps, events.ScrollTimestamps...)

	if len(allTimestamps) < 3 {
		return
	}

	// Check for synthetic timestamp base (timestamps that are suspiciously round)
	firstTimestamp := allTimestamps[0]
	if firstTimestamp > 1_000_000_000_000 && firstTimestamp%1000 == 0 {
		// Check if multiple timestamps fall on exact intervals
		exactIntervals := 0
		for i := 1; i < len(allTimestamps); i++ {
			interval := allTimestamps[i] - allTimestamps[i-1]
			if interval > 0 && interval%100 == 0 {
				exactIntervals++
			}
		}
		if float64(exactIntervals) > float64(len(allTimestamps))*0.3 {
			weight := 0.20
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "synthetic_timestamp_base",
				Message: "Event timestamps appear synthetically generated",
				Weight:  weight,
				Field:   "exact_interval_ratio",
				Value:   formatFloat(float64(exactIntervals) / float64(len(allTimestamps))),
			})
			result.Score += weight
		}
	}
}

// checkClickPatterns runs click-related checks.
func (ba *BehavioralAnalyzer) checkClickPatterns(events *EnhancedBehavioralEvents, result *VectorResult) {
	if len(events.ClickTimestamps) == 0 {
		return
	}

	// Check for perfectly synchronized click timestamps with other events
	if len(events.MouseTimestamps) > 0 && len(events.ClickTimestamps) > 0 {
		// Check if any click timestamp exactly matches a mouse timestamp
		matches := 0
		for _, ct := range events.ClickTimestamps {
			for _, mt := range events.MouseTimestamps {
				if ct == mt {
					matches++
					break
				}
			}
		}
		if len(events.ClickTimestamps) > 0 && float64(matches)/float64(len(events.ClickTimestamps)) > 0.5 {
			weight := 0.15
			result.Indicators = append(result.Indicators, VectorIndicator{
				Check:   "click_timestamp_sync_anomaly",
				Message: "Click timestamps too closely synchronized with mouse events",
				Weight:  weight,
				Field:   "click_sync_ratio",
				Value:   formatFloat(float64(matches) / float64(len(events.ClickTimestamps))),
			})
			result.Score += weight
		}
	}
}

// analyzeFallback performs analysis based on summary statistics when raw data is unavailable.
func (ba *BehavioralAnalyzer) analyzeFallback(events *EnhancedBehavioralEvents, result *VectorResult) *VectorResult {
	if events.MouseStdDev == 0 && len(events.MouseTimestamps) > 0 {
		result.Indicators = append(result.Indicators, VectorIndicator{Check: "zero_mouse_variance"})
		result.Score += 0.4
	}
	if events.TypingStdDev == 0 && len(events.TypingTimestamps) > 0 {
		result.Indicators = append(result.Indicators, VectorIndicator{Check: "zero_typing_variance"})
		result.Score += 0.3
	}
	if events.EventTimingStdDev == 0 && (len(events.MouseTimestamps) > 0 || len(events.TypingTimestamps) > 0) {
		result.Indicators = append(result.Indicators, VectorIndicator{Check: "perfect_event_pacing"})
		result.Score += 0.4
	}
	if events.MouseEvents < 5 && len(events.MouseTimestamps) > 0 {
		result.Indicators = append(result.Indicators, VectorIndicator{Check: "too_few_mouse_events"})
		result.Score += 0.2
	}
	if events.MouseStraightness > 0.95 {
		result.Indicators = append(result.Indicators, VectorIndicator{Check: "linear_mouse_movement"})
		result.Score += 0.3
	}

	if result.Score > 1.0 {
		result.Score = 1.0
	}
	result.Detected = result.Score > 0.3
	return result
}

// analyzeMouseMicroMovements detects the presence of involuntary micro-tremors.
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

		// Micro-movement: very small displacement (0.5-3 pixels)
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

// CalculateIntervalEntropy is a public wrapper for calculateIntervalEntropy.
func (ba *BehavioralAnalyzer) CalculateIntervalEntropy(timestamps []int64) float64 {
	return calculateIntervalEntropy(timestamps)
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
