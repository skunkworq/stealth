package challenge

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
