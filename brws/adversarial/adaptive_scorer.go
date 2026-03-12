package adversarial

import (
	"math"
	"sync"
	"time"
)

// AdaptiveScorerConfig configures the adaptive scoring engine.
type AdaptiveScorerConfig struct {
	LearningRate    float64 // Weight adjustment rate
	MinWeight       float64 // Minimum weight for any vector
	MaxWeight       float64 // Maximum weight for any vector
	WeightedAvgPct  float64 // Percentage of score from weighted average
	MaxScorePct     float64 // Percentage from max-score
	MajorityVotePct float64 // Percentage from majority vote
	HistorySize     int     // Max bypass records to retain
}

// DefaultAdaptiveScorerConfig returns sensible defaults.
func DefaultAdaptiveScorerConfig() *AdaptiveScorerConfig {
	return &AdaptiveScorerConfig{
		LearningRate:    0.05,
		MinWeight:       0.1,
		MaxWeight:       2.0,
		WeightedAvgPct:  0.50,
		MaxScorePct:     0.30,
		MajorityVotePct: 0.20,
		HistorySize:     1000,
	}
}

// BypassRecord records the outcome of a detection attempt.
type BypassRecord struct {
	Timestamp time.Time
	Category  VectorCategory
	Score     float64
	Bypassed  bool // true if the sword evaded this vector
}

// EnsembleResult is the output of the adaptive scoring engine.
type EnsembleResult struct {
	FinalScore    float64                    `json:"final_score"`
	IsBot         bool                       `json:"is_bot"`
	WeightedAvg   float64                    `json:"weighted_avg"`
	MaxScore      float64                    `json:"max_score"`
	MajorityVote  float64                    `json:"majority_vote"`
	VectorWeights map[VectorCategory]float64 `json:"vector_weights"`
	VectorScores  map[VectorCategory]float64 `json:"vector_scores"`
}

// AdaptiveScorer adjusts detection vector weights based on historical bypass data.
// Vectors that are frequently bypassed get higher weights.
type AdaptiveScorer struct {
	mu            sync.RWMutex
	weights       map[VectorCategory]float64
	bypassHistory []BypassRecord
	config        *AdaptiveScorerConfig
}

// NewAdaptiveScorer creates a new AdaptiveScorer with default weights.
func NewAdaptiveScorer(config *AdaptiveScorerConfig) *AdaptiveScorer {
	if config == nil {
		config = DefaultAdaptiveScorerConfig()
	}

	weights := map[VectorCategory]float64{
		VectorTLS:                 1.0,
		VectorHTTP:                1.0,
		VectorHTTP2:               0.8,
		VectorBehavioral:          1.2,
		VectorWebGL:               1.0,
		VectorCanvas:              1.0,
		VectorNavigator:           1.0,
		VectorTiming:              0.8,
		VectorWebRTC:              1.0,
		VectorFont:                0.8,
		VectorScreen:              0.9,
		VectorPlugin:              0.7,
		VectorAudio:               1.0,
		VectorAutomation:          1.1,
		VectorHeadless:            0.9,
		VectorFingerprintCoverage: 1.0,
		VectorCrossVector:         1.0,
	}

	return &AdaptiveScorer{
		weights:       weights,
		bypassHistory: make([]BypassRecord, 0),
		config:        config,
	}
}

// ScoreResults computes the ensemble score from individual vector results.
func (as *AdaptiveScorer) ScoreResults(results map[VectorCategory]*VectorResult) *EnsembleResult {
	as.mu.RLock()
	defer as.mu.RUnlock()

	ensemble := &EnsembleResult{
		VectorWeights: make(map[VectorCategory]float64),
		VectorScores:  make(map[VectorCategory]float64),
	}

	// Copy current weights
	for cat, w := range as.weights {
		ensemble.VectorWeights[cat] = w
	}

	// Compute per-vector scores.
	// Non-diluting: only vectors with Score > 0 contribute to the weighted average.
	// This prevents passing vectors (Score=0) from drowning real signals.
	var activeWeight float64
	var activeSum float64
	var maxScore float64
	detectedCount := 0
	weakSignalCount := 0

	for cat, result := range results {
		weight := as.weights[cat]
		if weight == 0 {
			weight = 1.0
		}

		ensemble.VectorScores[cat] = result.Score

		if result.Score > 0 {
			activeSum += result.Score * weight
			activeWeight += weight
		}

		if result.Score > maxScore {
			maxScore = result.Score
		}

		if result.Detected {
			detectedCount++
		}

		if result.Score > 0.1 {
			weakSignalCount++
		}
	}

	// Component 1: Non-diluting weighted average (only active vectors)
	if activeWeight > 0 {
		ensemble.WeightedAvg = activeSum / activeWeight
	}

	// Component 2: Max score
	ensemble.MaxScore = maxScore

	// Component 3: Majority vote (fraction of vectors that detected)
	if len(results) > 0 {
		ensemble.MajorityVote = float64(detectedCount) / float64(len(results))
	}

	// Ensemble: combine all three components
	ensemble.FinalScore = as.config.WeightedAvgPct*ensemble.WeightedAvg +
		as.config.MaxScorePct*ensemble.MaxScore +
		as.config.MajorityVotePct*ensemble.MajorityVote

	// Compound signal amplifier: when multiple independent weak signals fire,
	// the probability of ALL being false positives is very low. Boost accordingly.
	if weakSignalCount >= 2 {
		compoundBoost := math.Min(0.25, 0.05*float64(weakSignalCount-1))
		ensemble.FinalScore += compoundBoost
	}

	// "Too clean" penalty: if many vectors were evaluated but all returned 0,
	// a real browser would typically trigger at least minor signals.
	if len(results) >= 10 && weakSignalCount == 0 {
		ensemble.FinalScore += 0.05
	}

	ensemble.FinalScore = math.Min(1.0, ensemble.FinalScore)
	ensemble.IsBot = ensemble.FinalScore > 0.35

	return ensemble
}

// RecordOutcome records a bypass attempt outcome for weight adjustment.
func (as *AdaptiveScorer) RecordOutcome(record BypassRecord) {
	as.mu.Lock()
	defer as.mu.Unlock()

	as.bypassHistory = append(as.bypassHistory, record)

	// Trim history
	if len(as.bypassHistory) > as.config.HistorySize {
		as.bypassHistory = as.bypassHistory[len(as.bypassHistory)-as.config.HistorySize:]
	}

	// Adjust weights
	as.adjustWeightsLocked()
}

// adjustWeightsLocked adjusts vector weights based on bypass rates.
// Vectors that are frequently bypassed get higher weights.
// Must be called with as.mu held.
func (as *AdaptiveScorer) adjustWeightsLocked() {
	// Compute bypass rate per category
	bypassCounts := make(map[VectorCategory]int)
	totalCounts := make(map[VectorCategory]int)

	for _, record := range as.bypassHistory {
		totalCounts[record.Category]++
		if record.Bypassed {
			bypassCounts[record.Category]++
		}
	}

	for cat := range as.weights {
		total := totalCounts[cat]
		if total < 5 {
			continue // Not enough data
		}

		bypassRate := float64(bypassCounts[cat]) / float64(total)

		// w_new = clamp(w_old + lr * (bypass_rate - 0.5), min, max)
		// Bypass rate > 0.5 → increase weight (harder to bypass next time)
		// Bypass rate < 0.5 → decrease weight (already effective)
		adjustment := as.config.LearningRate * (bypassRate - 0.5)
		newWeight := as.weights[cat] + adjustment

		// Clamp
		if newWeight < as.config.MinWeight {
			newWeight = as.config.MinWeight
		}
		if newWeight > as.config.MaxWeight {
			newWeight = as.config.MaxWeight
		}

		as.weights[cat] = newWeight
	}
}

// GetWeights returns a copy of current vector weights.
func (as *AdaptiveScorer) GetWeights() map[VectorCategory]float64 {
	as.mu.RLock()
	defer as.mu.RUnlock()

	weights := make(map[VectorCategory]float64, len(as.weights))
	for k, v := range as.weights {
		weights[k] = v
	}
	return weights
}

// GetBypassRates returns the current bypass rate per category.
func (as *AdaptiveScorer) GetBypassRates() map[VectorCategory]float64 {
	as.mu.RLock()
	defer as.mu.RUnlock()

	rates := make(map[VectorCategory]float64)
	counts := make(map[VectorCategory]int)
	bypassed := make(map[VectorCategory]int)

	for _, record := range as.bypassHistory {
		counts[record.Category]++
		if record.Bypassed {
			bypassed[record.Category]++
		}
	}

	for cat, total := range counts {
		if total > 0 {
			rates[cat] = float64(bypassed[cat]) / float64(total)
		}
	}

	return rates
}
