package detection

import (
	"testing"
	"time"
)

func TestAdaptiveScorer_BasicScoring(t *testing.T) {
	scorer := NewAdaptiveScorer(nil)

	results := map[VectorCategory]*VectorResult{
		VectorTLS: {
			Category: VectorTLS,
			Detected: true,
			Score:    0.5,
		},
		VectorHTTP: {
			Category: VectorHTTP,
			Detected: true,
			Score:    0.7,
		},
		VectorBehavioral: {
			Category: VectorBehavioral,
			Detected: false,
			Score:    0.1,
		},
	}

	ensemble := scorer.ScoreResults(results)

	if ensemble.FinalScore <= 0 {
		t.Error("expected positive final score")
	}
	if ensemble.MaxScore != 0.7 {
		t.Errorf("expected max score 0.7, got %.4f", ensemble.MaxScore)
	}
	if ensemble.MajorityVote == 0 {
		t.Error("expected non-zero majority vote (2/3 detected)")
	}
}

func TestAdaptiveScorer_AllClear(t *testing.T) {
	scorer := NewAdaptiveScorer(nil)

	results := map[VectorCategory]*VectorResult{
		VectorTLS:  {Category: VectorTLS, Detected: false, Score: 0.0},
		VectorHTTP: {Category: VectorHTTP, Detected: false, Score: 0.05},
	}

	ensemble := scorer.ScoreResults(results)

	if ensemble.IsBot {
		t.Error("all clear results should not be classified as bot")
	}
	if ensemble.FinalScore > 0.35 {
		t.Errorf("expected low score for all clear, got %.4f", ensemble.FinalScore)
	}
}

func TestAdaptiveScorer_WeightAdjustment(t *testing.T) {
	scorer := NewAdaptiveScorer(nil)

	initialTLSWeight := scorer.GetWeights()[VectorTLS]

	// Record many TLS bypasses
	for i := 0; i < 20; i++ {
		scorer.RecordOutcome(BypassRecord{
			Timestamp: time.Now(),
			Category:  VectorTLS,
			Score:     0.5,
			Bypassed:  true,
		})
	}

	adjustedTLSWeight := scorer.GetWeights()[VectorTLS]

	if adjustedTLSWeight <= initialTLSWeight {
		t.Errorf("TLS weight should increase after frequent bypasses: initial=%.4f, adjusted=%.4f",
			initialTLSWeight, adjustedTLSWeight)
	}
}

func TestAdaptiveScorer_WeightDecrease(t *testing.T) {
	scorer := NewAdaptiveScorer(nil)

	initialHTTPWeight := scorer.GetWeights()[VectorHTTP]

	// Record many HTTP non-bypasses (vector is effective)
	for i := 0; i < 20; i++ {
		scorer.RecordOutcome(BypassRecord{
			Timestamp: time.Now(),
			Category:  VectorHTTP,
			Score:     0.8,
			Bypassed:  false,
		})
	}

	adjustedHTTPWeight := scorer.GetWeights()[VectorHTTP]

	if adjustedHTTPWeight >= initialHTTPWeight {
		t.Errorf("HTTP weight should decrease when rarely bypassed: initial=%.4f, adjusted=%.4f",
			initialHTTPWeight, adjustedHTTPWeight)
	}
}

func TestAdaptiveScorer_WeightClamp(t *testing.T) {
	config := DefaultAdaptiveScorerConfig()
	config.LearningRate = 1.0 // Very aggressive
	scorer := NewAdaptiveScorer(config)

	// Record massive bypasses
	for i := 0; i < 100; i++ {
		scorer.RecordOutcome(BypassRecord{
			Timestamp: time.Now(),
			Category:  VectorTLS,
			Score:     0.5,
			Bypassed:  true,
		})
	}

	weight := scorer.GetWeights()[VectorTLS]
	if weight > config.MaxWeight {
		t.Errorf("weight %.4f exceeds max %.4f", weight, config.MaxWeight)
	}

	// Record massive non-bypasses
	for i := 0; i < 200; i++ {
		scorer.RecordOutcome(BypassRecord{
			Timestamp: time.Now(),
			Category:  VectorTLS,
			Score:     0.5,
			Bypassed:  false,
		})
	}

	weight = scorer.GetWeights()[VectorTLS]
	if weight < config.MinWeight {
		t.Errorf("weight %.4f below min %.4f", weight, config.MinWeight)
	}
}

func TestAdaptiveScorer_BypassRates(t *testing.T) {
	scorer := NewAdaptiveScorer(nil)

	// 7 bypasses, 3 non-bypasses for TLS
	for i := 0; i < 7; i++ {
		scorer.RecordOutcome(BypassRecord{
			Timestamp: time.Now(),
			Category:  VectorTLS,
			Bypassed:  true,
		})
	}
	for i := 0; i < 3; i++ {
		scorer.RecordOutcome(BypassRecord{
			Timestamp: time.Now(),
			Category:  VectorTLS,
			Bypassed:  false,
		})
	}

	rates := scorer.GetBypassRates()
	if rate, ok := rates[VectorTLS]; !ok || rate != 0.7 {
		t.Errorf("expected TLS bypass rate 0.7, got %.4f", rate)
	}
}

func TestAdaptiveScorer_EnsembleComponents(t *testing.T) {
	config := DefaultAdaptiveScorerConfig()
	scorer := NewAdaptiveScorer(config)

	results := map[VectorCategory]*VectorResult{
		VectorTLS:  {Category: VectorTLS, Detected: true, Score: 0.8},
		VectorHTTP: {Category: VectorHTTP, Detected: true, Score: 0.6},
	}

	ensemble := scorer.ScoreResults(results)

	// Verify components are within expected ranges
	if ensemble.WeightedAvg < 0 || ensemble.WeightedAvg > 1 {
		t.Errorf("weighted avg out of range: %.4f", ensemble.WeightedAvg)
	}
	if ensemble.MaxScore != 0.8 {
		t.Errorf("expected max score 0.8, got %.4f", ensemble.MaxScore)
	}
	if ensemble.MajorityVote != 1.0 {
		t.Errorf("expected majority vote 1.0 (all detected), got %.4f", ensemble.MajorityVote)
	}
	if ensemble.FinalScore > 1.0 {
		t.Errorf("final score should be clamped to 1.0, got %.4f", ensemble.FinalScore)
	}
}
