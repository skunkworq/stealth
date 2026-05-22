package capture

import (
	"encoding/json"
	"net/http"

	"golang.org/x/net/websocket"

	"github.com/skunkworq/stealth/brws/core/detection"
	"github.com/skunkworq/stealth/brws/stealth/behavior"
)

// ProfileResult contains per-profile shield evaluation results.
type ProfileResult struct {
	Name       string             `json:"name"`
	Platform   string             `json:"platform"`
	Score      float64            `json:"score"`
	IsBot      bool               `json:"is_bot"`
	Vectors    map[string]float64 `json:"vectors"`
	Indicators []string           `json:"indicators"`
}

// ShieldSummary contains aggregate evaluation metrics.
type ShieldSummary struct {
	CatchRate float64 `json:"catch_rate"`
	AvgScore  float64 `json:"avg_score"`
	Threshold float64 `json:"threshold"`
}

// ShieldEvalResponse is the response from /api/shield/evaluate.
type ShieldEvalResponse struct {
	Profiles []ProfileResult `json:"profiles"`
	Summary  ShieldSummary   `json:"summary"`
}

// ShieldMetricsResponse is the response from /api/shield/metrics.
type ShieldMetricsResponse struct {
	Weights     map[string]float64 `json:"weights"`
	BypassRates map[string]float64 `json:"bypass_rates"`
	Threshold   float64            `json:"threshold"`
}

// handleShieldEvaluate runs sword profiles through the shield and returns per-profile
// scores, per-vector breakdown, and aggregate metrics.
func (s *EnhancedServer) handleShieldEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	profiles := behavior.DefaultProfiles()
	results := make([]ProfileResult, 0, len(profiles))
	caughtCount := 0
	totalScore := 0.0

	for _, profile := range profiles {
		detector := detection.NewStealthDetector()
		gen := behavior.NewRequestGenerator(&behavior.RequestGeneratorConfig{
			Profile: profile,
		})
		req := gen.GenerateRequest("http://test/api/ml/trap")
		result := detector.AnalyzeRequest(req, nil)

		vectors := make(map[string]float64)
		indicators := make([]string, 0)

		for _, v := range result.Vectors {
			vectors[v.Category] = v.Score
			if v.Score > 0 {
				indicators = append(indicators, v.Indicators...)
			}
		}

		if result.IsBot {
			caughtCount++
		}
		totalScore += result.Score

		results = append(results, ProfileResult{
			Name:       profile.Name,
			Platform:   profile.Platform,
			Score:      result.Score,
			IsBot:      result.IsBot,
			Vectors:    vectors,
			Indicators: indicators,
		})
	}

	resp := ShieldEvalResponse{
		Profiles: results,
		Summary: ShieldSummary{
			CatchRate: float64(caughtCount) / float64(len(profiles)),
			AvgScore:  totalScore / float64(len(profiles)),
			Threshold: 0.35,
		},
	}

	// Broadcast detection to WebSocket clients
	s.broadcastShieldDetection(resp)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleShieldMetrics returns the adaptive scorer's current weights and bypass rates.
func (s *EnhancedServer) handleShieldMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	scorer := detection.NewAdaptiveScorer(nil)
	rawWeights := scorer.GetWeights()
	rawBypassRates := scorer.GetBypassRates()

	weights := make(map[string]float64, len(rawWeights))
	for k, v := range rawWeights {
		weights[string(k)] = v
	}

	bypassRates := make(map[string]float64, len(rawBypassRates))
	for k, v := range rawBypassRates {
		bypassRates[string(k)] = v
	}

	resp := ShieldMetricsResponse{
		Weights:     weights,
		BypassRates: bypassRates,
		Threshold:   0.35,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// broadcastShieldDetection sends shield evaluation results to all WebSocket clients.
func (s *EnhancedServer) broadcastShieldDetection(eval ShieldEvalResponse) {
	s.wsMu.RLock()
	clients := make([]*websocket.Conn, 0, len(s.wsClients))
	for client := range s.wsClients {
		clients = append(clients, client)
	}
	s.wsMu.RUnlock()

	msg := map[string]interface{}{
		"type":          "shield_detection",
		"catch_rate":    eval.Summary.CatchRate,
		"avg_score":     eval.Summary.AvgScore,
		"threshold":     eval.Summary.Threshold,
		"profile_count": len(eval.Profiles),
	}

	for _, client := range clients {
		if err := websocket.JSON.Send(client, msg); err != nil {
			s.logger.Debug("Failed to send shield detection to WebSocket client", "error", err)
			s.wsMu.Lock()
			delete(s.wsClients, client)
			s.wsMu.Unlock()
			_ = client.Close()
		}
	}
}
