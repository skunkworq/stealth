package capture

import (
	"encoding/json"
	"net/http"
)

// handleV3Assessments returns the stored v3 assessment records as JSON.
func (s *EnhancedServer) handleV3Assessments(w http.ResponseWriter, _ *http.Request) {
	records := s.stealthServer.GetV3Assessments()
	w.Header().Set("Content-Type", "application/json")
	//nolint:errchkjson
	_ = json.NewEncoder(w).Encode(records)
}

// v3MetricsResponse contains aggregated metrics for v3 assessments.
type v3MetricsResponse struct {
	Total        int                       `json:"total"`
	AvgV3Score   float64                   `json:"avg_v3_score"`
	AvgDetection float64                   `json:"avg_detection_score"`
	AvgBehav     float64                   `json:"avg_behavioral_score"`
	PassRate     float64                   `json:"pass_rate"`
	ScoreBuckets map[string]int            `json:"score_buckets"`
	ByAction     map[string]*actionMetrics `json:"by_action"`
}

// actionMetrics contains per-action aggregated metrics.
type actionMetrics struct {
	Count    int     `json:"count"`
	AvgScore float64 `json:"avg_score"`
	PassRate float64 `json:"pass_rate"`
}

// handleV3Metrics computes and returns aggregated metrics from stored assessments.
func (s *EnhancedServer) handleV3Metrics(w http.ResponseWriter, _ *http.Request) {
	records := s.stealthServer.GetV3Assessments()

	resp := v3MetricsResponse{
		Total:        len(records),
		ScoreBuckets: map[string]int{"high": 0, "medium": 0, "low": 0},
		ByAction:     make(map[string]*actionMetrics),
	}

	if len(records) == 0 {
		w.Header().Set("Content-Type", "application/json")
		//nolint:errchkjson
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	var sumV3, sumDet, sumBehav float64
	passCount := 0

	for _, r := range records {
		sumV3 += r.V3Score
		sumDet += r.DetectionScore
		sumBehav += r.BehavioralScore

		if r.V3Score >= 0.5 {
			passCount++
		}

		// Score buckets
		switch {
		case r.V3Score >= 0.7:
			resp.ScoreBuckets["high"]++
		case r.V3Score >= 0.3:
			resp.ScoreBuckets["medium"]++
		default:
			resp.ScoreBuckets["low"]++
		}

		// Per-action metrics
		am, ok := resp.ByAction[r.Action]
		if !ok {
			am = &actionMetrics{}
			resp.ByAction[r.Action] = am
		}
		am.Count++
		am.AvgScore += r.V3Score
		if r.V3Score >= 0.5 {
			am.PassRate++
		}
	}

	n := float64(len(records))
	resp.AvgV3Score = sumV3 / n
	resp.AvgDetection = sumDet / n
	resp.AvgBehav = sumBehav / n
	resp.PassRate = float64(passCount) / n

	// Finalize per-action averages
	for _, am := range resp.ByAction {
		c := float64(am.Count)
		am.AvgScore /= c
		am.PassRate /= c
	}

	w.Header().Set("Content-Type", "application/json")
	//nolint:errchkjson
	_ = json.NewEncoder(w).Encode(resp)
}
