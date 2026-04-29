package lab

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/skunkworq/stealth/brws/stealth/challenge"
)

// handleManualSolve handles POST /api/captcha/manual-solve
func (s *EnhancedServer) handleManualSolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Image    string                `json:"image"` // base64 encoded
		Type     string                `json:"type"`
		Solution string                `json:"solution"`
		Events   []CaptchaEventCapture `json:"events"`
		IsExpert bool                  `json:"is_expert"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	// Create a challenge from the manual submission
	sessionID := fmt.Sprintf("manual_%d", time.Now().UnixNano())
	ch, err := s.stealthServer.CaptchaShield.CreateChallenge(sessionID, nil, req.Type)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	// Record events
	for _, event := range req.Events {
		s.stealthServer.Tracer.AddEvent(ch.ID, challenge.CaptchaEvent{
			Type:      event.Type,
			Timestamp: event.Timestamp,
			X:         event.X,
			Y:         event.Y,
			Key:       event.Key,
			Delta:     event.Delta,
		})
	}

	// Get bot score
	trace, _ := s.stealthServer.Tracer.GetTrace(ch.ID)
	var botScore float64
	if trace != nil {
		botScore = s.stealthServer.Tracer.CalculateBotScore(trace)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"challenge_id": ch.ID,
		"bot_score":    botScore,
		"type":         req.Type,
		"status":       "recorded",
	})
}

// handleTrainingSamples handles GET /api/training/samples
func (s *EnhancedServer) handleTrainingSamples(w http.ResponseWriter, r *http.Request) {
	limit := 50
	offset := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if n, err := strconv.Atoi(o); err == nil && n >= 0 {
			offset = n
		}
	}

	typeFilter := r.URL.Query().Get("type")
	labelFilter := r.URL.Query().Get("label")

	samples, total := s.stealthServer.CaptchaShield.GetTrainingData().GetSamplesFiltered(typeFilter, labelFilter, limit, offset)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"samples": samples,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

// handleTrainingExport handles GET /api/training/export
func (s *EnhancedServer) handleTrainingExport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	switch format {
	case "csv":
		csvData, err := s.stealthServer.CaptchaShield.GetTrainingData().ExportCSV()
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=training_data.csv")
		_, _ = w.Write(csvData)
	default:
		data, err := s.stealthServer.CaptchaShield.GetTrainingData().ExportForML()
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=training_data.json")
		_, _ = w.Write(data)
	}
}

// handleTrainingStats handles GET /api/training/stats
func (s *EnhancedServer) handleTrainingStats(w http.ResponseWriter, r *http.Request) {
	stats := s.stealthServer.CaptchaShield.GetTrainingData().GetStats()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}
