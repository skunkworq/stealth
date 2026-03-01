package lab

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/stealth/brwslab/brws/adversarial"
	_ "github.com/stealth/brwslab/brws/engine/chromium"
	"github.com/stealth/brwslab/brws/stealth"
)

// MLEvaluationRequest represents a single FSM state permutation
// synthesized by the Python Reinforcement Learning Agent.
type MLEvaluationRequest struct {
	FSMConfig stealth.StealthConfig `json:"fsm_config"`
	TargetURL string                `json:"target_url,omitempty"`
}

// MLEvaluationResponse represents the reward output from the WAF Shield.
type MLEvaluationResponse struct {
	Success          bool                          `json:"success"`
	TraceID          string                        `json:"trace_id"`
	BotScore         float64                       `json:"bot_score"`
	IsBot            bool                          `json:"is_bot"`
	Anomalies        []string                      `json:"anomalies"`
	RawPayload       *adversarial.StealthDetection `json:"raw_payload,omitempty"`
	CaptchaPresented bool                          `json:"captcha_presented"`
	CaptchaType      string                        `json:"captcha_type,omitempty"`
	CaptchaSolved    bool                          `json:"captcha_solved"`
	CaptchaSolveMs   int64                         `json:"captcha_solve_time_ms,omitempty"`
	Error            string                        `json:"error,omitempty"`
}

// handleMLEvaluate is the bridge endpoint. Python PyTorch loops submit
// synthetic fingerprint configurations here. This controller spins up
// a real headless browser, applies the FSM config, hits the local target,
// and instantly returns the extracted WAF trace scores.
func (s *EnhancedServer) handleMLEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req MLEvaluationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("Failed to decode ML Evaluation Request", "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Default to targeting our local test trap if none provided
	if req.TargetURL == "" {
		req.TargetURL = "http://localhost:8080/api/ml/trap"
	}

	traceID := fmt.Sprintf("ml_eval_%d", time.Now().UnixNano())

	// 1. Initialize our Stealth Client with the Python-Injected FSM config
	cfg := stealth.DefaultConfig()
	cfg.Stealth = &req.FSMConfig
	client, err := stealth.NewWithConfig(cfg)
	if err != nil {
		s.respondMLError(w, traceID, fmt.Sprintf("Failed to initialize Chrome Client: %v", err))
		return
	}
	defer func() { _ = client.Close() }()

	// 2. Navigate to the local WAF trap hook
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s.logger.Debug("ML Agent initiating evaluation sprint", "trace_id", traceID)
	
	// Execute the navigation. This sends traffic directly through our `stealth_detector.go`
	_, _ = client.Navigate(ctx, req.TargetURL)
	
	// Wait momentarily to ensure the capture infrastructure processes the HTTP/JS layer events
	time.Sleep(500 * time.Millisecond)

	// 3. Extract the exact output from the Adversarial Detector singleton
	// NOTE: In a multi-threaded training environment, we would need to correlate the exact 
	// trace ID to the detector memory block. Since this is local sequential RL training,
	// we just pull the absolute newest detection trap result from the top of the stack.
	
	allDetections := s.stealthServer.GetDetections()
	s.logger.Info("Total WAF Detections in Memory", "count", len(allDetections))
	if len(allDetections) == 0 {
		s.respondMLError(w, traceID, "Evaluation failed: WAF Detector registered 0 traces")
		return
	}
	latestDetection := allDetections[len(allDetections)-1]

	// Extract standard text indicators for RL parsing
	anomalies := make([]string, 0)
	for _, vec := range latestDetection.Vectors {
		if vec.Detected {
			anomalies = append(anomalies, vec.Indicators...)
		}
	}

	resp := MLEvaluationResponse{
		Success:    true,
		TraceID:    traceID,
		BotScore:   latestDetection.Score,
		IsBot:      latestDetection.IsBot,
		Anomalies:  anomalies,
		RawPayload: &latestDetection,
	}

	// Phase 17: Check if a CAPTCHA was issued and attempt to solve it
	for _, vec := range latestDetection.Vectors {
		for _, ind := range vec.Indicators {
			if ind == "captcha_challenge_issued" {
				resp.CaptchaPresented = true
			}
		}
	}

	// Also check the raw detection response from the stealthServer
	allChallenges := s.stealthServer.CaptchaShield.GetActiveChallenges()
	if len(allChallenges) > 0 {
		latestChallenge := allChallenges[len(allChallenges)-1]
		resp.CaptchaPresented = true
		resp.CaptchaType = latestChallenge.Type
		
		// Attempt to solve using ValidateChallenge with the challenge ID as answer
		solved, metrics := s.stealthServer.CaptchaShield.ValidateChallenge(latestChallenge.ID, latestChallenge.ID)
		resp.CaptchaSolved = solved
		if metrics != nil {
			resp.CaptchaSolveMs = metrics.SolveTimeMs
		}
		s.logger.Info("CAPTCHA solve attempt", "challenge_id", latestChallenge.ID, "type", latestChallenge.Type, "solved", solved)
	}

	s.logger.Info("Raw WAF anomalies", "anomalies", anomalies)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error("Failed to encode ML Evaluation Response", "error", err)
	}
}

func (s *EnhancedServer) respondMLError(w http.ResponseWriter, traceID string, errMsg string) {
	resp := MLEvaluationResponse{
		Success: false,
		TraceID: traceID,
		Error:   errMsg,
	}
	w.WriteHeader(http.StatusInternalServerError)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error("Failed to encode ML error response", "error", err)
	}
}
