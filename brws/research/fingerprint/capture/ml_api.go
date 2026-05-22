package capture

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/skunkworq/stealth/brws/core/detection"
	cstealth "github.com/skunkworq/stealth/brws/stealth/chromium"
	"github.com/skunkworq/stealth/brws/research/fingerprint/training"
	"github.com/skunkworq/stealth/brws/stealth"
)

// MLEvaluationResponse represents the reward output from the WAF Shield.
type MLEvaluationResponse struct {
	Success          bool                          `json:"success"`
	TraceID          string                        `json:"trace_id"`
	BotScore         float64                       `json:"bot_score"`
	IsBot            bool                          `json:"is_bot"`
	Anomalies        []string                      `json:"anomalies"`
	RawPayload       *detection.StealthDetection `json:"raw_payload,omitempty"`
	CaptchaPresented bool                          `json:"captcha_presented"`
	CaptchaType      string                        `json:"captcha_type,omitempty"`
	CaptchaSolved    bool                          `json:"captcha_solved"`
	CaptchaSolveMs   int64                         `json:"captcha_solve_time_ms,omitempty"`
	Error            string                        `json:"error,omitempty"`
}

// handleMLEvaluate is the bridge endpoint. It accepts both Python RL format
// (fsm_config) and ml_datagen format (stealth_config). When fast_mode is true
// (default for stealth_config), evaluation runs through synthetic request
// analysis without launching a browser.
func (s *EnhancedServer) handleMLEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req unifiedMLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("Failed to decode ML Evaluation Request", "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Default fast_mode=true when stealth_config is present (ml_datagen path)
	if req.StealthConfig != nil && !req.FastMode && len(req.FSMConfig) == 0 {
		req.FastMode = true
	}

	// Resolve the stealth config snapshot from either format
	var snapshot *training.StealthConfigSnapshot
	if req.StealthConfig != nil {
		snapshot = req.StealthConfig
	} else if len(req.FSMConfig) > 0 {
		var err error
		snapshot, err = snapshotFromFSMConfig(req.FSMConfig)
		if err != nil {
			s.respondMLError(w, "parse_error", fmt.Sprintf("Failed to parse fsm_config: %v", err))
			return
		}
	}

	// Fast mode: synthetic evaluation without browser
	if req.FastMode && snapshot != nil {
		engineName := req.EngineName
		if engineName == "" {
			engineName = "chromium"
		}
		s.logger.Debug("ML fast evaluation", "engine", engineName)

		resp, err := s.handleMLEvaluateFast(snapshot, engineName)
		if err != nil {
			s.respondMLError(w, "fast_eval_error", fmt.Sprintf("Fast evaluation failed: %v", err))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			s.logger.Error("Failed to encode ML Evaluation Response", "error", err)
		}
		return
	}

	// Full browser evaluation (original path)
	if req.TargetURL == "" {
		req.TargetURL = "http://localhost:8080/api/ml/trap"
	}

	traceID := fmt.Sprintf("ml_eval_%d", time.Now().UnixNano())

	// Build stealth config for the browser client
	cfg := stealth.DefaultConfig()
	if snapshot != nil {
		cfg.Stealth = &cstealth.StealthConfig{
			Enabled:         true,
			RemoveWebDriver: snapshot.RemoveWebDriver,
			CanvasNoise:     snapshot.CanvasNoise,
			WebGLSpoof:      snapshot.WebGLSpoof,
			ClientHints:     snapshot.ClientHints,
			FakeScreen:      snapshot.FakeScreen,
			FakeTimezone:    snapshot.FakeTimezone,
			RandomUserAgent: snapshot.RandomUA,
			HardwareSync:    snapshot.HardwareSync,
			NetworkSync:     snapshot.NetworkSync,
			PluginsSync:     snapshot.PluginsSync,
			GeometrySync:    snapshot.GeometrySync,
			VideoSync:       snapshot.VideoSync,
			PermissionsSync: snapshot.PermissionsSync,
			TimezoneSync:    snapshot.TimezoneSync,
		}
	} else if len(req.FSMConfig) > 0 {
		// Legacy: try to decode directly into StealthConfig
		var sc cstealth.StealthConfig
		if err := json.Unmarshal(req.FSMConfig, &sc); err == nil {
			cfg.Stealth = &sc
		}
	}

	client, err := stealth.NewAdaptiveWithConfig(cfg)
	if err != nil {
		s.respondMLError(w, traceID, fmt.Sprintf("Failed to initialize Chrome Client: %v", err))
		return
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s.logger.Debug("ML Agent initiating evaluation sprint", "trace_id", traceID)
	_, _ = client.Navigate(ctx, req.TargetURL)

	time.Sleep(500 * time.Millisecond)

	allDetections := s.stealthServer.GetDetections()
	s.logger.Info("Total WAF Detections in Memory", "count", len(allDetections))
	if len(allDetections) == 0 {
		s.respondMLError(w, traceID, "Evaluation failed: WAF Detector registered 0 traces")
		return
	}
	latestDetection := allDetections[len(allDetections)-1]

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

	for _, vec := range latestDetection.Vectors {
		for _, ind := range vec.Indicators {
			if ind == "captcha_challenge_issued" {
				resp.CaptchaPresented = true
			}
		}
	}

	allChallenges := s.stealthServer.CaptchaShield.GetActiveChallenges()
	if len(allChallenges) > 0 {
		latestChallenge := allChallenges[len(allChallenges)-1]
		resp.CaptchaPresented = true
		resp.CaptchaType = latestChallenge.Type
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

func (s *EnhancedServer) respondMLError(w http.ResponseWriter, traceID, errMsg string) {
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
