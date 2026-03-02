package lab

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/stealth/brwslab/brws/adversarial"
)

// CaptchaCatalogueEntry represents an entry in the CAPTCHA catalogue.
type CaptchaCatalogueEntry struct {
	Type        string   `json:"type"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Example     string   `json:"example"`
	Metrics     []string `json:"metrics"`
}

// CaptchaGenerateRequest represents a request to generate a CAPTCHA.
type CaptchaGenerateRequest struct {
	Type   string `json:"type"`
	Config any    `json:"config"`
}

// CaptchaGenerateResponse represents the response for a CAPTCHA generation request.
type CaptchaGenerateResponse struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Challenge   any                    `json:"challenge"`
	Metrics     map[string]interface{} `json:"metrics"`
	GeneratedAt int64                  `json:"generated_at"`
	ExpiresAt   int64                  `json:"expires_at"`
	SessionID   string                 `json:"session_id"`
}

// CaptchaSolveRequest represents a request to solve a CAPTCHA.
type CaptchaSolveRequest struct {
	ChallengeID string                `json:"challenge_id"`
	Solution    string                `json:"solution"`
	Events      []CaptchaEventCapture `json:"events"`
	Timing      CaptchaTimingCapture  `json:"timing"`
	Browser     BrowserMetricsCapture `json:"browser"`
}

// CaptchaEventCapture represents a CAPTCHA event capture.
type CaptchaEventCapture struct {
	Type      string  `json:"type"`
	Timestamp int64   `json:"timestamp"`
	X         float64 `json:"x"`
	Y         float64 `json:"y"`
	Key       string  `json:"key"`
	Delta     float64 `json:"delta"`
}

// CaptchaTimingCapture represents timing information for CAPTCHA events.
type CaptchaTimingCapture struct {
	LoadTimeMs        int64 `json:"load_time_ms"`
	FirstPaintMs      int64 `json:"first_paint_ms"`
	FirstContentfulMs int64 `json:"first_contentful_ms"`
	InteractionMs     int64 `json:"interaction_ms"`
	SubmitTimeMs      int64 `json:"submit_time_ms"`
	TotalTimeMs       int64 `json:"total_time_ms"`
}

// BrowserMetricsCapture holds browser-level metrics captured during CAPTCHA interaction.
type BrowserMetricsCapture struct {
	UserAgent           string  `json:"user_agent"`
	Platform            string  `json:"platform"`
	HardwareConcurrency int     `json:"hardware_concurrency"`
	DeviceMemory        float64 `json:"device_memory"`
	ScreenWidth         int     `json:"screen_width"`
	ScreenHeight        int     `json:"screen_height"`
	TouchPoints         int     `json:"touch_points"`
	WebGLVendor         string  `json:"webgl_vendor"`
	WebGLRenderer       string  `json:"webgl_renderer"`
	CanvasHash          string  `json:"canvas_hash"`
	Timezone            string  `json:"timezone"`
	Language            string  `json:"language"`
	CookiesEnabled      bool    `json:"cookies_enabled"`
	DoNotTrack          string  `json:"do_not_track"`
}

// CaptchaSolveResponse represents the response after solving a CAPTCHA.
type CaptchaSolveResponse struct {
	Solved       bool                       `json:"solved"`
	SolveTimeMs  int64                      `json:"solve_time_ms"`
	AttemptCount int                        `json:"attempt_count"`
	Events       []adversarial.CaptchaEvent `json:"events"`
	Metrics      map[string]interface{}     `json:"metrics"`
	BotScore     float64                    `json:"bot_score"`
	MLFeatures   map[string]float64         `json:"ml_features"`
}

// CaptchaTraceResponse represents the response for a CAPTCHA trace query.
type CaptchaTraceResponse struct {
	ChallengeID string                     `json:"challenge_id"`
	SessionID   string                     `json:"session_id"`
	Type        string                     `json:"type"`
	CreatedAt   int64                      `json:"created_at"`
	StartedAt   int64                      `json:"started_at"`
	Events      []adversarial.CaptchaEvent `json:"events"`
	Metrics     map[string]interface{}     `json:"metrics"`
	BotScore    float64                    `json:"bot_score"`
	IsBot       bool                       `json:"is_bot"`
}

// GlobalMetricsResponse represents the global CAPTCHA metrics response.
type GlobalMetricsResponse struct {
	TotalChallenges int                     `json:"total_challenges"`
	SuccessRate     float64                 `json:"success_rate"`
	AvgSolveTimeMs  int64                   `json:"avg_solve_time_ms"`
	ByType          map[string]TypeMetrics  `json:"by_type"`
	MLFeaturesStats map[string]FeatureStats `json:"ml_features_stats"`
}

// TypeMetrics holds metrics for a specific CAPTCHA type.
type TypeMetrics struct {
	Count     int     `json:"count"`
	Successes int     `json:"successes"`
	Failures  int     `json:"failures"`
	AvgTimeMs int64   `json:"avg_time_ms"`
	BotRate   float64 `json:"bot_rate"`
}

// FeatureStats holds statistical information about an ML feature.
type FeatureStats struct {
	Mean   float64 `json:"mean"`
	StdDev float64 `json:"std_dev"`
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
}

func (s *EnhancedServer) handleCaptchaCatalogue(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	catalogue := []CaptchaCatalogueEntry{
		{
			Type:        "text",
			Name:        "Text CAPTCHA",
			Description: "Classic text-based CAPTCHA with distorted characters",
			Example:     "A3B7XY",
			Metrics:     []string{"solve_time_ms", "attempt_count", "keystroke_timing"},
		},
		{
			Type:        "math",
			Name:        "Math CAPTCHA",
			Description: "Simple arithmetic problem",
			Example:     "7 + 5 = ?",
			Metrics:     []string{"solve_time_ms", "keystroke_timing", "mouse_movements"},
		},
		{
			Type:        "image",
			Name:        "Image Selection",
			Description: "Select images matching a category",
			Example:     "Select all images with traffic lights",
			Metrics:     []string{"click_latency", "selection_pattern", "scroll_behavior"},
		},
		{
			Type:        "slider",
			Name:        "Slider CAPTCHA",
			Description: "Drag slider to complete a puzzle",
			Example:     "Slide to complete the puzzle",
			Metrics:     []string{"drag_velocity", "pause_pattern", "completion_time"},
		},
		{
			Type:        "recaptcha_v2",
			Name:        "reCAPTCHA v2",
			Description: "Google reCAPTCHA v2 image challenge",
			Example:     "Select all images matching: street signs",
			Metrics:     []string{"image_selection_time", "confidence_score", "api_latency"},
		},
		{
			Type:        "hcaptcha",
			Name:        "hCaptcha",
			Description: "hCaptcha image challenge",
			Example:     "Select all images with: cars",
			Metrics:     []string{"selection_pattern", "api_response_time", "user_agent"},
		},
		{
			Type:        "turnstile",
			Name:        "Cloudflare Turnstile",
			Description: "Invisible challenge that checks browser behavior",
			Example:     "Invisible JS challenge",
			Metrics:     []string{"execution_time", "js_timing", "mouse_events"},
		},
		{
			Type:        "distorted",
			Name:        "Distorted Text",
			Description: "Highly distorted text challenge",
			Example:     "X7K9M2Q",
			Metrics:     []string{"ocr_attempts", "keystroke_durations", "corrections"},
		},
		{
			Type:        "audio",
			Name:        "Audio CAPTCHA",
			Description: "Audio challenge for accessibility",
			Example:     "Enter the numbers you hear",
			Metrics:     []string{"audio_latency", "playback_position", "input_timing"},
		},
		{
			Type:        "behavioral",
			Name:        "Behavioral",
			Description: "Implicit behavioral analysis",
			Example:     "Passive browser fingerprinting",
			Metrics:     []string{"mouse_velocity", "scroll_pattern", "keystroke_dynamics"},
		},
		{
			Type:        "webgl",
			Name:        "3D WebGL",
			Description: "3D object selection challenge",
			Example:     "Click on the sphere",
			Metrics:     []string{"3d_interaction_time", "camera_movement", "object_selection"},
		},
	}
	//nolint:errchkjson // Dynamic response
	_ = json.NewEncoder(w).Encode(catalogue)
}

func (s *EnhancedServer) handleCaptchaGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CaptchaGenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	now := time.Now()
	sessionID := fmt.Sprintf("session_%d", now.UnixNano())

	challenge, err := s.stealthServer.CaptchaShield.CreateChallenge(sessionID, nil, req.Type)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	resp := CaptchaGenerateResponse{
		ID:          challenge.ID,
		Type:        challenge.Type,
		Challenge:   challenge,
		Metrics:     map[string]interface{}{},
		GeneratedAt: now.UnixMilli(),
		ExpiresAt:   challenge.ExpiresAt.UnixMilli(),
		SessionID:   sessionID,
	}

	w.Header().Set("Content-Type", "application/json")
	//nolint:errchkjson // Dynamic response
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *EnhancedServer) handleCaptchaRandom(w http.ResponseWriter, r *http.Request) {
	requestedType := r.URL.Query().Get("type")
	validTypes := []string{"text", "math", "hcaptcha", "slider", "image_select", "turnstile", "webgl"}

	var captchaType string
	if requestedType != "" {
		valid := false
		for _, t := range validTypes {
			if t == requestedType {
				valid = true
				break
			}
		}
		if valid {
			captchaType = requestedType
		} else {
			// fallback
			randomTypes := []string{"text", "math", "slider"}
			captchaType = randomTypes[time.Now().UnixNano()%int64(len(randomTypes))]
		}
	} else {
		// Only randomize among visual/interactive types mostly
		randomTypes := []string{"text", "math", "slider"}
		captchaType = randomTypes[time.Now().UnixNano()%int64(len(randomTypes))]
	}

	id := fmt.Sprintf("train_%d", time.Now().UnixNano())
	challenge, err := s.stealthServer.CaptchaShield.CreateChallenge(id, nil, captchaType)
	if err != nil {
		http.Error(w, `{"error":"failed to generate challenge"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	//nolint:errchkjson // Dynamic response
	_ = json.NewEncoder(w).Encode(challenge)
}

func (s *EnhancedServer) handleCaptchaSolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CaptchaSolveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	startTime := time.Now()

	for _, event := range req.Events {
		s.stealthServer.Tracer.AddEvent(req.ChallengeID, adversarial.CaptchaEvent{
			Type:      event.Type,
			Timestamp: event.Timestamp,
			X:         event.X,
			Y:         event.Y,
			Key:       event.Key,
			Delta:     event.Delta,
		})
	}

	solved, metrics := s.stealthServer.CaptchaShield.ValidateChallenge(req.ChallengeID, req.Solution)

	trace, _ := s.stealthServer.Tracer.GetTrace(req.ChallengeID)
	var botScore float64
	if trace != nil {
		botScore = s.stealthServer.Tracer.CalculateBotScore(trace)
	}

	mlFeatures := map[string]float64{
		"keystroke_duration": 0,
		"mouse_velocity":     0,
		"scroll_smoothness":  0,
		"timing_variance":    0,
	}

	if trace != nil && trace.Metrics != nil {
		mlFeatures["mouse_velocity"] = trace.Metrics.MouseVelocity
		mlFeatures["typing_speed"] = trace.Metrics.TypingSpeed
		mlFeatures["event_intervals"] = trace.Metrics.EventIntervals
		mlFeatures["straightness"] = trace.Metrics.Straightness
		mlFeatures["long_pauses"] = float64(trace.Metrics.LongPauses)
		mlFeatures["total_events"] = float64(trace.Metrics.TotalEvents)
	}

	resp := CaptchaSolveResponse{
		Solved:       solved,
		SolveTimeMs:  time.Since(startTime).Milliseconds(),
		AttemptCount: metrics.AttemptCount,
		Events:       []adversarial.CaptchaEvent{},
		Metrics:      map[string]interface{}{},
		BotScore:     botScore,
		MLFeatures:   mlFeatures,
	}

	if trace != nil {
		resp.Events = trace.Events
	}

	w.Header().Set("Content-Type", "application/json")
	//nolint:errchkjson // Dynamic response
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *EnhancedServer) handleCaptchaTrain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID       string                     `json:"id"`
		Type     string                     `json:"type"`
		Solved   bool                       `json:"solved"`
		BotScore float64                    `json:"bot_score"`
		Events   []adversarial.CaptchaEvent `json:"events"`
		Metrics  *adversarial.TraceMetrics  `json:"metrics"`
		IsExpert bool                       `json:"is_expert"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	// Record as an expert track if IsExpert is true
	label := "bot"
	if req.IsExpert {
		label = "expert"
	} else if req.Solved && req.BotScore < 0.3 {
		label = "human"
	}

	// Use an internal method to record the training sample
	// For now we'll just log it
	log.Printf("RECORDING TRAINING SAMPLE ID=%s TYPE=%s LABEL=%s EVENTS=%d", req.ID, req.Type, label, len(req.Events))

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"recorded"}`))
}

func (s *EnhancedServer) handleCaptchaTrace(w http.ResponseWriter, r *http.Request) {
	challengeID := r.URL.Query().Get("challenge_id")
	if challengeID == "" {
		http.Error(w, `{"error":"challenge_id required"}`, http.StatusBadRequest)
		return
	}

	trace, ok := s.stealthServer.Tracer.GetTrace(challengeID)
	if !ok {
		http.Error(w, `{"error":"trace not found"}`, http.StatusNotFound)
		return
	}

	botScore := s.stealthServer.Tracer.CalculateBotScore(trace)

	resp := CaptchaTraceResponse{
		ChallengeID: trace.ChallengeID,
		SessionID:   trace.SessionID,
		Type:        trace.Type,
		CreatedAt:   trace.CreatedAt.UnixMilli(),
		StartedAt:   trace.StartedAt.UnixMilli(),
		Events:      trace.Events,
		Metrics: map[string]interface{}{
			"total_events":    trace.Metrics.TotalEvents,
			"mouse_movements": trace.Metrics.MouseMovements,
			"keystrokes":      trace.Metrics.Keystrokes,
			"scroll_events":   trace.Metrics.ScrollEvents,
			"clicks":          trace.Metrics.Clicks,
			"mouse_velocity":  trace.Metrics.MouseVelocity,
			"typing_speed":    trace.Metrics.TypingSpeed,
			"event_intervals": trace.Metrics.EventIntervals,
			"straightness":    trace.Metrics.Straightness,
			"pauses":          trace.Metrics.Pauses,
			"long_pauses":     trace.Metrics.LongPauses,
		},
		BotScore: botScore,
		IsBot:    botScore > 0.5,
	}

	w.Header().Set("Content-Type", "application/json")
	//nolint:errchkjson // Dynamic response
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *EnhancedServer) handleCaptchaEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ChallengeID string                     `json:"challenge_id"`
		Events      []adversarial.CaptchaEvent `json:"events"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	for _, event := range req.Events {
		s.stealthServer.Tracer.AddEvent(req.ChallengeID, event)
	}

	w.Header().Set("Content-Type", "application/json")
	//nolint:errchkjson // Dynamic response
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "recorded"})
}

func (s *EnhancedServer) handleCaptchaMetrics(w http.ResponseWriter, r *http.Request) {
	challenges := s.stealthServer.CaptchaShield.GetActiveChallenges()

	total := len(challenges)
	successes := 0
	var totalTime int64

	byType := make(map[string]TypeMetrics)

	for _, ch := range challenges {
		if ch.Solved {
			successes++
		}
		totalTime += ch.Metrics.SolveTimeMs

		tm := byType[ch.Type]
		tm.Count++
		if ch.Solved {
			tm.Successes++
		} else {
			tm.Failures++
		}
		if ch.Metrics.SolveTimeMs > 0 {
			tm.AvgTimeMs = (tm.AvgTimeMs + ch.Metrics.SolveTimeMs) / int64(tm.Count)
		}
		byType[ch.Type] = tm
	}

	resp := GlobalMetricsResponse{
		TotalChallenges: total,
		SuccessRate:     float64(successes) / float64(total+1),
		AvgSolveTimeMs:  totalTime / int64(total+1),
		ByType:          byType,
		MLFeaturesStats: map[string]FeatureStats{
			"mouse_velocity":  {Mean: 150, StdDev: 80, Min: 10, Max: 2000},
			"typing_speed":    {Mean: 120, StdDev: 40, Min: 20, Max: 500},
			"event_intervals": {Mean: 85, StdDev: 50, Min: 5, Max: 1000},
			"straightness":    {Mean: 0.85, StdDev: 0.15, Min: 0.1, Max: 1.0},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	//nolint:errchkjson // Dynamic response
	_ = json.NewEncoder(w).Encode(resp)
}
