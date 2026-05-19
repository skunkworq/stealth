package cloudflare

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	captchatraining "github.com/skunkworq/stealth/brws/research/captcha/training"
	"github.com/skunkworq/stealth/brws/research/evasion/recaptcha"
	"github.com/skunkworq/stealth/brws/core/observability"
)

// reCaptchaV3Request is the incoming assessment request.
type reCaptchaV3Request struct {
	Action string                     `json:"action"`
	Events []captchatraining.CaptchaEvent `json:"events"`
}

// HandleReCaptchaV3Assess performs invisible risk scoring — no visual challenge.
// It mirrors Google's POST /recaptchav3/api/siteverify:
//  1. Run AnalyzeRequest() on the incoming HTTP request (TLS, headers, navigator)
//  2. If behavioral events are included, run BehavioralAnalyzer
//  3. Combine: combinedBotScore = detection.Score * 0.6 + behavScore * 0.4
//  4. Invert to match Google's convention: v3Score = 1.0 - combinedBotScore
//  5. Return { success, score, action, challenge_ts, hostname }
func (as *AdvancedStealthServer) HandleReCaptchaV3Assess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var req reCaptchaV3Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"invalid request: %s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	// Step 1: Run AnalyzeRequest on the HTTP request itself (TLS, headers, navigator)
	det := as.AnalyzeRequest(r, r.TLS)
	detectionScore := det.Score
	if detectionScore > 1.0 {
		detectionScore = 1.0
	}

	// Step 2: If behavioral events are provided, score them with the CaptchaTracer
	behavScore := 0.85 // no behavioral data = strongly bot-like
	var behavChecks []recaptcha.BehavioralCheckResult
	eventBreakdown := map[string]int{"total": len(req.Events)}
	if len(req.Events) > 0 {
		tracer := captchatraining.NewCaptchaTracer()
		trace := tracer.CreateTrace("v3-assess", "v3-session", "v3")
		for _, ev := range req.Events {
			tracer.AddEvent(trace.ChallengeID, ev)
		}
		traceResult, _ := tracer.GetTrace(trace.ChallengeID)
		if traceResult != nil {
			behavScore = tracer.CalculateBotScore(traceResult)
		}
		_ = behavChecks // diagnostics available via CalculateBotScoreDetailed if needed
	}

	// Step 3: Combine scores
	const detectionWeight = 0.6
	const behavioralWeight = 0.4
	combinedBotScore := detectionScore*detectionWeight + behavScore*behavioralWeight

	if combinedBotScore > 1.0 {
		combinedBotScore = 1.0
	}
	if combinedBotScore < 0.0 {
		combinedBotScore = 0.0
	}

	// Step 4: Invert to match Google's convention
	v3Score := 1.0 - combinedBotScore

	action := req.Action
	if action == "" {
		action = "assess"
	}

	// Step 5: Build assessment record
	record := &recaptcha.V3AssessmentRecord{
		ID:                       fmt.Sprintf("req_%d", time.Now().UnixNano()),
		Timestamp:                time.Now(),
		Action:                   action,
		V3Score:                  v3Score,
		DetectionScore:           detectionScore,
		BehavioralScore:          behavScore,
		CombinedBotScore:         combinedBotScore,
		EventCount:               len(req.Events),
		Hostname:                 r.Host,
		BehavioralChecks:         behavChecks,
		BehavioralEventBreakdown: eventBreakdown,
	}
	as.storeV3Assessment(record)
	if as.OnV3Assessment != nil {
		go as.OnV3Assessment(record)
	}

	// Observability metrics
	observability.IncCounter("recaptcha_v3_total", map[string]string{"action": action})
	observability.GlobalCollector().RecordHistogram("recaptcha_v3_score", v3Score, nil)

	resp := recaptcha.ReCaptchaV3Response{
		Success:     true,
		Score:       v3Score,
		Action:      action,
		ChallengeTS: time.Now().Format(time.RFC3339),
		Hostname:    r.Host,
	}

	w.Header().Set("Content-Type", "application/json")
	//nolint:errchkjson
	_ = json.NewEncoder(w).Encode(resp)
}
