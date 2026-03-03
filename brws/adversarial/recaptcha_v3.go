package adversarial

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/skunkworq/stealth/brws/observability"
)

// BehavioralCheckResult captures one behavioral analysis check outcome.
type BehavioralCheckResult struct {
	Check   string  `json:"check"`
	Message string  `json:"message"`
	Weight  float64 `json:"weight"`
	Field   string  `json:"field"`
	Value   string  `json:"value"`
}

// V3AssessmentRecord captures the full analysis data from a v3 assessment.
type V3AssessmentRecord struct {
	ID                   string                  `json:"id"`
	Timestamp            time.Time               `json:"timestamp"`
	Action               string                  `json:"action"`
	V3Score              float64                 `json:"v3_score"`
	DetectionScore       float64                 `json:"detection_score"`
	BehavioralScore      float64                 `json:"behavioral_score"`
	CombinedBotScore     float64                 `json:"combined_bot_score"`
	EventCount           int                     `json:"event_count"`
	Hostname             string                  `json:"hostname"`
	Vectors              []DetectionVector       `json:"vectors"`
	Indicators           []StealthIndicator      `json:"indicators"`
	BehavioralChecks     []BehavioralCheckResult `json:"behavioral_checks"`
	BehavioralEventBreakdown map[string]int      `json:"behavioral_event_breakdown"`
}

// ReCaptchaV3Response mirrors Google's reCAPTCHA v3 siteverify response.
type ReCaptchaV3Response struct {
	Success     bool    `json:"success"`
	Score       float64 `json:"score"`        // 0.0 (bot) – 1.0 (human)
	Action      string  `json:"action"`       // action name from the client
	ChallengeTS string  `json:"challenge_ts"` // ISO timestamp
	Hostname    string  `json:"hostname"`
}

// reCaptchaV3Request is the incoming assessment request.
type reCaptchaV3Request struct {
	Action string         `json:"action"`
	Events []CaptchaEvent `json:"events"`
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
	detection := as.AnalyzeRequest(r, r.TLS)
	detectionScore := detection.Score
	if detectionScore > 1.0 {
		detectionScore = 1.0
	}

	// Step 2: If behavioral events are provided, score them with the CaptchaTracer
	// quick heuristics. The full BehavioralAnalyzer (checks 1-24) is for HTTP
	// request-level detection; captcha events use lighter scoring.
	// No events = very suspicious (real browsers always generate behavioral data
	// when a v3 script is embedded), so default to a high bot score.
	behavScore := 0.85 // no behavioral data = strongly bot-like
	var behavChecks []BehavioralCheckResult
	eventBreakdown := map[string]int{"total": len(req.Events)}
	if len(req.Events) > 0 {
		enhanced := eventsToEnhanced(req.Events)
		tracer := NewCaptchaTracer()
		trace := tracer.CreateTrace("v3-assess", "v3-session", "v3")
		for _, ev := range req.Events {
			tracer.AddEvent(trace.ChallengeID, ev)
		}
		traceResult, _ := tracer.GetTrace(trace.ChallengeID)
		if traceResult != nil {
			behavScore = tracer.CalculateBotScore(traceResult)
		}
		eventBreakdown["mouse"] = len(enhanced.MouseTimestamps)
		eventBreakdown["typing"] = len(enhanced.TypingTimestamps)
		eventBreakdown["scroll"] = len(enhanced.ScrollTimestamps)
		eventBreakdown["click"] = len(enhanced.ClickTimestamps)
		_ = behavChecks // diagnostics available via CalculateBotScoreDetailed if needed
	}

	// Step 3: Combine scores
	// detectionScore and behavScore are both bot scores (higher = more bot-like)
	const detectionWeight = 0.6
	const behavioralWeight = 0.4
	combinedBotScore := detectionScore*detectionWeight + behavScore*behavioralWeight

	// Clamp
	if combinedBotScore > 1.0 {
		combinedBotScore = 1.0
	}
	if combinedBotScore < 0.0 {
		combinedBotScore = 0.0
	}

	// Step 4: Invert to match Google's convention (1.0 = human, 0.0 = bot)
	v3Score := 1.0 - combinedBotScore

	// Step 5: Return response
	action := req.Action
	if action == "" {
		action = "assess"
	}

	// Step 6: Build assessment record, store, and emit observability metrics
	record := &V3AssessmentRecord{
		ID:                       generateRequestID(),
		Timestamp:                time.Now(),
		Action:                   action,
		V3Score:                  v3Score,
		DetectionScore:           detectionScore,
		BehavioralScore:          behavScore,
		CombinedBotScore:         combinedBotScore,
		EventCount:               len(req.Events),
		Hostname:                 r.Host,
		Vectors:                  detection.Vectors,
		Indicators:               detection.Indicators,
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
	observability.GlobalCollector().RecordHistogram("recaptcha_v3_detection_score", detectionScore, nil)
	observability.GlobalCollector().RecordHistogram("recaptcha_v3_behavioral_score", behavScore, nil)

	resp := ReCaptchaV3Response{
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
