package cloudflare

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/skunkworq/stealth/brws/core/detection"
	captchatraining "github.com/skunkworq/stealth/brws/research/captcha/training"
	"github.com/skunkworq/stealth/brws/research/evasion/recaptcha"
)

// AdvancedStealthServer combines a StealthDetector with a TestServer to provide
// HTTP request handling with integrated stealth detection capabilities.
type AdvancedStealthServer struct {
	*detection.StealthDetector

	Server               *TestServer
	CaptchaShield        *CaptchaShield
	Tracer               *captchatraining.CaptchaTracer
	RecaptchaWidget      *recaptcha.ReCaptchaWidget
	CloudflareChallenger *CloudflareChallenger

	// CaptchaMode controls which captcha flow HandleRequest uses for suspicious
	// requests (score 0.20–0.60). Values: "recaptcha_v2" (default), "inline".
	CaptchaMode string

	// Session tokens for post-captcha-solve access
	captchaSecret []byte
	solvedTokens  map[string]time.Time // token -> expiry
	tokenMu       sync.RWMutex

	// V3 assessment ring buffer
	v3Assessments   []*recaptcha.V3AssessmentRecord
	v3AssessmentsMu sync.RWMutex
	v3MaxRecords    int
	OnV3Assessment  func(record *recaptcha.V3AssessmentRecord) // callback for WebSocket broadcast
}

// NewAdvancedStealthServer creates and initializes a new AdvancedStealthServer
// with default detector and test server configurations.
func NewAdvancedStealthServer() *AdvancedStealthServer {
	detector := detection.NewStealthDetector()
	testServer := NewTestServer()
	tracer := captchatraining.NewCaptchaTracer()

	// Generate a random secret for HMAC tokens
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(time.Now().UnixNano()>>uint(i*8)) ^ byte(i*37+13) //nolint:gosec,mnd
	}

	shield := NewCaptchaShield(nil, nil, tracer)
	widget := recaptcha.NewReCaptchaWidget(shield)
	cfChallenger := NewCloudflareChallenger(tracer, nil)

	as := &AdvancedStealthServer{
		StealthDetector:      detector,
		Server:               testServer,
		CaptchaShield:        shield,
		Tracer:               tracer,
		RecaptchaWidget:      widget,
		CloudflareChallenger: cfChallenger,
		CaptchaMode:          "recaptcha_v2",
		captchaSecret:        secret,
		solvedTokens:         make(map[string]time.Time),
		v3Assessments:        make([]*recaptcha.V3AssessmentRecord, 0, 100),
		v3MaxRecords:         100,
	}

	// Bridge reCAPTCHA v2 tokens into the server's solvedTokens so that
	// HandleRequest's validateCaptchaToken recognizes v2-issued tokens.
	widget.SetTokenCallback(func(token string, expiry time.Time) {
		as.tokenMu.Lock()
		as.solvedTokens[token] = expiry
		as.tokenMu.Unlock()
	})

	return as
}

// generateCaptchaToken creates an HMAC-SHA256 session token for post-solve access.
func (as *AdvancedStealthServer) generateCaptchaToken(challengeID string) (string, string) {
	expiry := time.Now().Add(5 * time.Minute)
	data := fmt.Sprintf("%s|%d", challengeID, expiry.UnixMilli())

	mac := hmac.New(sha256.New, as.captchaSecret)
	mac.Write([]byte(data))
	token := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	as.tokenMu.Lock()
	as.solvedTokens[token] = expiry
	as.tokenMu.Unlock()

	return token, expiry.Format(time.RFC3339)
}

// validateCaptchaToken checks if a token is valid and not expired.
func (as *AdvancedStealthServer) validateCaptchaToken(token string) bool {
	if token == "" {
		return false
	}
	as.tokenMu.RLock()
	expiry, ok := as.solvedTokens[token]
	as.tokenMu.RUnlock()

	if !ok {
		return false
	}
	return time.Now().Before(expiry)
}

// storeV3Assessment appends a record to the ring buffer, evicting the oldest if at capacity.
func (as *AdvancedStealthServer) storeV3Assessment(record *recaptcha.V3AssessmentRecord) {
	as.v3AssessmentsMu.Lock()
	defer as.v3AssessmentsMu.Unlock()
	if len(as.v3Assessments) >= as.v3MaxRecords {
		as.v3Assessments = as.v3Assessments[1:]
	}
	as.v3Assessments = append(as.v3Assessments, record)
}

// GetV3Assessments returns a copy of the v3 assessment ring buffer.
func (as *AdvancedStealthServer) GetV3Assessments() []*recaptcha.V3AssessmentRecord {
	as.v3AssessmentsMu.RLock()
	defer as.v3AssessmentsMu.RUnlock()
	out := make([]*recaptcha.V3AssessmentRecord, len(as.v3Assessments))
	copy(out, as.v3Assessments)
	return out
}

// selectCaptchaTypeFromScore selects the CAPTCHA type based on the WAF detection score.
func selectCaptchaTypeFromScore(score float64) string {
	switch {
	case score >= 0.80:
		return "cloudflare_managed"
	case score >= 0.60:
		return "cloudflare_js"
	case score >= 0.35:
		return "hcaptcha"
	default:
		return "text"
	}
}

// HandleCaptchaVerify verifies a submitted CAPTCHA solution.
func (as *AdvancedStealthServer) HandleCaptchaVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ChallengeID string         `json:"challenge_id"`
		Solution    string         `json:"solution"`
		Answer      string         `json:"answer"` // Keep for backward compatibility
		IsExpert    bool           `json:"is_expert"`
		Events      []CaptchaEvent `json:"events"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	// Support both naming conventions
	solution := req.Solution
	if solution == "" {
		solution = req.Answer
	}

	// Add events to tracer if provided
	if len(req.Events) > 0 {
		for _, ev := range req.Events {
			_ = as.CaptchaShield.RecordEvent(req.ChallengeID, ev)
		}
	}

	solved, metrics := as.CaptchaShield.ValidateChallenge(req.ChallengeID, solution)

	botScore := 0.0
	var behavioralBreakdown map[string]interface{}
	trace, _ := as.CaptchaShield.tracer.GetTrace(req.ChallengeID)
	if trace != nil {
		var analysisResult *detection.VectorResult
		botScore, analysisResult = as.CaptchaShield.tracer.CalculateBotScoreDetailed(trace)

		// Build behavioral breakdown for observability
		behavioralBreakdown = map[string]interface{}{
			"analyzer_score":  analysisResult.Score,
			"checks_detected": analysisResult.Detected,
		}
		for _, ind := range analysisResult.Indicators {
			behavioralBreakdown[ind.Check] = ind.Value
		}

		log.Printf("CAPTCHA_SOLVE_METRICS challenge_id=%s correct=%v bot_score=%.2f solve_time_ms=%d indicators=%d",
			req.ChallengeID, solved, botScore, metrics.SolveTimeMs, len(analysisResult.Indicators))
		for _, ind := range analysisResult.Indicators {
			log.Printf("  %s=%s (weight=%.2f)", ind.Check, ind.Value, ind.Weight)
		}
	}

	mlFeatures := map[string]float64{
		"mouse_velocity": 0,
		"typing_speed":   0,
	}
	if trace != nil && trace.Metrics != nil {
		mlFeatures["mouse_velocity"] = trace.Metrics.MouseVelocity
		mlFeatures["typing_speed"] = trace.Metrics.TypingSpeed
	}

	// If the answer is correct but the behavioral bot score is too high, reject
	if solved && botScore >= 0.5 {
		solved = false
	}

	w.Header().Set("Content-Type", "application/json")

	// Generate session token on successful solve
	var captchaToken string
	var tokenExpiresAt string
	if solved && as.captchaSecret != nil {
		captchaToken, tokenExpiresAt = as.generateCaptchaToken(req.ChallengeID)
	}

	// For expert training tracks, we always return 200 even if solve failed
	// so the UI can show the analysis.
	if req.IsExpert {
		w.WriteHeader(http.StatusOK)
		//nolint:errchkjson // Dynamic response requires interface{}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"solved":               solved,
			"message":              "Expert track recorded",
			"solve_time_ms":        metrics.SolveTimeMs,
			"attempts":             metrics.AttemptCount,
			"bot_score":            botScore,
			"ml_features":          mlFeatures,
			"behavioral_breakdown": behavioralBreakdown,
		})
		return
	}

	if solved {
		resp := map[string]interface{}{
			"solved":        true,
			"message":       "CAPTCHA solved successfully",
			"solve_time_ms": metrics.SolveTimeMs,
			"attempts":      metrics.AttemptCount,
			"bot_score":     botScore,
		}
		if captchaToken != "" {
			resp["captcha_token"] = captchaToken
			resp["token_expires_at"] = tokenExpiresAt
		}
		if behavioralBreakdown != nil {
			resp["behavioral_breakdown"] = behavioralBreakdown
		}
		w.WriteHeader(http.StatusOK)
		//nolint:errchkjson // Dynamic response requires interface{}
		_ = json.NewEncoder(w).Encode(resp)
	} else {
		resp := map[string]interface{}{
			"solved":  false,
			"message": "Incorrect CAPTCHA solution",
		}
		if behavioralBreakdown != nil {
			resp["bot_score"] = botScore
			resp["behavioral_breakdown"] = behavioralBreakdown
		}
		w.WriteHeader(http.StatusForbidden)
		//nolint:errchkjson // Dynamic response requires interface{}
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// HandleRequest processes an HTTP request through stealth detection and returns
// the detection results as JSON with appropriate HTTP status codes.
func (as *AdvancedStealthServer) HandleRequest(w http.ResponseWriter, r *http.Request) {
	var tlsConn *tls.ConnectionState
	if r.TLS != nil {
		tlsConn = r.TLS
	}

	result := as.AnalyzeRequest(r, tlsConn)

	// Check for valid captcha session token — reduce effective score
	captchaToken := r.Header.Get("X-Captcha-Token")
	if as.validateCaptchaToken(captchaToken) {
		result.Score -= 0.15
		if result.Score < 0 {
			result.Score = 0
		}
		result.IsBot = result.Score > 0.60
	}

	// Add detection to test server's records
	as.Server.mu.Lock()
	record := DetectionRecord{
		Timestamp:  result.Timestamp,
		RequestID:  result.RequestID,
		IsBot:      result.IsBot,
		Score:      result.Score,
		Indicators: make([]detection.Indicator, 0),
	}
	for _, ind := range result.Indicators {
		record.Indicators = append(record.Indicators, detection.Indicator{
			Category: ind.Vector,
			Name:     ind.Name,
			Severity: ind.Severity,
			Message:  ind.Message,
		})
	}
	as.Server.Detections = append(as.Server.Detections, record)
	as.Server.mu.Unlock()

	// Return detection results
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Bot-Score", fmt.Sprintf("%.2f", result.Score))
	w.Header().Set("X-Is-Bot", fmt.Sprintf("%v", result.IsBot))
	w.Header().Set("X-Is-Stealth", fmt.Sprintf("%v", result.IsStealth))

	response := map[string]interface{}{
		"request_id": result.RequestID,
		"is_bot":     result.IsBot,
		"is_stealth": result.IsStealth,
		"score":      result.Score,
		"confidence": result.Confidence,
		"vectors":    result.Vectors,
		"indicators": result.Indicators,
	}

	// Phase 17: Graduated CAPTCHA response based on bot score
	const captchaThresholdLow = 0.20
	const captchaThresholdHigh = 0.60

	if result.Score > captchaThresholdHigh && result.IsBot {
		// Hard block — confirmed bot with very high score
		response["detection_type"] = "blocked"
		response["message"] = "Bot detected"
		w.Header().Set("X-Datadome", "1")
		w.WriteHeader(http.StatusForbidden)
	} else if result.Score > captchaThresholdLow {
		// Suspicious — issue CAPTCHA challenge. Mode selects the flow.
		captchaMode := as.CaptchaMode
		if captchaMode == "" {
			captchaMode = "recaptcha_v2"
		}

		switch captchaMode {
		case "recaptcha_v2":
			// Redirect client to the reCAPTCHA v2 widget flow (init → checkbox → verify).
			// No inline captcha image; the client follows the 5-step v2 API.
			response["detection_type"] = "recaptcha_v2"
			response["init_url"] = "/api/recaptcha/init"
			response["site_key"] = as.RecaptchaWidget.GetSiteKey()
			response["message"] = "reCAPTCHA v2 challenge required"
			log.Printf("RECAPTCHA_V2_REDIRECT score=%.2f request_id=%s", result.Score, result.RequestID)
			w.Header().Set("X-Captcha-Required", "1")
			w.Header().Set("X-Captcha-Type", "recaptcha-v2")
			w.WriteHeader(http.StatusOK)

		default: // "inline" — preserve the original CreateChallenge inline behavior
			captchaType := selectCaptchaTypeFromScore(result.Score)
			cfChallenge, err := as.CaptchaShield.CreateChallenge(result.RequestID, nil, captchaType)
			if err != nil {
				log.Printf("CAPTCHA_GENERATION_FAILED: %v", err)
				w.WriteHeader(http.StatusOK)
			} else {
				response["detection_type"] = "captcha"
				challengeData := make(map[string]interface{})
				for k, v := range cfChallenge.Challenge {
					if k != "text" {
						challengeData[k] = v
					}
				}
				response["captcha"] = map[string]interface{}{
					"challenge_id":   cfChallenge.ID,
					"type":           cfChallenge.Type,
					"captcha_id":     cfChallenge.CaptchaID,
					"challenge_data": challengeData,
				}
				response["message"] = "CAPTCHA challenge required"
				log.Printf("CAPTCHA_CHALLENGE_ISSUED type=%s challenge_id=%s score=%.2f", cfChallenge.Type, cfChallenge.ID, result.Score)
				w.Header().Set("X-Captcha-Required", "1")
				w.Header().Set("X-Captcha-Type", cfChallenge.Type)
				w.Header().Set("X-Captcha-Id", cfChallenge.ID)
				w.WriteHeader(http.StatusOK)
			}
		}
	} else {
		// Clean pass
		w.WriteHeader(http.StatusOK)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, `{"error": "encode failed"}`, http.StatusInternalServerError)
	}
}

