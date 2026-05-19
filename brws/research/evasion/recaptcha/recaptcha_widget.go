package recaptcha

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/skunkworq/stealth/brws/core/detection"
	captchatraining "github.com/skunkworq/stealth/brws/research/captcha/training"
	"github.com/skunkworq/stealth/brws/stealth/captcha"
)

// CaptchaShieldProvider is an interface for the shield used by the widget.
// This avoids a circular import between the recaptcha and cloudflare packages.
type CaptchaShieldProvider interface{}

// ReCaptchaWidget implements a reCAPTCHA v2-like server-side flow:
// checkbox → behavioral check → challenge popup → solve → token.
type ReCaptchaWidget struct {
	shield        CaptchaShieldProvider
	generator     *captcha.Generator
	analyzer      *detection.BehavioralAnalyzer
	sessions      map[string]*WidgetSession
	siteKey       string
	secretKey     string
	hmacKey       []byte
	onTokenIssued func(token string, expiry time.Time)
	mu            sync.RWMutex
}

// WidgetSession tracks a single reCAPTCHA v2 interaction session.
type WidgetSession struct {
	ID              string             `json:"id"`
	ChallengeID     string             `json:"challenge_id,omitempty"`
	CheckboxClicked bool               `json:"checkbox_clicked"`
	BehavioralScore float64            `json:"behavioral_score"`
	NeedChallenge   bool               `json:"need_challenge"`
	Token           string             `json:"token,omitempty"`
	TokenExpiry     time.Time          `json:"token_expiry,omitempty"`
	TokenUsed       bool               `json:"-"`
	RefreshCount    int                `json:"refresh_count"`
	MaxRefreshes    int                `json:"max_refreshes"`
	Difficulty      captcha.Difficulty `json:"-"`
	Solution        string             `json:"-"`
	CreatedAt       time.Time          `json:"created_at"`
}

// NewReCaptchaWidget creates a new reCAPTCHA v2 widget backend.
func NewReCaptchaWidget(shield CaptchaShieldProvider) *ReCaptchaWidget {
	siteKey := fmt.Sprintf("6L%s", base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("site_%d", time.Now().UnixNano())))[:20])
	secretKey := fmt.Sprintf("6L%s", base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("secret_%d", time.Now().UnixNano())))[:20])

	hmacKey := make([]byte, 32)
	for i := range hmacKey {
		hmacKey[i] = byte(time.Now().UnixNano()>>uint(i*8)) ^ byte(i*41+7) //nolint:gosec,mnd
	}

	return &ReCaptchaWidget{
		shield:    shield,
		generator: captcha.NewGenerator(captcha.ConfigForDifficulty(captcha.DifficultyMedium)),
		analyzer:  detection.NewBehavioralAnalyzer(nil),
		sessions:  make(map[string]*WidgetSession),
		siteKey:   siteKey,
		secretKey: secretKey,
		hmacKey:   hmacKey,
	}
}

// HandleInit handles POST /api/recaptcha/init — creates a new widget session.
func (w *ReCaptchaWidget) HandleInit(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	sessionID := fmt.Sprintf("rc_%d", time.Now().UnixNano())

	session := &WidgetSession{
		ID:           sessionID,
		MaxRefreshes: 5,
		Difficulty:   captcha.DifficultyMedium,
		CreatedAt:    time.Now(),
	}

	w.mu.Lock()
	w.sessions[sessionID] = session
	w.mu.Unlock()

	rw.Header().Set("Content-Type", "application/json")
	//nolint:errchkjson
	_ = json.NewEncoder(rw).Encode(map[string]interface{}{
		"session_id": sessionID,
		"site_key":   w.siteKey,
	})
}

// HandleCheckbox handles POST /api/recaptcha/checkbox — processes checkbox click with behavioral analysis.
func (w *ReCaptchaWidget) HandleCheckbox(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		SessionID string         `json:"session_id"`
		Events    []captchatraining.CaptchaEvent `json:"events"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(rw, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	w.mu.Lock()
	session, ok := w.sessions[req.SessionID]
	if !ok {
		w.mu.Unlock()
		http.Error(rw, `{"error":"session not found"}`, http.StatusNotFound)
		return
	}
	session.CheckboxClicked = true

	// Run behavioral analysis on the checkbox click events
	enhanced := eventsToEnhanced(req.Events)
	result := w.analyzer.Analyze(enhanced)
	session.BehavioralScore = result.Score

	// Build behavioral breakdown for debugging
	cbBreakdown := buildBehavioralBreakdown(result, enhanced, len(req.Events))

	rw.Header().Set("Content-Type", "application/json")

	if result.Score < 0.3 {
		// Low risk — pass immediately without challenge
		session.NeedChallenge = false
		token, expiry := w.generateToken(session.ID)
		session.Token = token
		session.TokenExpiry = expiry
		w.mu.Unlock()

		//nolint:errchkjson
		_ = json.NewEncoder(rw).Encode(map[string]interface{}{
			"passed":               true,
			"token":                token,
			"behavioral_score":     result.Score,
			"behavioral_breakdown": cbBreakdown,
		})
		return
	}

	// High risk — generate captcha challenge
	session.NeedChallenge = true
	challengeData, err := w.generateChallenge(session)
	w.mu.Unlock()

	if err != nil {
		http.Error(rw, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	//nolint:errchkjson
	_ = json.NewEncoder(rw).Encode(map[string]interface{}{
		"passed":               false,
		"behavioral_score":     result.Score,
		"behavioral_breakdown": cbBreakdown,
		"challenge":            challengeData,
	})
}

// HandleVerify handles POST /api/recaptcha/verify — submit captcha solution.
func (w *ReCaptchaWidget) HandleVerify(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		SessionID string         `json:"session_id"`
		Solution  string         `json:"solution"`
		Events    []captchatraining.CaptchaEvent `json:"events"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(rw, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	w.mu.Lock()
	session, ok := w.sessions[req.SessionID]
	if !ok {
		w.mu.Unlock()
		http.Error(rw, `{"error":"session not found"}`, http.StatusNotFound)
		return
	}

	// Behavioral analysis on solve events
	enhanced := eventsToEnhanced(req.Events)
	behavResult := w.analyzer.Analyze(enhanced)

	// Build behavioral breakdown for debugging
	behavBreakdown := buildBehavioralBreakdown(behavResult, enhanced, len(req.Events))

	// Check solution
	correct := session.Solution != "" &&
		len(req.Solution) > 0 &&
		equalFoldTrimmed(session.Solution, req.Solution)

	rw.Header().Set("Content-Type", "application/json")

	if correct && behavResult.Score < 0.5 {
		token, expiry := w.generateToken(session.ID)
		session.Token = token
		session.TokenExpiry = expiry
		w.mu.Unlock()

		//nolint:errchkjson
		_ = json.NewEncoder(rw).Encode(map[string]interface{}{
			"success":              true,
			"token":                token,
			"behavioral_score":     behavResult.Score,
			"behavioral_breakdown": behavBreakdown,
		})
		return
	}

	errorCodes := make([]string, 0)
	if !correct {
		errorCodes = append(errorCodes, "incorrect-captcha-sol")
	}
	if behavResult.Score >= 0.5 {
		errorCodes = append(errorCodes, "behavioral-bot-detected")
	}
	w.mu.Unlock()

	//nolint:errchkjson
	_ = json.NewEncoder(rw).Encode(map[string]interface{}{
		"success":              false,
		"error_codes":          errorCodes,
		"behavioral_score":     behavResult.Score,
		"behavioral_breakdown": behavBreakdown,
	})
}

// HandleRefresh handles POST /api/recaptcha/refresh — get a new captcha for current session.
func (w *ReCaptchaWidget) HandleRefresh(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(rw, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	w.mu.Lock()
	session, ok := w.sessions[req.SessionID]
	if !ok {
		w.mu.Unlock()
		http.Error(rw, `{"error":"session not found"}`, http.StatusNotFound)
		return
	}

	if session.RefreshCount >= session.MaxRefreshes {
		w.mu.Unlock()
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusTooManyRequests)
		//nolint:errchkjson
		_ = json.NewEncoder(rw).Encode(map[string]interface{}{
			"error":               "max refreshes exceeded",
			"refreshes_remaining": 0,
		})
		return
	}

	session.RefreshCount++

	// Escalate difficulty based on refresh count
	switch {
	case session.RefreshCount >= 3:
		session.Difficulty = captcha.DifficultyHard
	case session.RefreshCount >= 1:
		session.Difficulty = captcha.DifficultyMedium
	}

	challengeData, err := w.generateChallenge(session)
	remaining := session.MaxRefreshes - session.RefreshCount
	w.mu.Unlock()

	if err != nil {
		http.Error(rw, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	//nolint:errchkjson
	_ = json.NewEncoder(rw).Encode(map[string]interface{}{
		"challenge":           challengeData,
		"refreshes_remaining": remaining,
	})
}

// HandleSiteVerify handles POST /api/recaptcha/siteverify — server-side token verification.
func (w *ReCaptchaWidget) HandleSiteVerify(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Secret   string `json:"secret"`
		Response string `json:"response"`
		RemoteIP string `json:"remoteip,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(rw, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	rw.Header().Set("Content-Type", "application/json")

	// Validate secret
	if req.Secret != w.secretKey {
		//nolint:errchkjson
		_ = json.NewEncoder(rw).Encode(map[string]interface{}{
			"success":     false,
			"error-codes": []string{"invalid-input-secret"},
		})
		return
	}

	// Find the session with this token
	w.mu.Lock()
	var matchedSession *WidgetSession
	for _, s := range w.sessions {
		if s.Token == req.Response {
			matchedSession = s
			break
		}
	}

	if matchedSession == nil {
		w.mu.Unlock()
		//nolint:errchkjson
		_ = json.NewEncoder(rw).Encode(map[string]interface{}{
			"success":     false,
			"error-codes": []string{"invalid-input-response"},
		})
		return
	}

	// Check expiry
	if time.Now().After(matchedSession.TokenExpiry) {
		w.mu.Unlock()
		//nolint:errchkjson
		_ = json.NewEncoder(rw).Encode(map[string]interface{}{
			"success":     false,
			"error-codes": []string{"timeout-or-duplicate"},
		})
		return
	}

	// Check single-use
	if matchedSession.TokenUsed {
		w.mu.Unlock()
		//nolint:errchkjson
		_ = json.NewEncoder(rw).Encode(map[string]interface{}{
			"success":     false,
			"error-codes": []string{"timeout-or-duplicate"},
		})
		return
	}

	matchedSession.TokenUsed = true
	w.mu.Unlock()

	//nolint:errchkjson
	_ = json.NewEncoder(rw).Encode(map[string]interface{}{
		"success":      true,
		"challenge_ts": matchedSession.CreatedAt.Format(time.RFC3339),
		"hostname":     r.Host,
	})
}

// generateChallenge creates a captcha challenge for the session. Must be called with w.mu held.
func (w *ReCaptchaWidget) generateChallenge(session *WidgetSession) (map[string]interface{}, error) {
	cfg := captcha.ConfigForDifficulty(session.Difficulty)
	gen := captcha.NewGenerator(cfg)

	c, err := gen.Generate(captcha.CaptchaTypeText)
	if err != nil {
		return nil, fmt.Errorf("generate captcha: %w", err)
	}

	b64, err := captcha.EncodeToBase64(c.Image)
	if err != nil {
		return nil, fmt.Errorf("encode captcha image: %w", err)
	}

	// Extract solution text
	if sol, ok := c.Solution.(captcha.TextSolution); ok {
		session.Solution = sol.Text
	}
	session.ChallengeID = c.ID

	return map[string]interface{}{
		"id":           c.ID,
		"type":         "text",
		"image_base64": b64,
		"num_chars":    cfg.Length,
	}, nil
}

// generateToken creates an HMAC token with 2-minute TTL.
// If a token callback is registered, it notifies the parent server so the token
// is recognized by HandleRequest's validateCaptchaToken.
func (w *ReCaptchaWidget) generateToken(sessionID string) (string, time.Time) {
	expiry := time.Now().Add(2 * time.Minute)
	data := fmt.Sprintf("%s|%d", sessionID, expiry.UnixMilli())

	mac := hmac.New(sha256.New, w.hmacKey)
	mac.Write([]byte(data))
	token := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	// Bridge token into the parent server's solvedTokens map
	if w.onTokenIssued != nil {
		w.onTokenIssued(token, expiry)
	}

	return token, expiry
}

// GetSiteKey returns the widget's site key for embedding in redirect responses.
func (w *ReCaptchaWidget) GetSiteKey() string {
	return w.siteKey
}

// SetTokenCallback registers a callback invoked whenever a token is issued.
// This bridges reCAPTCHA v2 tokens into the main AdvancedStealthServer's solvedTokens.
func (w *ReCaptchaWidget) SetTokenCallback(cb func(token string, expiry time.Time)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.onTokenIssued = cb
}

// GetSession returns a session by ID (for testing).
func (w *ReCaptchaWidget) GetSession(id string) (*WidgetSession, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	s, ok := w.sessions[id]
	return s, ok
}

// eventsToEnhanced converts raw CaptchaEvents to EnhancedBehavioralEvents for analysis.
func eventsToEnhanced(events []captchatraining.CaptchaEvent) *detection.EnhancedBehavioralEvents {
	enhanced := &detection.EnhancedBehavioralEvents{}

	var prevX, prevY float64
	var prevTS int64
	hasPrev := false

	for _, ev := range events {
		switch ev.Type {
		case "mousemove":
			enhanced.MouseTimestamps = append(enhanced.MouseTimestamps, ev.Timestamp)
			enhanced.MousePositions = append(enhanced.MousePositions, detection.Position{X: ev.X, Y: ev.Y})

			if hasPrev {
				dt := float64(ev.Timestamp-prevTS) / 1000.0
				if dt > 0 {
					dx := ev.X - prevX
					dy := ev.Y - prevY
					dist := dx*dx + dy*dy
					if dist > 0 {
						velocity := sqrtFloat(dist) / dt
						enhanced.MouseVelocities = append(enhanced.MouseVelocities, velocity)
					}
				}
			}
			prevX, prevY, prevTS = ev.X, ev.Y, ev.Timestamp
			hasPrev = true

		case "click", "mousedown":
			enhanced.ClickTimestamps = append(enhanced.ClickTimestamps, ev.Timestamp)
			enhanced.ClickPositions = append(enhanced.ClickPositions, detection.Position{X: ev.X, Y: ev.Y})

		case "keydown", "keyup":
			enhanced.TypingTimestamps = append(enhanced.TypingTimestamps, ev.Timestamp)

		case "scroll", "wheel":
			enhanced.ScrollTimestamps = append(enhanced.ScrollTimestamps, ev.Timestamp)
			enhanced.ScrollDeltas = append(enhanced.ScrollDeltas, ev.Delta)
		}
	}

	return enhanced
}

// buildBehavioralBreakdown creates a JSON-friendly map of behavioral analysis details.
func buildBehavioralBreakdown(result *detection.VectorResult, enhanced *detection.EnhancedBehavioralEvents, totalEvents int) map[string]interface{} {
	breakdown := map[string]interface{}{
		"score":           result.Score,
		"detected":        result.Detected,
		"mouse_events":    len(enhanced.MouseTimestamps),
		"typing_events":   len(enhanced.TypingTimestamps),
		"scroll_events":   len(enhanced.ScrollTimestamps),
		"click_events":    len(enhanced.ClickTimestamps),
		"total_events":    totalEvents,
		"indicator_count": len(result.Indicators),
	}
	indicators := make([]map[string]interface{}, 0, len(result.Indicators))
	for _, ind := range result.Indicators {
		indicators = append(indicators, map[string]interface{}{
			"check":   ind.Check,
			"message": ind.Message,
			"weight":  ind.Weight,
			"field":   ind.Field,
			"value":   ind.Value,
		})
	}
	breakdown["indicators"] = indicators
	return breakdown
}

// equalFoldTrimmed compares two strings case-insensitively after trimming whitespace.
func equalFoldTrimmed(a, b string) bool {
	ta := trimSpace(a)
	tb := trimSpace(b)
	if len(ta) != len(tb) {
		return false
	}
	for i := 0; i < len(ta); i++ {
		ca, cb := ta[i], tb[i]
		if ca >= 'a' && ca <= 'z' {
			ca -= 32
		}
		if cb >= 'a' && cb <= 'z' {
			cb -= 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func trimSpace(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}

// sqrtFloat is a simple sqrt that avoids importing math in this file.
func sqrtFloat(x float64) float64 {
	if x <= 0 {
		return 0
	}
	z := x
	for i := 0; i < 20; i++ {
		z = (z + x/z) / 2
	}
	return z
}
