package adversarial

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// HandleChallengePage serves the 503 "Just a moment..." HTML page with CF markers
// that DetectChallenge() can parse, closing the loop between detection and reproduction.
func (cc *CloudflareChallenger) HandleChallengePage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		sessionID = fmt.Sprintf("cf_%d", time.Now().UnixNano())
	}

	// Check for existing cf_clearance cookie
	if cookie, err := r.Cookie("cf_clearance"); err == nil {
		if cc.ValidateClearanceCookie(cookie.Value) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<!DOCTYPE html><html><body><p>Access granted.</p></body></html>`))
			return
		}
	}

	detectionScore := 0.5 // default mid-range
	session := cc.CreateManagedChallenge(sessionID, detectionScore)

	powJSON, _ := json.Marshal(map[string]interface{}{
		"chlApiUrl":  "/api/cloudflare",
		"cRay":       session.RayID,
		"cType":      "managed",
		"chlTimeout": 300,
		"pow": map[string]interface{}{
			"prefix":     session.PoW.Prefix,
			"difficulty": session.PoW.Difficulty,
			"algorithm":  session.PoW.Algorithm,
		},
	})

	w.Header().Set("Server", "cloudflare")
	w.Header().Set("Cf-Ray", session.RayID)
	w.Header().Set("Cf-Mitigated", "challenge")
	w.Header().Set("Cache-Control", "private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Content-Type", "text/html")
	http.SetCookie(w, &http.Cookie{
		Name:     "__cf_bm",
		Value:    session.CFBMValue,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		Expires:  time.Now().Add(30 * time.Minute),
	})
	w.WriteHeader(http.StatusServiceUnavailable)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Just a moment...</title></head>
<body>
  <div id="cf-browser-verification" class="cf-im-under-attack">
    <noscript><h1>Enable JavaScript and cookies to continue</h1></noscript>
    <div id="cf-challenge-running" class="challenge-platform">
      <h2 data-translate="checking_browser">Checking if the site connection is secure</h2>
      <div class="managed_challenge" id="challenge-stage">
        <div id="cf-spinner-please-wait"></div>
      </div>
    </div>
    <script>var _cf_chl_opt=%s;</script>
    <script src="/cdn-cgi/challenge-platform/scripts/turnstile/managed.js" defer></script>
  </div>
  <div class="cf-error-footer">
    <p><span>Ray ID: <strong>%s</strong></span></p>
  </div>
</body>
</html>`, string(powJSON), session.RayID)

	_, _ = w.Write([]byte(html))
}

// cfInitRequest is the request body for HandleInit.
type cfInitRequest struct {
	SessionID      string  `json:"session_id"`
	ChallengeType  string  `json:"challenge_type"`
	DetectionScore float64 `json:"detection_score"`
	SiteKey        string  `json:"site_key"`
}

// cfInitResponse is the response from HandleInit.
type cfInitResponse struct {
	SessionID           string       `json:"session_id"`
	Type                string       `json:"type"`
	RayID               string       `json:"ray_id"`
	PoW                 *PoWChallenge `json:"pow"`
	RequiresFingerprint bool         `json:"requires_fingerprint"`
	RequiresBehavioral  bool         `json:"requires_behavioral"`
	SiteKey             string       `json:"site_key,omitempty"`
}

// HandleInit creates a new challenge session and returns PoW parameters.
func (cc *CloudflareChallenger) HandleInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req cfInitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.SessionID == "" {
		req.SessionID = fmt.Sprintf("cf_%d", time.Now().UnixNano())
	}

	var session *CloudflareChallengeSession

	switch req.ChallengeType {
	case "cloudflare_js", "js":
		session = cc.CreateJSChallenge(req.SessionID, req.DetectionScore)
	case "cloudflare_turnstile", "turnstile":
		siteKey := req.SiteKey
		if siteKey == "" {
			siteKey = "0x4AAAAAAAfake_sitekey"
		}
		session = cc.CreateTurnstileChallenge(req.SessionID, siteKey)
	default:
		// Default to managed challenge
		session = cc.CreateManagedChallenge(req.SessionID, req.DetectionScore)
	}

	resp := cfInitResponse{
		SessionID:           session.ID,
		Type:                string(session.Type),
		RayID:               session.RayID,
		PoW:                 session.PoW,
		RequiresFingerprint: session.RequiresFingerprint,
		RequiresBehavioral:  session.RequiresBehavioral,
		SiteKey:             session.SiteKey,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Server", "cloudflare")
	w.Header().Set("Cf-Ray", session.RayID)
	_ = json.NewEncoder(w).Encode(resp)
}

// cfSolveJSRequest is the request body for HandleSolveJS.
type cfSolveJSRequest struct {
	SessionID string      `json:"session_id"`
	Solution  PoWSolution `json:"solution"`
}

// HandleSolveJS validates a JS PoW challenge and issues a clearance cookie.
func (cc *CloudflareChallenger) HandleSolveJS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req cfSolveJSRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	result, err := cc.CompleteChallengeJS(req.SessionID, &req.Solution)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cf-Mitigated", "challenge")
		w.Header().Set("Server", "cloudflare")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	// Successful solve — no Cf-Mitigated header (real CF removes it)
	http.SetCookie(w, result.ClearanceCookie)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Server", "cloudflare")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"method":       result.Method,
		"solve_ms":     result.SolveTimeMs,
		"cf_clearance": result.ClearanceCookie.Value,
	})
}

// cfSolveManagedRequest is the request body for HandleSolveManaged.
type cfSolveManagedRequest struct {
	SessionID   string              `json:"session_id"`
	Solution    PoWSolution         `json:"solution"`
	Fingerprint *FingerprintPayload `json:"fingerprint"`
	Events      []CaptchaEvent      `json:"events"`
}

// HandleSolveManaged validates a managed challenge (PoW + fingerprint + behavioral).
func (cc *CloudflareChallenger) HandleSolveManaged(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req cfSolveManagedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	result, err := cc.CompleteChallengeManaged(req.SessionID, &req.Solution, req.Fingerprint, req.Events)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cf-Mitigated", "challenge")
		w.Header().Set("Server", "cloudflare")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	// Successful solve — no Cf-Mitigated header (real CF removes it)
	http.SetCookie(w, result.ClearanceCookie)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Server", "cloudflare")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"method":       result.Method,
		"solve_ms":     result.SolveTimeMs,
		"cf_clearance": result.ClearanceCookie.Value,
	})
}

// cfSolveTurnstileRequest is the request body for HandleSolveTurnstile.
type cfSolveTurnstileRequest struct {
	SessionID string         `json:"session_id"`
	Solution  PoWSolution    `json:"solution"`
	Events    []CaptchaEvent `json:"events"`
}

// HandleSolveTurnstile validates a Turnstile challenge (PoW + behavioral).
func (cc *CloudflareChallenger) HandleSolveTurnstile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req cfSolveTurnstileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	result, err := cc.CompleteTurnstile(req.SessionID, &req.Solution, req.Events)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cf-Mitigated", "challenge")
		w.Header().Set("Server", "cloudflare")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	// Successful solve — no Cf-Mitigated header
	http.SetCookie(w, result.ClearanceCookie)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Server", "cloudflare")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":         true,
		"method":          result.Method,
		"solve_ms":        result.SolveTimeMs,
		"turnstile_token": result.TurnstileToken,
		"cf_clearance":    result.ClearanceCookie.Value,
	})
}

// HandleVerifyClearance checks a cf_clearance cookie.
func (cc *CloudflareChallenger) HandleVerifyClearance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cookie, err := r.Cookie("cf_clearance")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"valid": false,
			"error": "no cf_clearance cookie",
		})
		return
	}

	valid := cc.ValidateClearanceCookie(cookie.Value)
	status := http.StatusOK
	if !valid {
		status = http.StatusForbidden
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"valid": valid,
	})
}

// HandleProtectedPage serves a challenge page for ANY request that lacks a valid
// cf_clearance cookie. Once solved, proxies through to real content. This emulates
// real CF behavior: the sword hits a normal-looking URL and gets a challenge page back.
func (cc *CloudflareChallenger) HandleProtectedPage(contentHandler http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check for valid cf_clearance cookie
		if cookie, err := r.Cookie("cf_clearance"); err == nil {
			if cc.ValidateClearanceCookie(cookie.Value) {
				contentHandler.ServeHTTP(w, r)
				return
			}
		}
		// Serve challenge page instead
		cc.HandleChallengePage(w, r)
	}
}

// HandleStatus returns challenge session statistics.
func (cc *CloudflareChallenger) HandleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := cc.GetStats()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}
