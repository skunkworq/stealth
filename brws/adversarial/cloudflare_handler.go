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
		Expires:  time.Now().Add(30 * time.Minute),
	})
	w.WriteHeader(http.StatusServiceUnavailable)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <title>Just a moment...</title>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=Edge">
  <meta name="robots" content="noindex,nofollow">
  <style>
    body{margin:0;padding:0;display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f5f5}
    .main-wrapper{text-align:center;padding:20px}
    .challenge-platform{margin:20px 0}
    #cf-spinner-please-wait{width:40px;height:40px;border:4px solid #ddd;border-top-color:#f38020;border-radius:50%%;animation:spin 1s linear infinite;margin:20px auto}
    @keyframes spin{to{transform:rotate(360deg)}}
    .cf-error-footer{color:#999;font-size:12px;margin-top:20px}
  </style>
</head>
<body>
  <div class="main-wrapper">
    <div id="cf-browser-verification" class="cf-im-under-attack">
      <noscript><h1>Enable JavaScript and cookies to continue</h1></noscript>
      <div id="cf-challenge-running" class="challenge-platform">
        <h2 data-translate="checking_browser">Checking if the site connection is secure</h2>
        <div class="managed_challenge" id="challenge-stage">
          <div id="cf-spinner-please-wait"></div>
          <p id="cf-spinner-text">This process is automatic. Your browser will redirect shortly.</p>
        </div>
      </div>
      <script>var _cf_chl_opt=%s;</script>
      <script>
      // CF fingerprint collection stub — collects browser environment data
      // and reports back via XHR before solving the challenge.
      (function(){
        var opt = window._cf_chl_opt;
        if (!opt) return;
        var fp = {
          ts: Date.now(),
          ray: opt.cRay,
          screen: [screen.width, screen.height, screen.colorDepth],
          nav: navigator.userAgent,
          lang: navigator.language,
          platform: navigator.platform,
          cores: navigator.hardwareConcurrency || 0,
          mem: navigator.deviceMemory || 0,
          tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
          webgl: (function(){try{var c=document.createElement('canvas'),g=c.getContext('webgl');return g?g.getParameter(g.RENDERER):''}catch(e){return''}})()
        };
        // Report fingerprint to callback endpoint
        var xhr = new XMLHttpRequest();
        xhr.open('POST', '/cdn-cgi/challenge-platform/h/g/cv/result/' + opt.cRay, true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.send(JSON.stringify({fp: fp, t: 'fp'}));
      })();
      </script>
      <script src="/cdn-cgi/challenge-platform/scripts/turnstile/managed.js" defer></script>
    </div>
    <div class="cf-error-footer">
      <p><span>Performance &amp; security by Cloudflare</span></p>
      <p><span>Ray ID: <strong>%s</strong></span></p>
    </div>
  </div>
</body>
</html>`, string(powJSON), session.RayID)

	_, _ = w.Write([]byte(html))
}

// cfInitRequest is the request body for HandleInit.
type cfInitRequest struct {
	SessionID       string  `json:"session_id"`
	ChallengeType   string  `json:"challenge_type"`
	DetectionScore  float64 `json:"detection_score"`
	SiteKey         string  `json:"site_key"`
	WidgetMode      string  `json:"widget_mode,omitempty"`
	Action          string  `json:"action,omitempty"`
	CData           string  `json:"cdata,omitempty"`
	Theme           string  `json:"theme,omitempty"`
	Size            string  `json:"size,omitempty"`
	Appearance      string  `json:"appearance,omitempty"`
	Execution       string  `json:"execution,omitempty"`
	Retry           string  `json:"retry,omitempty"`
	RetryIntervalMS int     `json:"retry_interval_ms,omitempty"`
	RefreshExpired  string  `json:"refresh_expired,omitempty"`
	RefreshTimeout  string  `json:"refresh_timeout,omitempty"`
	TokenTTLSeconds int     `json:"token_ttl_seconds,omitempty"`
}

// cfInitResponse is the response from HandleInit.
type cfInitResponse struct {
	SessionID           string                 `json:"session_id"`
	Type                string                 `json:"type"`
	RayID               string                 `json:"ray_id"`
	PoW                 *PoWChallenge          `json:"pow"`
	RequiresFingerprint bool                   `json:"requires_fingerprint"`
	RequiresBehavioral  bool                   `json:"requires_behavioral"`
	SiteKey             string                 `json:"site_key,omitempty"`
	Widget              *TurnstileWidgetConfig `json:"widget,omitempty"`
	CallbackState       *WidgetCallbackState   `json:"callback_state,omitempty"`
	WidgetURL           string                 `json:"widget_url,omitempty"`
	CallbackURL         string                 `json:"callback_url,omitempty"`
	SiteverifyURL       string                 `json:"siteverify_url,omitempty"`
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
		cfg := DefaultTurnstileWidgetConfig(req.SiteKey)
		cfg.Mode = req.WidgetMode
		cfg.Action = req.Action
		cfg.CData = req.CData
		cfg.Theme = req.Theme
		cfg.Size = req.Size
		cfg.Appearance = req.Appearance
		cfg.Execution = req.Execution
		cfg.Retry = req.Retry
		cfg.RetryIntervalMS = req.RetryIntervalMS
		cfg.RefreshExpired = req.RefreshExpired
		cfg.RefreshTimeout = req.RefreshTimeout
		cfg.TokenTTLSeconds = req.TokenTTLSeconds
		session = cc.CreateTurnstileChallengeWithConfig(req.SessionID, cfg)
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
		Widget:              session.TurnstileWidget,
		CallbackState:       session.CallbackState,
	}
	if session.Type == ChallengeTurnstile {
		resp.WidgetURL = fmt.Sprintf("/api/cloudflare/turnstile/widget?session_id=%s", session.ID)
		resp.CallbackURL = "/api/cloudflare/turnstile/callback"
		resp.SiteverifyURL = "/turnstile/v0/siteverify"
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Server", "cloudflare")
	w.Header().Set("Cf-Ray", session.RayID)
	// Set __cf_bm cookie — binds this session to subsequent solve requests
	http.SetCookie(w, &http.Cookie{
		Name:     "__cf_bm",
		Value:    session.CFBMValue,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // false for test servers (http, not https)
		Expires:  time.Now().Add(30 * time.Minute),
	})
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

	// Validate __cf_bm cookie is present and matches the session
	if err := cc.ValidateCFBMCookie(r, req.SessionID); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cf-Mitigated", "challenge")
		w.Header().Set("Server", "cloudflare")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "cookie validation failed: " + err.Error(),
		})
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

	// Validate __cf_bm cookie is present and matches the session
	if err := cc.ValidateCFBMCookie(r, req.SessionID); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cf-Mitigated", "challenge")
		w.Header().Set("Server", "cloudflare")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "cookie validation failed: " + err.Error(),
		})
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
	SessionID string           `json:"session_id"`
	Solution  PoWSolution      `json:"solution"`
	Events    []CaptchaEvent   `json:"events"`
	Telemetry *WidgetTelemetry `json:"telemetry,omitempty"`
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

	// Validate __cf_bm cookie is present and matches the session
	if err := cc.ValidateCFBMCookie(r, req.SessionID); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cf-Mitigated", "challenge")
		w.Header().Set("Server", "cloudflare")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "cookie validation failed: " + err.Error(),
		})
		return
	}

	result, err := cc.CompleteTurnstileInteraction(req.SessionID, &req.Solution, req.Events, req.Telemetry, r.Host)
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
		"success":             true,
		"method":              result.Method,
		"solve_ms":            result.SolveTimeMs,
		"turnstile_token":     result.TurnstileToken,
		"lab_turnstile_token": result.LabToken,
		"widget_telemetry":    result.WidgetTelemetry,
		"cf_clearance":        result.ClearanceCookie.Value,
		"siteverify_url":      "/turnstile/v0/siteverify",
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

	if sessionID := r.URL.Query().Get("session_id"); sessionID != "" {
		session, ok := cc.GetSession(sessionID)
		if !ok {
			http.Error(w, `{"error":"session not found"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"session_id":       session.ID,
			"type":             session.Type,
			"state":            session.State,
			"widget":           session.TurnstileWidget,
			"callback_state":   session.CallbackState,
			"widget_telemetry": session.WidgetTelemetry,
			"turnstile_token":  session.TurnstileToken,
			"passed":           session.Passed,
		})
		return
	}

	stats := cc.GetStats()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}

// HandleChallengeCallback accepts XHR callbacks from the challenge page JS.
// Real CF challenge pages send fingerprint data, timing signals, and behavioral
// events to /cdn-cgi/challenge-platform/h/g/cv/result/{rayID} before submitting
// the final solve. This endpoint logs those signals for observability.
func (cc *CloudflareChallenger) HandleChallengeCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Accept the callback data (discard for now — logging only)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Server", "cloudflare")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// HandleManagedJS serves a stub managed.js script that would normally orchestrate
// the challenge flow client-side. In the lab, this returns a minimal script that
// signals the page is ready.
func (cc *CloudflareChallenger) HandleManagedJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	w.Header().Set("Server", "cloudflare")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write([]byte(`
// Cloudflare managed challenge orchestrator (lab stub)
(function(){
  var opt = window._cf_chl_opt;
  if (!opt || !opt.pow) return;
  document.getElementById('cf-spinner-text').textContent = 'Verifying you are human...';
  // In the real flow, this script would:
  // 1. Solve the PoW challenge
  // 2. Collect fingerprint data
  // 3. Record behavioral events
  // 4. Submit the solution via XHR
  // The lab solver handles this server-side instead.
})();
`))
}

// MountRoutes registers all Cloudflare challenge API routes on the given mux.
// Solve endpoints are wrapped with the per-IP rate limiter.
func (cc *CloudflareChallenger) MountRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/cloudflare/init", cc.HandleInit)
	mux.HandleFunc("/api/cloudflare/challenge", cc.HandleChallengePage)
	mux.HandleFunc("/api/cloudflare/verify", cc.HandleVerifyClearance)
	mux.HandleFunc("/api/cloudflare/status", cc.HandleStatus)

	// Solve endpoints are rate-limited
	mux.HandleFunc("/api/cloudflare/solve/js", cc.RateLimiter.RateLimitMiddleware(cc.HandleSolveJS))
	mux.HandleFunc("/api/cloudflare/solve/managed", cc.RateLimiter.RateLimitMiddleware(cc.HandleSolveManaged))
	mux.HandleFunc("/api/cloudflare/solve/turnstile", cc.RateLimiter.RateLimitMiddleware(cc.HandleSolveTurnstile))

	// XHR callback endpoints (used by challenge page JS)
	mux.HandleFunc("/cdn-cgi/challenge-platform/h/g/cv/result/", cc.HandleChallengeCallback)
	mux.HandleFunc("/cdn-cgi/challenge-platform/scripts/turnstile/managed.js", cc.HandleManagedJS)
	mux.HandleFunc("/api/cloudflare/turnstile/widget", cc.HandleTurnstileWidgetPage)
	mux.HandleFunc("/api/cloudflare/turnstile/callback", cc.HandleTurnstileCallback)
	mux.HandleFunc("/turnstile/v0/api.js", cc.HandleTurnstileAPIJS)
	mux.HandleFunc("/turnstile/v0/siteverify", cc.HandleTurnstileSiteVerify)
}
