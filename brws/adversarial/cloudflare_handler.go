package adversarial

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
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
	SessionID      string  `json:"session_id"`
	ChallengeType  string  `json:"challenge_type"`
	DetectionScore float64 `json:"detection_score"`
	SiteKey        string  `json:"site_key"`
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
	Turnstile           *TurnstileWidgetConfig `json:"turnstile,omitempty"`
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
	session.Hostname = r.Host

	resp := cfInitResponse{
		SessionID:           session.ID,
		Type:                string(session.Type),
		RayID:               session.RayID,
		PoW:                 session.PoW,
		RequiresFingerprint: session.RequiresFingerprint,
		RequiresBehavioral:  session.RequiresBehavioral,
		SiteKey:             session.SiteKey,
	}
	if session.Type == ChallengeTurnstile {
		cfg := session.TurnstileConfig
		resp.Turnstile = &cfg
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

// HandleTurnstileWidgetPage serves a local Turnstile-style widget page for owned-environment testing.
func (cc *CloudflareChallenger) HandleTurnstileWidgetPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		sessionID = fmt.Sprintf("cf_ts_%d", time.Now().UnixNano())
	}

	siteKey := r.URL.Query().Get("site_key")
	if siteKey == "" {
		siteKey = "1x00000000000000000000AA"
	}

	session, ok := cc.GetSession(sessionID)
	if !ok || session.Type != ChallengeTurnstile {
		session = cc.CreateTurnstileChallenge(sessionID, siteKey)
	}

	cc.PresentTurnstileWidget(session.ID, r.Host)

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Server", "cloudflare")
	w.Header().Set("Cf-Ray", session.RayID)
	w.WriteHeader(http.StatusForbidden)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="robots" content="noindex,nofollow">
  <title>Just a moment...</title>
  <style>
    body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f7f7f7;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
    .cf-shell{width:min(420px,92vw);padding:28px;background:#fff;border:1px solid #e5e5e5;border-radius:16px;box-shadow:0 18px 60px rgba(0,0,0,.08)}
    .cf-turnstile{min-height:65px;border:1px solid #d9d9d9;border-radius:12px;padding:12px;background:#fafafa}
    .cf-meta{margin-top:14px;color:#6f6f6f;font-size:12px}
  </style>
</head>
<body>
  <main class="cf-shell">
    <h1>Verify you are human</h1>
    <p>This is a local Turnstile harness for owned-environment testing.</p>
    <div class="cf-turnstile"
      data-sitekey="%s"
      data-action="%s"
      data-cdata="%s"
      data-theme="%s"
      data-size="%s"
      data-appearance="%s"
      data-execution="%s"
      data-retry="%s"
      data-retry-interval="%d"
      data-refresh-expired="%s"
      data-refresh-timeout="%s"
      data-before-interactive-callback="__tsBeforeInteractive"
      data-after-interactive-callback="__tsAfterInteractive"
      data-callback="__tsSuccess"
      data-expired-callback="__tsExpired"
      data-timeout-callback="__tsTimeout"
      data-error-callback="__tsError"></div>
    <div class="cf-meta">Ray ID: %s</div>
  </main>
  <script>
    function __tsPost(callbackName){
      navigator.sendBeacon('/cdn-cgi/challenge-platform/h/g/cv/result/%s', JSON.stringify({callback: callbackName, session_id: %q}));
    }
    __tsPost('before-interactive');
    function __tsBeforeInteractive(){ __tsPost('before-interactive'); }
    function __tsAfterInteractive(){ __tsPost('after-interactive'); }
    function __tsSuccess(token){ __tsPost('success'); return token; }
    function __tsExpired(){ __tsPost('expired'); }
    function __tsTimeout(){ __tsPost('timeout'); }
    function __tsError(){ __tsPost('error'); }
    setTimeout(__tsAfterInteractive, 10);
  </script>
</body>
</html>`,
		session.SiteKey,
		session.TurnstileConfig.Action,
		session.TurnstileConfig.CData,
		session.TurnstileConfig.Theme,
		session.TurnstileConfig.Size,
		session.TurnstileConfig.Appearance,
		session.TurnstileConfig.Execution,
		session.TurnstileConfig.RetryPolicy.Mode,
		session.TurnstileConfig.RetryPolicy.IntervalMs,
		session.TurnstileConfig.RefreshPolicy.Expired,
		session.TurnstileConfig.RefreshPolicy.Timeout,
		session.RayID,
		session.RayID,
		session.ID,
	)

	_, _ = w.Write([]byte(html))
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
		"success":          true,
		"method":           result.Method,
		"solve_ms":         result.SolveTimeMs,
		"turnstile_token":  result.TurnstileToken,
		"turnstile":        result.Turnstile,
		"widget_telemetry": result.Telemetry,
		"cf_clearance":     result.ClearanceCookie.Value,
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

// HandleTurnstileSiteVerify verifies locally issued Turnstile tokens using lab-only semantics.
func (cc *CloudflareChallenger) HandleTurnstileSiteVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	type verifyReq struct {
		Secret   string `json:"secret"`
		Response string `json:"response"`
		RemoteIP string `json:"remoteip,omitempty"`
	}

	var req verifyReq
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, `{"error":"invalid form body"}`, http.StatusBadRequest)
			return
		}
		req.Secret = r.FormValue("secret")
		req.Response = r.FormValue("response")
		req.RemoteIP = r.FormValue("remoteip")
	}

	result := cc.VerifyTurnstileToken(req.Secret, req.Response, r.Host)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Server", "cloudflare")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      result.Success,
		"challenge_ts": result.ChallengeTS,
		"hostname":     result.Hostname,
		"action":       result.Action,
		"cdata":        result.CData,
		"error-codes":  result.ErrorCodes,
	})
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

	var payload struct {
		SessionID string `json:"session_id"`
		Callback  string `json:"callback"`
		Type      string `json:"t"`
	}
	_ = json.NewDecoder(r.Body).Decode(&payload)

	rayID := strings.TrimPrefix(r.URL.Path, "/cdn-cgi/challenge-platform/h/g/cv/result/")
	cc.mu.RLock()
	var matchedSessionID string
	for _, session := range cc.sessions {
		if session.RayID != rayID && payload.SessionID != session.ID {
			continue
		}
		matchedSessionID = session.ID
		break
	}
	cc.mu.RUnlock()

	switch {
	case matchedSessionID == "":
	case payload.Callback != "":
		cc.RecordTurnstileCallback(matchedSessionID, payload.Callback)
	case payload.Type == "fp":
		cc.RecordTurnstileCallback(matchedSessionID, "before-interactive")
	}

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
	mux.HandleFunc("/api/cloudflare/turnstile/widget", cc.HandleTurnstileWidgetPage)
	mux.HandleFunc("/api/cloudflare/turnstile/siteverify", cc.HandleTurnstileSiteVerify)
	mux.HandleFunc("/turnstile/v0/siteverify", cc.HandleTurnstileSiteVerify)
	mux.HandleFunc("/api/cloudflare/verify", cc.HandleVerifyClearance)
	mux.HandleFunc("/api/cloudflare/status", cc.HandleStatus)

	// Solve endpoints are rate-limited
	mux.HandleFunc("/api/cloudflare/solve/js", cc.RateLimiter.RateLimitMiddleware(cc.HandleSolveJS))
	mux.HandleFunc("/api/cloudflare/solve/managed", cc.RateLimiter.RateLimitMiddleware(cc.HandleSolveManaged))
	mux.HandleFunc("/api/cloudflare/solve/turnstile", cc.RateLimiter.RateLimitMiddleware(cc.HandleSolveTurnstile))

	// XHR callback endpoints (used by challenge page JS)
	mux.HandleFunc("/cdn-cgi/challenge-platform/h/g/cv/result/", cc.HandleChallengeCallback)
	mux.HandleFunc("/cdn-cgi/challenge-platform/scripts/turnstile/managed.js", cc.HandleManagedJS)
}
