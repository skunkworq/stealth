package adversarial

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
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
    .managed_challenge{display:flex;justify-content:center}
    .cf-managed-shell{width:min(420px,92vw);padding:16px;background:#fff;border:1px solid #e5e5e5;border-radius:16px;box-shadow:0 18px 60px rgba(0,0,0,.08);text-align:left}
    .cf-managed-widget{min-height:65px;border:1px solid #d9d9d9;border-radius:12px;padding:12px;background:#fafafa;display:grid;grid-template-columns:auto 1fr auto;align-items:center;gap:12px}
    .cf-managed-checkbox{width:28px;height:28px;border:2px solid #8c8c8c;border-radius:6px;background:#fff;display:grid;place-items:center;padding:0;cursor:pointer;transition:border-color .18s ease, background-color .18s ease}
    .cf-managed-checkbox:hover{border-color:#3b82f6}
    #cf-spinner-please-wait{width:16px;height:16px;border:2px solid #cbd5e1;border-top-color:#2563eb;border-radius:50%%;animation:spin 1s linear infinite;display:block}
    .cf-managed-check{display:none;font-size:16px;line-height:1}
    .cf-managed-copy{min-width:0}
    .cf-managed-title{font-size:14px;font-weight:600;color:#1f2937}
    .cf-managed-subtitle{font-size:12px;color:#6b7280;margin:0}
    .cf-managed-brand{font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.08em}
    .cf-managed-widget[data-state="interactive"] #cf-spinner-please-wait{display:none}
    .cf-managed-widget[data-state="interactive"] .cf-managed-checkbox{border-color:#3b82f6}
    .cf-managed-widget[data-state="solving"] #cf-spinner-please-wait{display:block}
    .cf-managed-widget[data-state="complete"] #cf-spinner-please-wait{display:none}
    .cf-managed-widget[data-state="complete"] .cf-managed-check{display:block}
    .cf-managed-widget[data-state="complete"] .cf-managed-checkbox{border-color:#16a34a;background:#16a34a;color:#fff}
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
          <div class="cf-managed-shell">
            <div class="cf-managed-widget" id="cf-managed-widget" data-state="loading">
              <button class="cf-managed-checkbox" id="cf-managed-checkbox" type="button" aria-label="Local managed challenge checkbox" aria-pressed="false">
                <span id="cf-spinner-please-wait"></span>
                <span class="cf-managed-check">✓</span>
              </button>
              <div class="cf-managed-copy">
                <div class="cf-managed-title">Verify you are human</div>
                <p class="cf-managed-subtitle" id="cf-spinner-text">Checking your browser before accessing the local harness.</p>
              </div>
              <div class="cf-managed-brand">Turnstile</div>
            </div>
          </div>
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
		session = cc.CreateTurnstileChallengeWithRisk(req.SessionID, siteKey, req.DetectionScore)
	default:
		// Default to managed challenge
		session = cc.CreateManagedChallenge(req.SessionID, req.DetectionScore)
	}
	session.Hostname = normalizeChallengeHost(r.Host)

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

func turnstileInitialSubtitle(cfg TurnstileWidgetConfig) string {
	switch cfg.Interaction.Type {
	case turnstileInteractionHold:
		return "Press and hold to continue"
	case turnstileInteractionDrag:
		return "Drag the handle to the end"
	default:
		return "Local Turnstile harness ready"
	}
}

func turnstileControlMarkup(cfg TurnstileWidgetConfig) string {
	switch cfg.Interaction.Type {
	case turnstileInteractionHold:
		return `<button class="cf-ts-hold" type="button" data-primary-control="true" aria-label="Local Turnstile harness hold button" aria-pressed="false">Hold</button>`
	case turnstileInteractionDrag:
		trackLength := cfg.Interaction.DragTrackLengthPx
		if trackLength <= 0 {
			trackLength = 220
		}
		return fmt.Sprintf(`<div class="cf-ts-slider" style="width:%dpx">
          <div class="cf-ts-slider-track"></div>
          <div class="cf-ts-slider-fill"></div>
          <button class="cf-ts-slider-knob" type="button" data-primary-control="true" aria-label="Local Turnstile harness drag handle" aria-pressed="false"></button>
        </div>`, trackLength)
	default:
		return `<button class="cf-ts-checkbox" type="button" data-primary-control="true" aria-label="Local Turnstile harness checkbox" aria-pressed="false">
          <span class="cf-ts-spinner">↻</span>
          <span class="cf-ts-check">✓</span>
        </button>`
	}
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
	detectionScore, _ := strconv.ParseFloat(r.URL.Query().Get("detection_score"), 64)

	session, ok := cc.GetSession(sessionID)
	if !ok || session.Type != ChallengeTurnstile {
		session = cc.CreateTurnstileChallengeWithRisk(sessionID, siteKey, detectionScore)
	}

	cc.PresentTurnstileWidget(session.ID, r.Host)

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Server", "cloudflare")
	w.Header().Set("Cf-Ray", session.RayID)
	w.WriteHeader(http.StatusForbidden)

	initialSubtitle := turnstileInitialSubtitle(session.TurnstileConfig)
	controlMarkup := turnstileControlMarkup(session.TurnstileConfig)

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
    .cf-turnstile-shell{display:grid;grid-template-columns:auto 1fr auto;align-items:center;gap:12px}
    .cf-ts-control{display:flex;align-items:center;justify-content:center;min-width:40px;min-height:32px}
    .cf-ts-checkbox{width:28px;height:28px;border:2px solid #8c8c8c;border-radius:6px;background:#fff;display:grid;place-items:center;padding:0;cursor:pointer;transition:border-color .18s ease, background-color .18s ease}
    .cf-ts-checkbox:hover{border-color:#3b82f6}
    .cf-ts-hold{display:none;min-width:84px;height:32px;padding:0 14px;border:1px solid #8c8c8c;border-radius:999px;background:#fff;color:#1f2937;font-size:12px;font-weight:600;cursor:pointer;transition:border-color .18s ease, background-color .18s ease}
    .cf-ts-hold:hover{border-color:#3b82f6}
    .cf-ts-slider{display:none;position:relative;height:32px;align-items:center}
    .cf-ts-slider-track{position:absolute;left:0;right:0;height:10px;border-radius:999px;background:#e5e7eb}
    .cf-ts-slider-fill{position:absolute;left:0;width:18px;height:10px;border-radius:999px;background:#93c5fd;transition:width .08s linear}
    .cf-ts-slider-knob{position:absolute;left:0;top:50%%;width:28px;height:28px;border:1px solid #9ca3af;border-radius:999px;background:#fff;transform:translate(0px,-50%%);box-shadow:0 1px 4px rgba(0,0,0,.12);cursor:grab}
    .cf-ts-spinner,.cf-ts-check{display:none;font-size:16px;line-height:1}
    .cf-ts-copy{min-width:0}
    .cf-ts-title{font-size:14px;font-weight:600;color:#1f2937}
    .cf-ts-subtitle{font-size:12px;color:#6b7280}
    .cf-ts-brand{font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.08em}
    .cf-turnstile[data-interaction="hold"] .cf-ts-hold{display:inline-flex;align-items:center;justify-content:center}
    .cf-turnstile[data-interaction="drag"] .cf-ts-slider{display:flex}
    .cf-turnstile[data-interaction="drag"] .cf-turnstile-shell{grid-template-columns:minmax(220px,1fr) 1fr auto}
    .cf-turnstile[data-interaction="hold"] .cf-ts-checkbox,
    .cf-turnstile[data-interaction="drag"] .cf-ts-checkbox{display:none}
    .cf-turnstile[data-state="solving"] .cf-ts-spinner{display:block;animation:cf-ts-spin 1s linear infinite}
    .cf-turnstile[data-state="solving"] .cf-ts-checkbox{border-color:#2563eb}
    .cf-turnstile[data-state="solving"] .cf-ts-hold{border-color:#2563eb;background:#eff6ff}
    .cf-turnstile[data-state="complete"] .cf-ts-checkbox{border-color:#16a34a;background:#16a34a;color:#fff}
    .cf-turnstile[data-state="complete"] .cf-ts-check{display:block}
    .cf-turnstile[data-state="complete"] .cf-ts-spinner{display:none}
    .cf-turnstile[data-state="complete"] .cf-ts-hold{border-color:#16a34a;background:#16a34a;color:#fff}
    .cf-turnstile[data-state="complete"] .cf-ts-slider-fill{background:#16a34a}
    .cf-turnstile[data-state="complete"] .cf-ts-slider-knob{background:#16a34a;border-color:#16a34a}
    @keyframes cf-ts-spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}
    .cf-meta{margin-top:14px;color:#6f6f6f;font-size:12px}
    @media (max-width: 520px){
      .cf-shell{padding:24px}
      .cf-turnstile[data-interaction="drag"] .cf-turnstile-shell{grid-template-columns:1fr;gap:10px}
      .cf-turnstile[data-interaction="drag"] .cf-ts-control{justify-content:flex-start}
      .cf-turnstile[data-interaction="drag"] .cf-ts-brand{justify-self:start}
    }
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
      data-risk-level="%s"
      data-interaction="%s"
      data-required-hold-ms="%d"
      data-required-drag-distance="%d"
      data-required-drag-events="%d"
      data-drag-track-length="%d"
      data-retry="%s"
      data-retry-interval="%d"
      data-refresh-expired="%s"
      data-refresh-timeout="%s"
      data-before-interactive-callback="__tsBeforeInteractive"
      data-after-interactive-callback="__tsAfterInteractive"
      data-callback="__tsSuccess"
      data-expired-callback="__tsExpired"
      data-timeout-callback="__tsTimeout"
      data-error-callback="__tsError">
      <div class="cf-turnstile-shell">
        <div class="cf-ts-control">%s</div>
        <div class="cf-ts-copy">
          <div class="cf-ts-title">Verify you are human</div>
          <div class="cf-ts-subtitle">%s</div>
        </div>
        <div class="cf-ts-brand">Turnstile</div>
      </div>
      <input type="hidden" name="cf-turnstile-response" value="">
    </div>
    <div class="cf-meta">Ray ID: %s</div>
  </main>
  <script>
    const __tsWidget = document.querySelector('.cf-turnstile');
    const __tsPrimaryControl = document.querySelector('[data-primary-control="true"]');
    const __tsSubtitle = document.querySelector('.cf-ts-subtitle');
    const __tsCheckbox = document.querySelector('.cf-ts-checkbox');
    const __tsHoldButton = document.querySelector('.cf-ts-hold');
    const __tsSlider = document.querySelector('.cf-ts-slider');
    const __tsSliderFill = document.querySelector('.cf-ts-slider-fill');
    const __tsSliderKnob = document.querySelector('.cf-ts-slider-knob');
    const __tsVariant = (__tsWidget && __tsWidget.dataset.interaction) || 'checkbox';
    const __tsRequiredHoldMs = parseInt((__tsWidget && __tsWidget.dataset.requiredHoldMs) || '900', 10);
    const __tsRequiredDragDistance = parseInt((__tsWidget && __tsWidget.dataset.requiredDragDistance) || '160', 10);
    const __tsRequiredDragEvents = parseInt((__tsWidget && __tsWidget.dataset.requiredDragEvents) || '6', 10);
    const __tsDragTrackLength = parseInt((__tsWidget && __tsWidget.dataset.dragTrackLength) || '220', 10);
    function __tsSetState(state, subtitle){
      if (__tsWidget) {
        __tsWidget.dataset.state = state;
      }
      if (__tsSubtitle && subtitle) {
        __tsSubtitle.textContent = subtitle;
      }
      if (__tsPrimaryControl && __tsPrimaryControl.setAttribute) {
        __tsPrimaryControl.setAttribute('aria-pressed', state === 'complete' ? 'true' : 'false');
      }
    }
    function __tsPost(payload){
      navigator.sendBeacon('/cdn-cgi/challenge-platform/h/g/cv/result/%s', JSON.stringify(Object.assign({session_id: %q}, payload)));
    }
    function __tsPostInteraction(proof){
      __tsPost({type: 'interaction', interaction: Object.assign({type: __tsVariant}, proof)});
    }
    function __tsSnapshot(){
      __tsPost({
        type: 'snapshot',
        snapshot: {
          user_agent: navigator.userAgent || '',
          language: navigator.language || '',
          languages: navigator.languages || [],
          platform: navigator.platform || '',
          hardware_concurrency: navigator.hardwareConcurrency || 0,
          webdriver: !!navigator.webdriver,
          screen_width: screen.width || 0,
          screen_height: screen.height || 0,
          color_depth: screen.colorDepth || 0,
          timezone: (Intl.DateTimeFormat().resolvedOptions().timeZone || ''),
          max_touch_points: navigator.maxTouchPoints || 0,
          cookie_enabled: !!navigator.cookieEnabled
        }
      });
    }
    function __tsPostCallback(callbackName){
      __tsPost({callback: callbackName});
    }
    __tsSetState('ready', 'Local Turnstile harness ready');
    __tsSnapshot();
    __tsPostCallback('before-interactive');
    function __tsBeforeInteractive(){ __tsPostCallback('before-interactive'); }
    function __tsAfterInteractive(){ __tsPostCallback('after-interactive'); }
    function __tsSuccess(token){ __tsPostCallback('success'); return token; }
    function __tsExpired(){ __tsPostCallback('expired'); }
    function __tsTimeout(){ __tsPostCallback('timeout'); }
    function __tsError(){ __tsPostCallback('error'); }
    function __tsArmSubtitle(){
      switch (__tsVariant) {
        case 'hold':
          return 'Press and hold to continue';
        case 'drag':
          return 'Drag the handle to the end';
        default:
          return 'Interaction telemetry armed';
      }
    }
    setTimeout(function(){
      __tsSetState('interactive', __tsArmSubtitle());
      __tsAfterInteractive();
    }, 10);
    if (__tsCheckbox) {
      __tsCheckbox.addEventListener('click', function(){
        if (__tsWidget && __tsWidget.dataset.state === 'solving') {
          return;
        }
        __tsSetState('solving', 'Checking your browser in the local harness...');
        setTimeout(function(){
          __tsPostInteraction({completed: true, checkbox_clicks: 1});
          __tsSetState('complete', 'Interaction recorded. Submit via the lab flow to mint a token.');
        }, 650);
      });
    }
    let __tsHoldStartedAt = 0;
    if (__tsHoldButton) {
      const __tsReleaseHold = function(){
        if (!__tsHoldStartedAt) {
          return;
        }
        const heldFor = Date.now() - __tsHoldStartedAt;
        __tsHoldStartedAt = 0;
        const completed = heldFor >= __tsRequiredHoldMs;
        __tsPostInteraction({completed: completed, hold_duration_ms: heldFor});
        if (completed) {
          __tsSetState('complete', 'Hold interaction recorded. Submit via the lab flow to mint a token.');
          return;
        }
        __tsSetState('interactive', 'Hold a little longer to continue');
      };
      __tsHoldButton.addEventListener('pointerdown', function(event){
        event.preventDefault();
        if (__tsWidget && __tsWidget.dataset.state === 'solving') {
          return;
        }
        __tsHoldStartedAt = Date.now();
        __tsSetState('solving', 'Keep holding to confirm you are human...');
      });
      window.addEventListener('pointerup', __tsReleaseHold);
      window.addEventListener('pointercancel', __tsReleaseHold);
    }
    let __tsDragging = false;
    let __tsDragOrigin = 0;
    let __tsDragOffset = 0;
    let __tsDragMoveCount = 0;
    function __tsResetDrag(){
      __tsDragOffset = 0;
      __tsDragMoveCount = 0;
      if (__tsSliderKnob) {
        __tsSliderKnob.style.transform = 'translate(0px, -50%%)';
      }
      if (__tsSliderFill) {
        __tsSliderFill.style.width = '18px';
      }
    }
    if (__tsSlider && __tsSliderKnob) {
      __tsSliderKnob.addEventListener('pointerdown', function(event){
        event.preventDefault();
        if (__tsWidget && __tsWidget.dataset.state === 'solving') {
          return;
        }
        __tsDragging = true;
        __tsDragOrigin = event.clientX;
        __tsDragOffset = 0;
        __tsDragMoveCount = 0;
        __tsSetState('solving', 'Drag the handle to complete verification...');
      });
      window.addEventListener('pointermove', function(event){
        if (!__tsDragging) {
          return;
        }
        __tsDragMoveCount += 1;
        const nextOffset = Math.max(0, Math.min(__tsDragTrackLength, event.clientX - __tsDragOrigin));
        __tsDragOffset = nextOffset;
        __tsSliderKnob.style.transform = 'translate(' + nextOffset + 'px, -50%%)';
        __tsSliderFill.style.width = (18 + nextOffset) + 'px';
      });
      window.addEventListener('pointerup', function(){
        if (!__tsDragging) {
          return;
        }
        __tsDragging = false;
        const completed = __tsDragOffset >= __tsRequiredDragDistance && __tsDragMoveCount >= __tsRequiredDragEvents;
        __tsPostInteraction({
          completed: completed,
          drag_distance_px: Math.round(__tsDragOffset),
          drag_event_count: __tsDragMoveCount
        });
        if (completed) {
          __tsSetState('complete', 'Drag interaction recorded. Submit via the lab flow to mint a token.');
          return;
        }
        __tsResetDrag();
        __tsSetState('interactive', 'Drag the handle further to continue');
      });
      window.addEventListener('pointercancel', function(){
        if (!__tsDragging) {
          return;
        }
        __tsDragging = false;
        __tsResetDrag();
        __tsSetState('interactive', 'Drag the handle to the end');
      });
    }
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
		session.TurnstileConfig.RiskLevel,
		session.TurnstileConfig.Interaction.Type,
		session.TurnstileConfig.Interaction.RequiredHoldMs,
		session.TurnstileConfig.Interaction.RequiredDragDistancePx,
		session.TurnstileConfig.Interaction.RequiredDragEventCount,
		session.TurnstileConfig.Interaction.DragTrackLengthPx,
		session.TurnstileConfig.RetryPolicy.Mode,
		session.TurnstileConfig.RetryPolicy.IntervalMs,
		session.TurnstileConfig.RefreshPolicy.Expired,
		session.TurnstileConfig.RefreshPolicy.Timeout,
		controlMarkup,
		initialSubtitle,
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

	if sessionID := strings.TrimSpace(r.URL.Query().Get("session_id")); sessionID != "" {
		session, ok := cc.GetSession(sessionID)
		if !ok {
			http.Error(w, `{"error":"session not found"}`, http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"session_id":           session.ID,
			"type":                 session.Type,
			"hostname":             session.Hostname,
			"passed":               session.Passed,
			"score":                session.Score,
			"turnstile_presented":  session.TurnstilePresented,
			"turnstile_config":     session.TurnstileConfig,
			"widget_telemetry":     session.TurnstileTelemetry,
			"turnstile_snapshot":   session.TurnstileSnapshot,
			"turnstile_token_used": session.TurnstileTokenUsed,
		})
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
		SessionID   string                     `json:"session_id"`
		Callback    string                     `json:"callback"`
		Type        string                     `json:"type"`
		LegacyType  string                     `json:"t"`
		Snapshot    *TurnstileClientSnapshot   `json:"snapshot"`
		Interaction *TurnstileInteractionProof `json:"interaction"`
	}
	_ = json.NewDecoder(r.Body).Decode(&payload)
	if payload.Type == "" {
		payload.Type = payload.LegacyType
	}

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
	case payload.Type == "interaction" || payload.Interaction != nil:
		cc.RecordTurnstileInteractionProof(matchedSessionID, payload.Interaction)
	case payload.Type == "snapshot" || payload.Snapshot != nil:
		cc.RecordTurnstileClientSnapshot(matchedSessionID, payload.Snapshot)
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
  var widget = document.getElementById('cf-managed-widget');
  var checkbox = document.getElementById('cf-managed-checkbox');
  var subtitle = document.getElementById('cf-spinner-text');
  function setState(state, text) {
    if (widget) {
      widget.dataset.state = state;
    }
    if (subtitle && text) {
      subtitle.textContent = text;
    }
    if (checkbox) {
      checkbox.setAttribute('aria-pressed', state === 'complete' ? 'true' : 'false');
    }
  }
  setState('interactive', 'Verifying you are human...');
  if (checkbox) {
    checkbox.addEventListener('click', function() {
      setState('solving', 'Recording interaction telemetry in the local harness...');
      window.setTimeout(function() {
        setState('complete', 'Interaction captured. Continue with the lab solver flow.');
      }, 700);
    });
  }
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
