package adversarial

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type turnstileCallbackRequest struct {
	SessionID string `json:"session_id"`
	Callback  string `json:"callback"`
	ErrorCode string `json:"error_code,omitempty"`
}

type turnstileSiteverifyRequest struct {
	Secret   string `json:"secret"`
	Response string `json:"response"`
	RemoteIP string `json:"remoteip,omitempty"`
}

// HandleTurnstileWidgetPage serves a local Turnstile widget page that mirrors
// the public DOM/configuration contract closely enough for owned-environment
// browser automation and regression testing.
func (cc *CloudflareChallenger) HandleTurnstileWidgetPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.URL.Query().Get("session_id")
	var session *CloudflareChallengeSession
	if sessionID != "" {
		if existing, ok := cc.GetSession(sessionID); ok {
			session = existing
		}
	}
	if session == nil {
		if sessionID == "" {
			sessionID = fmt.Sprintf("cf_ts_%d", time.Now().UnixNano())
		}
		session = cc.CreateTurnstileChallenge(sessionID, TurnstileTestingSiteKeyVisiblePass)
	}

	cfg := session.TurnstileWidget.Normalize()
	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"session_id":     session.ID,
		"callback_url":   "/api/cloudflare/turnstile/callback",
		"solve_url":      "/api/cloudflare/solve/turnstile",
		"siteverify_url": "/turnstile/v0/siteverify",
		"pow":            session.PoW,
		"widget":         cfg,
	})

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Server", "cloudflare")
	w.Header().Set("Cf-Ray", session.RayID)
	w.Header().Set("Cf-Mitigated", "challenge")
	w.Header().Set("Cache-Control", "private, max-age=0, no-store, no-cache, must-revalidate")
	http.SetCookie(w, &http.Cookie{
		Name:     "__cf_bm",
		Value:    session.CFBMValue,
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Now().Add(30 * time.Minute),
	})
	w.WriteHeader(http.StatusForbidden)

	page := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Verify you are human</title>
  <meta name="robots" content="noindex,nofollow">
  <style>
    :root {
      color-scheme: light;
      --ts-border: #d9d9d9;
      --ts-shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
      --ts-bg: #f6f8fb;
      --ts-card: #ffffff;
      --ts-text: #1f2328;
      --ts-muted: #667085;
      --ts-brand: #f38020;
      --ts-success: #0f9d58;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background:
        radial-gradient(circle at top, rgba(243,128,32,0.12), transparent 34%%),
        linear-gradient(180deg, #f8fafc 0%%, #eef2f7 100%%);
      font-family: "SF Pro Display", "Segoe UI", sans-serif;
      color: var(--ts-text);
      padding: 24px;
    }
    .ts-shell {
      width: min(100%%, 420px);
      display: grid;
      gap: 16px;
    }
    .ts-caption {
      text-align: center;
      font-size: 13px;
      color: var(--ts-muted);
      letter-spacing: 0.02em;
    }
    .cf-turnstile {
      width: 100%%;
    }
    .ts-card {
      background: var(--ts-card);
      border: 1px solid rgba(15, 23, 42, 0.08);
      border-radius: 18px;
      box-shadow: var(--ts-shadow);
      padding: 18px;
    }
    .ts-frame {
      display: grid;
      grid-template-columns: auto 1fr auto;
      gap: 14px;
      align-items: center;
      min-height: 82px;
      border: 1px solid var(--ts-border);
      border-radius: 14px;
      background: linear-gradient(180deg, #ffffff 0%%, #f8fafc 100%%);
      padding: 14px 16px;
      transition: border-color 150ms ease, box-shadow 150ms ease, transform 150ms ease;
    }
    .ts-frame[data-status="verifying"] {
      border-color: rgba(243,128,32,0.45);
      box-shadow: 0 0 0 4px rgba(243,128,32,0.10);
    }
    .ts-frame[data-status="success"] {
      border-color: rgba(15,157,88,0.35);
      box-shadow: 0 0 0 4px rgba(15,157,88,0.08);
    }
    .ts-checkbox {
      width: 32px;
      height: 32px;
      border-radius: 10px;
      border: 1px solid #b8c0cc;
      background: #fff;
      display: grid;
      place-items: center;
      cursor: pointer;
      position: relative;
      transition: transform 150ms ease, border-color 150ms ease, box-shadow 150ms ease;
    }
    .ts-checkbox:hover {
      transform: translateY(-1px);
      border-color: #8c99aa;
    }
    .ts-check {
      width: 12px;
      height: 7px;
      border-left: 2px solid transparent;
      border-bottom: 2px solid transparent;
      transform: rotate(-45deg);
      margin-top: -2px;
    }
    .ts-checkbox[data-checked="true"] .ts-check {
      border-left-color: var(--ts-success);
      border-bottom-color: var(--ts-success);
    }
    .ts-spinner {
      width: 14px;
      height: 14px;
      border-radius: 50%%;
      border: 2px solid rgba(243,128,32,0.24);
      border-top-color: var(--ts-brand);
      animation: spin 900ms linear infinite;
      display: none;
    }
    .ts-frame[data-status="verifying"] .ts-spinner {
      display: block;
    }
    .ts-frame[data-status="verifying"] .ts-check {
      display: none;
    }
    .ts-copy {
      display: grid;
      gap: 4px;
    }
    .ts-title {
      font-size: 16px;
      font-weight: 600;
    }
    .ts-state {
      font-size: 12px;
      color: var(--ts-muted);
    }
    .ts-brand {
      display: grid;
      justify-items: end;
      gap: 4px;
      font-size: 11px;
      color: var(--ts-muted);
    }
    .ts-brand strong {
      color: var(--ts-brand);
      font-size: 12px;
    }
    .ts-meta {
      display: flex;
      justify-content: space-between;
      font-size: 11px;
      color: var(--ts-muted);
      padding-top: 10px;
    }
    .ts-token {
      border-radius: 12px;
      background: rgba(15, 23, 42, 0.03);
      border: 1px dashed rgba(15, 23, 42, 0.12);
      padding: 10px 12px;
      font-size: 11px;
      color: var(--ts-muted);
      overflow-wrap: anywhere;
    }
    @media (max-width: 540px) {
      .ts-frame {
        grid-template-columns: auto 1fr;
      }
      .ts-brand {
        grid-column: 1 / -1;
        justify-items: start;
      }
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
  </style>
</head>
<body>
  <div class="ts-shell">
    <div class="ts-caption">Owned-environment Turnstile harness</div>
    <div
      id="cf-turnstile-widget"
      class="cf-turnstile"
      data-session-id="%s"
      data-mode="%s"
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
      data-response-field="%t"
      data-response-field-name="%s"
      data-token-ttl="%d">
      <div class="ts-card">
        <div id="turnstile-frame" class="ts-frame" data-status="ready">
          <button id="turnstile-checkbox" class="ts-checkbox" type="button" aria-label="Verify you are human" aria-checked="false">
            <span class="ts-spinner" aria-hidden="true"></span>
            <span class="ts-check" aria-hidden="true"></span>
          </button>
          <div class="ts-copy">
            <div class="ts-title">Verify you are human</div>
            <div id="turnstile-state" class="ts-state">Ready</div>
          </div>
          <div class="ts-brand">
            <strong>Cloudflare</strong>
            <span>Turnstile</span>
          </div>
        </div>
        <div class="ts-meta">
          <span id="turnstile-mode">Mode: %s</span>
          <span id="turnstile-expiry">TTL: %ds</span>
        </div>
      </div>
      <input id="cf-turnstile-response" name="%s" type="hidden" value="">
    </div>
    <div id="turnstile-token" class="ts-token">No token issued yet.</div>
  </div>
  <script id="turnstile-config" type="application/json">%s</script>
  <script src="/turnstile/v0/api.js?render=explicit" defer></script>
</body>
</html>`,
		session.ID,
		cfg.Mode,
		cfg.SiteKey,
		cfg.Action,
		cfg.CData,
		cfg.Theme,
		cfg.Size,
		cfg.Appearance,
		cfg.Execution,
		cfg.Retry,
		cfg.RetryIntervalMS,
		cfg.RefreshExpired,
		cfg.RefreshTimeout,
		cfg.ResponseField,
		cfg.ResponseFieldName,
		cfg.TokenTTLSeconds,
		cfg.Mode,
		cfg.TokenTTLSeconds,
		cfg.ResponseFieldName,
		string(cfgJSON),
	)

	_, _ = w.Write([]byte(page))
}

// HandleTurnstileCallback records lifecycle callbacks from the local widget.
func (cc *CloudflareChallenger) HandleTurnstileCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req turnstileCallbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	cc.RecordTurnstileCallback(req.SessionID, req.Callback, req.ErrorCode)

	session, _ := cc.GetSession(req.SessionID)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Server", "cloudflare")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":             true,
		"callback_state": session.CallbackState,
	})
}

// HandleTurnstileSiteVerify mirrors Cloudflare's siteverify endpoint for lab
// tokens. It accepts either JSON or form-encoded input.
func (cc *CloudflareChallenger) HandleTurnstileSiteVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	req, err := decodeTurnstileSiteverifyRequest(r)
	if err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	result := cc.VerifyTurnstileToken(req.Secret, req.Response, "")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Server", "cloudflare")
	_ = json.NewEncoder(w).Encode(result)
}

// HandleTurnstileAPIJS serves a small local harness implementation of the
// Turnstile browser API for browser-driven tests.
func (cc *CloudflareChallenger) HandleTurnstileAPIJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	w.Header().Set("Server", "cloudflare")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write([]byte(`
(function(){
  function readConfig() {
    var raw = document.getElementById('turnstile-config');
    return raw ? JSON.parse(raw.textContent || '{}') : {};
  }

  async function sha256Hex(input) {
    var bytes = new TextEncoder().encode(input);
    var buffer = await crypto.subtle.digest('SHA-256', bytes);
    var out = '';
    var arr = new Uint8Array(buffer);
    for (var i = 0; i < arr.length; i++) {
      out += arr[i].toString(16).padStart(2, '0');
    }
    return out;
  }

  function hasLeadingZeroBits(hex, bits) {
    var fullNibbles = Math.floor(bits / 4);
    var remain = bits % 4;
    for (var i = 0; i < fullNibbles; i++) {
      if (hex[i] !== '0') return false;
    }
    if (!remain) return true;
    var nibble = parseInt(hex[fullNibbles] || '0', 16);
    return nibble < (1 << (4 - remain));
  }

  async function solvePow(prefix, difficulty, maxIterations) {
    for (var i = 0; i < maxIterations; i++) {
      var nonce = i.toString(16).padStart(16, '0');
      var hash = await sha256Hex(prefix + nonce);
      if (hasLeadingZeroBits(hash, difficulty)) {
        return { nonce: nonce, hash: hash, iterations: i + 1, time_ms: 0 };
      }
      if (i > 0 && i % 256 === 0) {
        await new Promise(function(resolve){ setTimeout(resolve, 0); });
      }
    }
    throw new Error('pow_failed');
  }

  function collectTelemetry(state, widget, config) {
    return {
      widget_found: !!widget,
      mode: config.widget.mode,
      appearance: config.widget.appearance,
      execution: config.widget.execution,
      event_count: state.events.length,
      mouse_moves: state.events.filter(function(e){ return e.type === 'mousemove'; }).length,
      clicks: state.events.filter(function(e){ return e.type === 'click' || e.type === 'mousedown' || e.type === 'mouseup'; }).length,
      key_presses: state.events.filter(function(e){ return e.type.indexOf('key') === 0; }).length,
      scrolls: state.events.filter(function(e){ return e.type === 'scroll' || e.type === 'wheel'; }).length,
      viewport_width: window.innerWidth,
      viewport_height: window.innerHeight,
      user_agent: navigator.userAgent,
      started_at: state.startedAt ? new Date(state.startedAt).toISOString() : '',
      completed_at: new Date().toISOString(),
      last_event_at: state.events.length ? new Date(state.events[state.events.length - 1].timestamp).toISOString() : ''
    };
  }

  function setState(label, status) {
    var frame = document.getElementById('turnstile-frame');
    var state = document.getElementById('turnstile-state');
    if (frame) frame.setAttribute('data-status', status);
    if (state) state.textContent = label;
  }

  function setToken(token) {
    var input = document.getElementById('cf-turnstile-response');
    var output = document.getElementById('turnstile-token');
    if (input) input.value = token || '';
    if (output) output.textContent = token || 'No token issued yet.';
  }

  function postCallback(config, callback, errorCode) {
    return fetch(config.callback_url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        session_id: config.session_id,
        callback: callback,
        error_code: errorCode || ''
      })
    }).catch(function(){});
  }

  function installEventCapture(state, widget) {
    ['mousemove', 'mousedown', 'mouseup', 'click', 'keydown', 'keyup', 'scroll', 'wheel'].forEach(function(type){
      window.addEventListener(type, function(event){
        state.events.push({
          type: type,
          timestamp: Date.now(),
          elapsed_ms: state.startedAt ? Date.now() - state.startedAt : 0,
          x: event.clientX || 0,
          y: event.clientY || 0,
          key: event.key || '',
          delta: event.deltaY || 0
        });
      }, { passive: true });
    });
    if (widget) {
      widget.addEventListener('mousemove', function(){});
    }
  }

  function startExpiryTimer(config, api) {
    if (!config.widget.token_ttl_seconds) return;
    window.clearTimeout(api.expiryTimer);
    api.expiryTimer = window.setTimeout(function(){
      setState('Expired', 'expired');
      setToken('');
      postCallback(config, 'expired');
      if (config.widget.refresh_expired === 'auto') {
        api.reset();
      }
    }, config.widget.token_ttl_seconds * 1000);
  }

  window.turnstile = {
    widgets: new Map(),
    render: function(selector) {
      var widget = typeof selector === 'string' ? document.querySelector(selector) : selector;
      var config = readConfig();
      var state = { events: [], startedAt: null, running: false };
      installEventCapture(state, widget);
      var api = {
        expiryTimer: null,
        getResponse: function() {
          var input = document.getElementById('cf-turnstile-response');
          return input ? input.value : '';
        },
        reset: function() {
          state.running = false;
          state.startedAt = null;
          setToken('');
          setState('Ready', 'ready');
          var checkbox = document.getElementById('turnstile-checkbox');
          if (checkbox) checkbox.setAttribute('data-checked', 'false');
          postCallback(config, 'reset');
        },
        execute: async function() {
          if (state.running) return api.getResponse();
          state.running = true;
          state.startedAt = Date.now();
          setState('Verifying…', 'verifying');
          postCallback(config, 'execute');
          try {
            var started = Date.now();
            var pow = await solvePow(config.pow.prefix, config.pow.difficulty, config.pow.max_iterations || 200000);
            pow.time_ms = Date.now() - started;
            var resp = await fetch(config.solve_url, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                session_id: config.session_id,
                solution: pow,
                events: state.events,
                telemetry: collectTelemetry(state, widget, config)
              })
            });
            var data = await resp.json();
            if (!resp.ok || !data.success) {
              throw new Error(data.error || 'solve_failed');
            }
            setToken(data.turnstile_token);
            var checkbox = document.getElementById('turnstile-checkbox');
            if (checkbox) checkbox.setAttribute('data-checked', 'true');
            setState('Verification complete', 'success');
            postCallback(config, 'success');
            startExpiryTimer(config, api);
            state.running = false;
            return data.turnstile_token;
          } catch (err) {
            setState('Verification failed', 'error');
            postCallback(config, 'error', err.message || 'solve_failed');
            state.running = false;
            if (config.widget.retry === 'auto') {
              window.setTimeout(function(){ api.reset(); }, config.widget.retry_interval_ms || 800);
            }
            throw err;
          }
        }
      };

      postCallback(config, 'render');
      window.turnstile.widgets.set(widget, api);

      var checkbox = document.getElementById('turnstile-checkbox');
      if (checkbox) {
        checkbox.addEventListener('click', function() {
          api.execute().catch(function(){});
        });
      }

      if (config.widget.execution === 'execute' || config.widget.size === 'invisible') {
        window.setTimeout(function(){ api.execute().catch(function(){}); }, 50);
      } else {
        setState('Ready', 'ready');
      }

      return widget ? widget.id || 'cf-turnstile-widget' : 'cf-turnstile-widget';
    },
    execute: function(selector) {
      var widget = typeof selector === 'string' ? document.querySelector(selector) : selector;
      var api = window.turnstile.widgets.get(widget);
      return api ? api.execute() : Promise.reject(new Error('widget_not_found'));
    },
    reset: function(selector) {
      var widget = typeof selector === 'string' ? document.querySelector(selector) : selector;
      var api = window.turnstile.widgets.get(widget);
      if (api) api.reset();
    },
    getResponse: function(selector) {
      var widget = typeof selector === 'string' ? document.querySelector(selector) : selector;
      var api = window.turnstile.widgets.get(widget);
      return api ? api.getResponse() : '';
    }
  };

  window.addEventListener('DOMContentLoaded', function(){
    var widget = document.getElementById('cf-turnstile-widget');
    if (widget) {
      window.turnstile.render(widget);
    }
  });
})();
`))
}

func decodeTurnstileSiteverifyRequest(r *http.Request) (*turnstileSiteverifyRequest, error) {
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		var req turnstileSiteverifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, err
		}
		return &req, nil
	}

	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	return &turnstileSiteverifyRequest{
		Secret:   formValue(r.Form, "secret"),
		Response: formValue(r.Form, "response"),
		RemoteIP: formValue(r.Form, "remoteip"),
	}, nil
}

func formValue(values url.Values, key string) string {
	if values == nil {
		return ""
	}
	return values.Get(key)
}
