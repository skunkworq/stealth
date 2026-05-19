package tracing

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"sync"
	"time"
)

// TraceLabServer serves interactive challenge pages and records human traces.
type TraceLabServer struct {
	mu       sync.Mutex
	recorder *TraceRecorder
	library  *TraceLibrary
	metrics  *SolveMetricsTracker
	session  *TraceSession // current active session
}

// NewTraceLabServer creates a trace lab server.
func NewTraceLabServer(dataDir string) *TraceLabServer {
	absDir, _ := filepath.Abs(dataDir)
	lib := NewTraceLibrary(absDir)
	_ = lib.LoadAll()

	return &TraceLabServer{
		recorder: NewTraceRecorder(absDir),
		library:  lib,
		metrics:  NewSolveMetricsTracker(),
	}
}

// MountRoutes registers the trace lab API routes.
func (tls *TraceLabServer) MountRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/trace/lab", tls.HandleLabPage)
	mux.HandleFunc("/api/trace/start", tls.HandleStartSession)
	mux.HandleFunc("/api/trace/record", tls.HandleRecordEvents)
	mux.HandleFunc("/api/trace/complete", tls.HandleComplete)
	mux.HandleFunc("/api/trace/status", tls.HandleStatus)
	mux.HandleFunc("/api/trace/end", tls.HandleEndSession)
}

// HandleEndSession ends the current session and flushes traces to disk.
func (tls *TraceLabServer) HandleEndSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	tls.mu.Lock()
	defer tls.mu.Unlock()

	if tls.session == nil {
		http.Error(w, "no active session", http.StatusBadRequest)
		return
	}

	session, err := tls.recorder.EndSession(tls.session.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tls.session = nil

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"session_id": session.ID,
		"recordings": len(session.Recordings),
		"saved_to":   filepath.Join("traces", session.ID),
	})
}

// HandleStartSession starts a recording session and returns the session/recording IDs.
func (tls *TraceLabServer) HandleStartSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Operator         string `json:"operator"`
		ChallengeType    string `json:"challenge_type"`
		ChallengeVariant string `json:"challenge_variant"`
		SiteURL          string `json:"site_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	tls.mu.Lock()
	defer tls.mu.Unlock()

	if tls.session == nil {
		env := TraceEnvironment{
			UserAgent: r.UserAgent(),
			Timezone:  r.Header.Get("X-Timezone"),
		}
		tls.session = tls.recorder.StartSession(req.Operator, env)
	}

	rec, err := tls.recorder.StartRecording(
		tls.session.ID,
		req.ChallengeType,
		req.ChallengeVariant,
		req.SiteURL,
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"session_id":   tls.session.ID,
		"recording_id": rec.ID,
	})
}

// HandleRecordEvents receives a batch of events from the browser.
func (tls *TraceLabServer) HandleRecordEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		SessionID   string         `json:"session_id"`
		RecordingID string         `json:"recording_id"`
		Events      []CaptchaEvent `json:"events"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if err := tls.recorder.RecordEvents(req.SessionID, req.RecordingID, req.Events); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int{"accepted": len(req.Events)})
}

// HandleComplete finalizes a recording and returns metrics.
func (tls *TraceLabServer) HandleComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		SessionID   string `json:"session_id"`
		RecordingID string `json:"recording_id"`
		Solved      bool   `json:"solved"`
		EndSession  bool   `json:"end_session"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	rec, err := tls.recorder.CompleteRecording(req.SessionID, req.RecordingID, req.Solved)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Add to library and metrics
	tls.library.Add(rec)
	tls.metrics.RecordFromValidation(
		rec.ChallengeType, rec.ChallengeVariant, "human",
		req.Solved, rec.DurationMs, rec.Metrics.TotalEvents, nil, 1.0,
	)

	if req.EndSession {
		tls.mu.Lock()
		if tls.session != nil {
			_, _ = tls.recorder.EndSession(tls.session.ID)
			tls.session = nil
		}
		tls.mu.Unlock()
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"recording_id": rec.ID,
		"solved":       rec.Solved,
		"duration_ms":  rec.DurationMs,
		"metrics":      rec.Metrics,
		"fingerprint":  TraceFingerprint(rec),
	})
}

// HandleStatus returns library and metrics summary.
func (tls *TraceLabServer) HandleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"library": tls.library.Summary(),
		"metrics": tls.metrics.Report(),
		"session": tls.session != nil,
	})
}

// HandleLabPage serves an interactive challenge page with full event capture.
func (tls *TraceLabServer) HandleLabPage(w http.ResponseWriter, r *http.Request) {
	challengeType := r.URL.Query().Get("type")
	if challengeType == "" {
		challengeType = "rotate"
	}

	w.Header().Set("Content-Type", "text/html")
	_, _ = fmt.Fprintf(w, traceLabHTML, challengeType, time.Now().UnixMilli())
}

var traceLabHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Captcha Trace Lab</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;background:#0f172a;color:#e2e8f0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,monospace}
.lab{width:min(520px,94vw);padding:32px;background:#1e293b;border:1px solid #334155;border-radius:16px;box-shadow:0 25px 50px rgba(0,0,0,.4)}
h1{font-size:20px;margin-bottom:8px;color:#f8fafc}
.subtitle{font-size:13px;color:#94a3b8;margin-bottom:24px}
.challenge-area{position:relative;width:100%%;height:320px;background:#0f172a;border:1px solid #334155;border-radius:12px;margin-bottom:20px;overflow:hidden;cursor:crosshair}
.controls{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap}
.btn{padding:10px 20px;border:1px solid #475569;border-radius:8px;background:#1e293b;color:#e2e8f0;font-size:13px;font-weight:600;cursor:pointer;transition:all .15s}
.btn:hover{background:#334155;border-color:#60a5fa}
.btn:disabled{opacity:.4;cursor:default}
.btn.primary{background:#2563eb;border-color:#3b82f6;color:#fff}
.btn.primary:hover{background:#1d4ed8}
.btn.success{background:#16a34a;border-color:#22c55e;color:#fff}
.status{padding:12px 16px;background:#0f172a;border:1px solid #334155;border-radius:8px;font-size:12px;line-height:1.6;max-height:260px;overflow-y:auto}
.status .label{color:#94a3b8}
.status .value{color:#60a5fa;font-weight:600}
.status .good{color:#4ade80}
.status .warn{color:#fbbf24}
.tabs{display:flex;gap:4px;margin-bottom:16px}
.tab{padding:8px 16px;border:1px solid #334155;border-radius:8px 8px 0 0;background:transparent;color:#94a3b8;font-size:12px;cursor:pointer;font-weight:600}
.tab.active{background:#334155;color:#f8fafc;border-bottom-color:#334155}
svg text{user-select:none}
</style>
</head>
<body>
<div class="lab">
  <h1>Captcha Trace Lab</h1>
  <p class="subtitle">Solve the challenge below. Every mouse/key event is recorded for trace analysis.</p>

  <div class="tabs">
    <button class="tab active" data-type="rotate" onclick="switchChallenge('rotate')">Rotate</button>
    <button class="tab" data-type="slide" onclick="switchChallenge('slide')">Slide Puzzle</button>
    <button class="tab" data-type="drag" onclick="switchChallenge('drag')">Drag</button>
    <button class="tab" data-type="orient3d" onclick="switchChallenge('orient3d')">3D Orient</button>
    <button class="tab" data-type="orientlr" onclick="switchChallenge('orientlr')">L/R Orient</button>
  </div>

  <div class="challenge-area" id="challenge-area"></div>

  <div class="controls">
    <button class="btn primary" id="btn-start" onclick="startRecording()">Start Recording</button>
    <button class="btn success" id="btn-complete" onclick="completeRecording()" disabled>Mark Solved</button>
    <button class="btn" onclick="resetChallenge()">Reset</button>
  </div>

  <div class="status" id="status">
    <div><span class="label">Status:</span> <span class="value" id="s-status">Ready — click Start Recording, then solve the challenge</span></div>
    <div><span class="label">Events:</span> <span class="value" id="s-events">0</span></div>
    <div><span class="label">Duration:</span> <span class="value" id="s-duration">0ms</span></div>
    <div><span class="label">Mouse moves:</span> <span class="value" id="s-moves">0</span></div>
    <div><span class="label">Clicks:</span> <span class="value" id="s-clicks">0</span></div>
  </div>
</div>

<script>
const CHALLENGE_TYPE = "%s";
const PAGE_LOAD = %d;
let currentType = CHALLENGE_TYPE;
let recording = false;
let events = [];
let startTime = 0;
let sessionId = null;
let recordingId = null;
let flushTimer = null;

const area = document.getElementById('challenge-area');

function captureEvent(type, e) {
  if (!recording) return;
  const rect = area.getBoundingClientRect();
  const ev = {
    type: type,
    elapsed_ms: Date.now() - startTime,
    x: e.clientX !== undefined ? e.clientX - rect.left : 0,
    y: e.clientY !== undefined ? e.clientY - rect.top : 0
  };
  if (e.key) ev.key = e.key;
  if (e.deltaY) ev.delta = e.deltaY;
  events.push(ev);
  updateStatus();
}

area.addEventListener('mousemove', e => captureEvent('mousemove', e));
area.addEventListener('mousedown', e => captureEvent('mousedown', e));
area.addEventListener('mouseup', e => captureEvent('mouseup', e));
area.addEventListener('click', e => captureEvent('click', e));
document.addEventListener('keydown', e => captureEvent('keydown', e));
area.addEventListener('wheel', e => captureEvent('scroll', e), {passive: true});

function updateStatus() {
  const moves = events.filter(e => e.type === 'mousemove').length;
  const clicks = events.filter(e => e.type === 'click' || e.type === 'mousedown').length;
  const dur = events.length > 0 ? events[events.length-1].elapsed_ms : 0;
  document.getElementById('s-events').textContent = events.length;
  document.getElementById('s-duration').textContent = dur + 'ms';
  document.getElementById('s-moves').textContent = moves;
  document.getElementById('s-clicks').textContent = clicks;
}

async function flushEvents() {
  if (!sessionId || !recordingId || events.length === 0) return;
  const batch = events.splice(0);
  try {
    await fetch('/api/trace/record', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({session_id: sessionId, recording_id: recordingId, events: batch})
    });
  } catch(e) {
    events.unshift(...batch);
  }
}

async function startRecording() {
  const resp = await fetch('/api/trace/start', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      operator: 'ben',
      challenge_type: 'turnstile',
      challenge_variant: currentType,
      site_url: location.href
    })
  });
  const data = await resp.json();
  sessionId = data.session_id;
  recordingId = data.recording_id;
  recording = true;
  startTime = Date.now();
  events = [];
  document.getElementById('btn-start').disabled = true;
  document.getElementById('btn-complete').disabled = false;
  document.getElementById('s-status').textContent = 'RECORDING — solve the challenge now';
  document.getElementById('s-status').className = 'value warn';
  flushTimer = setInterval(flushEvents, 2000);
}

async function completeRecording() {
  recording = false;
  clearInterval(flushTimer);
  await flushEvents();
  const resp = await fetch('/api/trace/complete', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      session_id: sessionId,
      recording_id: recordingId,
      solved: true,
      end_session: false
    })
  });
  const data = await resp.json();
  document.getElementById('s-status').textContent = 'SAVED — trace recorded';
  document.getElementById('s-status').className = 'value good';
  document.getElementById('btn-start').disabled = false;
  document.getElementById('btn-complete').disabled = true;

  const m = data.metrics || {};
  const statusEl = document.getElementById('status');
  statusEl.innerHTML += '<div style="margin-top:8px;border-top:1px solid #334155;padding-top:8px">' +
    '<div><span class="label">Fingerprint:</span> <span class="value">' + (data.fingerprint||'') + '</span></div>' +
    '<div><span class="label">Avg velocity:</span> <span class="value">' + (m.avg_mouse_velocity||0).toFixed(0) + ' px/s</span></div>' +
    '<div><span class="label">Max velocity:</span> <span class="value">' + (m.max_mouse_velocity||0).toFixed(0) + ' px/s</span></div>' +
    '<div><span class="label">Straightness:</span> <span class="value">' + (m.straightness||0).toFixed(3) + '</span></div>' +
    '<div><span class="label">Direction changes:</span> <span class="value">' + (m.direction_changes||0) + '</span></div>' +
    '<div><span class="label">Y variance:</span> <span class="value">' + (m.y_variance||0).toFixed(1) + ' px</span></div>' +
    '<div><span class="label">Hesitations:</span> <span class="value">' + (m.hesitations||0) + '</span></div>' +
    '<div><span class="label">Pauses:</span> <span class="value">' + (m.pauses||0) + '</span></div>' +
    '</div>';
}

function switchChallenge(type) {
  currentType = type;
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.type === type));
  resetChallenge();
}

function resetChallenge() {
  events = [];
  updateStatus();
  switch(currentType) {
    case 'rotate': renderRotate(); break;
    case 'slide': renderSlide(); break;
    case 'drag': renderDrag(); break;
    case 'orient3d': renderOrient3D(); break;
    case 'orientlr': renderOrientLR(); break;
  }
}

function renderRotate() {
  const cx = 230, cy = 150, r = 100;
  const targetDeg = 200 + Math.floor(Math.random() * 120);
  const targetRad = targetDeg * Math.PI / 180;
  const tolDeg = 15;

  area.innerHTML =
    '<svg width="460" height="300" viewBox="0 0 460 300" style="position:absolute;top:0;left:50%%;transform:translateX(-50%%)">' +
    '<circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="none" stroke="#334155" stroke-width="3"/>' +
    '<path id="dial-target" fill="none" stroke="#f59e0b" stroke-width="4" stroke-linecap="round" opacity=".6"/>' +
    '<polygon id="dial-arrow" fill="#f59e0b" opacity=".7"/>' +
    '<circle id="dial-handle" cx="'+(cx+r)+'" cy="'+cy+'" r="14" fill="#3b82f6" style="cursor:grab;filter:drop-shadow(0 2px 4px rgba(0,0,0,.3))"/>' +
    '<text x="'+cx+'" y="28" fill="#94a3b8" font-size="13" text-anchor="middle">Rotate to the yellow marker ('+targetDeg+'°)</text>' +
    '<text id="dial-angle" x="'+cx+'" y="'+cy+'" fill="#e2e8f0" font-size="16" text-anchor="middle" dominant-baseline="middle">0°</text>' +
    '</svg>';

  const arcS = (targetDeg - tolDeg) * Math.PI / 180;
  const arcE = (targetDeg + tolDeg) * Math.PI / 180;
  const rr = r + 20;
  document.getElementById('dial-target').setAttribute('d',
    'M '+(cx+rr*Math.cos(arcS))+' '+(cy+rr*Math.sin(arcS))+' A '+rr+' '+rr+' 0 0 1 '+(cx+rr*Math.cos(arcE))+' '+(cy+rr*Math.sin(arcE)));
  const ax = cx + (r+30)*Math.cos(targetRad), ay = cy + (r+30)*Math.sin(targetRad);
  const dx = Math.cos(targetRad), dy = Math.sin(targetRad);
  document.getElementById('dial-arrow').setAttribute('points',
    (ax+dx*10)+','+(ay+dy*10)+' '+(ax-dy*6)+','+(ay+dx*6)+' '+(ax+dy*6)+','+(ay-dx*6));

  const handle = document.getElementById('dial-handle');
  const angleText = document.getElementById('dial-angle');
  let dragging = false;
  let currentAngle = 0;

  function setAngle(deg) {
    currentAngle = ((deg %% 360) + 360) %% 360;
    const rad = currentAngle * Math.PI / 180;
    handle.setAttribute('cx', cx + r * Math.cos(rad));
    handle.setAttribute('cy', cy + r * Math.sin(rad));
    angleText.textContent = Math.round(currentAngle) + '°';
    let diff = ((currentAngle - targetDeg) %% 360 + 360) %% 360;
    if (diff > 180) diff = 360 - diff;
    handle.setAttribute('fill', diff <= tolDeg ? '#4ade80' : '#3b82f6');
    angleText.setAttribute('fill', diff <= tolDeg ? '#4ade80' : '#e2e8f0');
  }

  handle.addEventListener('mousedown', e => { e.preventDefault(); dragging = true; });
  area.addEventListener('mousemove', e => {
    if (!dragging) return;
    const rect = area.querySelector('svg').getBoundingClientRect();
    const svgCx = rect.left + rect.width/2;
    const svgCy = rect.top + rect.height * (150/300);
    setAngle(Math.atan2(e.clientY - svgCy, e.clientX - svgCx) * 180 / Math.PI);
  });
  window.addEventListener('mouseup', () => { dragging = false; });
}

function renderSlide() {
  const trackW = area.clientWidth - 48;
  const targetX = 120 + Math.floor(Math.random() * (trackW - 200));
  const tolPx = 10;

  area.innerHTML =
    '<div style="position:absolute;top:24px;left:24px;right:24px;font-size:13px;color:#94a3b8">Slide the piece to the yellow zone</div>' +
    '<div style="position:absolute;top:50%%;left:24px;right:24px;height:12px;background:#334155;border-radius:999px;transform:translateY(-50%%)">' +
    '<div id="slide-fill" style="position:absolute;height:100%%;background:#3b82f6;border-radius:999px;width:0"></div>' +
    '<div id="slide-target" style="position:absolute;top:-6px;height:24px;border:2px dashed #f59e0b;border-radius:4px;background:rgba(245,158,11,.1);left:'+(targetX-tolPx)+'px;width:'+(tolPx*2)+'px"></div>' +
    '</div>' +
    '<div id="slide-piece" style="position:absolute;top:50%%;left:24px;width:44px;height:44px;background:#3b82f6;border:2px solid #60a5fa;border-radius:8px;transform:translateY(-50%%);cursor:grab;display:flex;align-items:center;justify-content:center;font-size:18px;box-shadow:0 4px 12px rgba(0,0,0,.3)">⬛</div>' +
    '<div style="position:absolute;bottom:24px;left:24px;font-size:12px;color:#64748b">Target: '+targetX+'px ±'+tolPx+'px</div>';

  const piece = document.getElementById('slide-piece');
  const fill = document.getElementById('slide-fill');
  let dragging = false, originX = 0, offsetX = 0;

  piece.addEventListener('mousedown', e => { e.preventDefault(); dragging = true; originX = e.clientX - offsetX; });
  area.addEventListener('mousemove', e => {
    if (!dragging) return;
    offsetX = Math.max(0, Math.min(trackW - 44, e.clientX - originX));
    piece.style.left = (24 + offsetX) + 'px';
    fill.style.width = offsetX + 'px';
    const diff = Math.abs(offsetX - targetX);
    piece.style.background = diff <= tolPx ? '#16a34a' : '#3b82f6';
    piece.style.borderColor = diff <= tolPx ? '#4ade80' : '#60a5fa';
  });
  window.addEventListener('mouseup', () => { dragging = false; });
}

function renderDrag() {
  const trackW = area.clientWidth - 48;
  const requiredDist = Math.floor(trackW * 0.75);

  area.innerHTML =
    '<div style="position:absolute;top:24px;left:24px;right:24px;font-size:13px;color:#94a3b8">Drag the handle to the end ('+requiredDist+'px)</div>' +
    '<div style="position:absolute;top:50%%;left:24px;right:24px;height:12px;background:#334155;border-radius:999px;transform:translateY(-50%%)">' +
    '<div id="drag-fill" style="position:absolute;height:100%%;background:#3b82f6;border-radius:999px;width:0"></div>' +
    '</div>' +
    '<div id="drag-handle" style="position:absolute;top:50%%;left:24px;width:36px;height:36px;background:#3b82f6;border:2px solid #60a5fa;border-radius:50%%;transform:translateY(-50%%);cursor:grab;display:flex;align-items:center;justify-content:center;font-size:16px;box-shadow:0 4px 12px rgba(0,0,0,.3)">→</div>' +
    '<div style="position:absolute;bottom:24px;left:24px;font-size:12px;color:#64748b">Required: '+requiredDist+'px</div>';

  const handle = document.getElementById('drag-handle');
  const fill = document.getElementById('drag-fill');
  let dragging = false, originX = 0, offsetX = 0;

  handle.addEventListener('mousedown', e => { e.preventDefault(); dragging = true; originX = e.clientX - offsetX; });
  area.addEventListener('mousemove', e => {
    if (!dragging) return;
    offsetX = Math.max(0, Math.min(trackW - 36, e.clientX - originX));
    handle.style.left = (24 + offsetX) + 'px';
    fill.style.width = offsetX + 'px';
    const done = offsetX >= requiredDist;
    handle.style.background = done ? '#16a34a' : '#3b82f6';
    fill.style.background = done ? '#16a34a' : '#3b82f6';
  });
  window.addEventListener('mouseup', () => { dragging = false; });
}

function renderOrient3D() {
  const targetY = Math.floor(Math.random() * 300) + 30; // target Y rotation 30-330 deg
  const targetX = Math.floor(Math.random() * 40) - 20;  // slight X tilt -20 to +20
  const tolDeg = 20;
  let currentY = 0;
  let currentX = 0;

  const faceColors = ['#3b82f6','#ef4444','#22c55e','#f59e0b','#8b5cf6','#ec4899'];
  const faceLabels = ['Front','Back','Right','Left','Top','Bottom'];

  area.innerHTML =
    '<div style="position:absolute;top:16px;left:0;right:0;text-align:center;font-size:13px;color:#94a3b8">' +
      'Use the buttons to match the target orientation</div>' +
    '<div style="position:absolute;top:44px;left:0;right:0;display:flex;justify-content:center;gap:24px;align-items:center">' +
      '<div style="text-align:center"><div style="font-size:11px;color:#64748b;margin-bottom:6px">TARGET</div>' +
        '<div id="orient-target" style="width:80px;height:80px;perspective:200px;margin:0 auto">' +
          '<div id="target-cube" style="width:80px;height:80px;position:relative;transform-style:preserve-3d;transform:rotateX('+targetX+'deg) rotateY('+targetY+'deg)"></div>' +
        '</div>' +
        '<div style="font-size:11px;color:#f59e0b;margin-top:6px">Y:'+targetY+'° X:'+targetX+'°</div>' +
      '</div>' +
      '<div style="font-size:24px;color:#475569">→</div>' +
      '<div style="text-align:center"><div style="font-size:11px;color:#64748b;margin-bottom:6px">YOUR OBJECT</div>' +
        '<div style="width:120px;height:120px;perspective:300px;margin:0 auto">' +
          '<div id="orient-cube" style="width:120px;height:120px;position:relative;transform-style:preserve-3d;transition:transform 0.15s ease-out"></div>' +
        '</div>' +
        '<div id="orient-angle" style="font-size:12px;color:#94a3b8;margin-top:6px">Y:0° X:0°</div>' +
      '</div>' +
    '</div>' +
    '<div style="position:absolute;bottom:80px;left:0;right:0;display:flex;justify-content:center;gap:12px">' +
      '<button id="btn-up" class="btn" style="font-size:18px;width:48px;padding:8px 0" onclick="orient3DMove(\'up\')">↑</button>' +
    '</div>' +
    '<div style="position:absolute;bottom:36px;left:0;right:0;display:flex;justify-content:center;gap:12px">' +
      '<button id="btn-left" class="btn" style="font-size:18px;width:48px;padding:8px 0" onclick="orient3DMove(\'left\')">←</button>' +
      '<button id="btn-down" class="btn" style="font-size:18px;width:48px;padding:8px 0" onclick="orient3DMove(\'down\')">↓</button>' +
      '<button id="btn-right" class="btn" style="font-size:18px;width:48px;padding:8px 0" onclick="orient3DMove(\'right\')">→</button>' +
    '</div>' +
    '<div id="orient-match" style="position:absolute;top:16px;right:16px;font-size:12px;font-weight:600;color:#64748b;display:none;padding:6px 10px;border-radius:6px;border:1px solid transparent"></div>';

  // Build cube faces (6 faces for both target and user cube)
  function buildCube(container, size) {
    const half = size / 2;
    const faces = [
      {transform:'translateZ('+half+'px)',                   bg:faceColors[0], label:faceLabels[0]},
      {transform:'rotateY(180deg) translateZ('+half+'px)',   bg:faceColors[1], label:faceLabels[1]},
      {transform:'rotateY(90deg) translateZ('+half+'px)',    bg:faceColors[2], label:faceLabels[2]},
      {transform:'rotateY(-90deg) translateZ('+half+'px)',   bg:faceColors[3], label:faceLabels[3]},
      {transform:'rotateX(90deg) translateZ('+half+'px)',    bg:faceColors[4], label:faceLabels[4]},
      {transform:'rotateX(-90deg) translateZ('+half+'px)',   bg:faceColors[5], label:faceLabels[5]},
    ];
    let html = '';
    faces.forEach(f => {
      html += '<div style="position:absolute;width:'+size+'px;height:'+size+'px;' +
        'background:'+f.bg+';opacity:0.85;border:2px solid rgba(255,255,255,0.3);' +
        'display:flex;align-items:center;justify-content:center;font-size:'+(size<100?10:14)+'px;' +
        'color:rgba(255,255,255,0.8);font-weight:600;backface-visibility:visible;' +
        'transform:'+f.transform+'">'+f.label+'</div>';
    });
    container.innerHTML = html;
  }

  buildCube(document.getElementById('target-cube'), 80);
  buildCube(document.getElementById('orient-cube'), 120);

  const cube = document.getElementById('orient-cube');
  const angleLabel = document.getElementById('orient-angle');
  const matchLabel = document.getElementById('orient-match');

  function updateCube() {
    cube.style.transform = 'rotateX('+currentX+'deg) rotateY('+currentY+'deg)';
    angleLabel.textContent = 'Y:'+currentY+'° X:'+currentX+'°';

    let diffY = ((currentY - targetY) %% 360 + 360) %% 360;
    if (diffY > 180) diffY = 360 - diffY;
    let diffX = Math.abs(currentX - targetX);
    const matched = diffY <= tolDeg && diffX <= tolDeg;

    matchLabel.style.display = 'block';
    if (matched) {
      matchLabel.textContent = 'MATCHED';
      matchLabel.style.color = '#4ade80';
      matchLabel.style.borderColor = '#4ade80';
    } else {
      const totalOff = diffY + diffX;
      matchLabel.textContent = totalOff + '° off';
      matchLabel.style.color = totalOff < 60 ? '#fbbf24' : '#64748b';
      matchLabel.style.borderColor = totalOff < 60 ? '#fbbf24' : '#334155';
    }
  }
  updateCube();

  // Expose to global scope for button onclick
  window.orient3DMove = function(dir) {
    const step = 15;
    switch(dir) {
      case 'left':  currentY = ((currentY - step) %% 360 + 360) %% 360; break;
      case 'right': currentY = ((currentY + step) %% 360 + 360) %% 360; break;
      case 'up':    currentX = Math.max(-90, currentX - step); break;
      case 'down':  currentX = Math.min(90, currentX + step); break;
    }
    updateCube();
  };

  // Keyboard support
  area.setAttribute('tabindex', '0');
  area.focus();
  area._orient3DKeyHandler = function(e) {
    if (currentType !== 'orient3d') return;
    switch(e.key) {
      case 'ArrowLeft':  e.preventDefault(); orient3DMove('left'); break;
      case 'ArrowRight': e.preventDefault(); orient3DMove('right'); break;
      case 'ArrowUp':    e.preventDefault(); orient3DMove('up'); break;
      case 'ArrowDown':  e.preventDefault(); orient3DMove('down'); break;
    }
  };
  document.removeEventListener('keydown', area._orient3DKeyHandler);
  document.addEventListener('keydown', area._orient3DKeyHandler);
}

function renderOrientLR() {
  const targetY = (Math.floor(Math.random() * 22) + 2) * 15; // 30-345 in 15° steps
  const tolDeg = 20;
  let currentY = 0;

  const faceColors = ['#3b82f6','#ef4444','#22c55e','#f59e0b','#8b5cf6','#ec4899'];
  const faceLabels = ['F','B','R','L','T','Bo'];

  area.innerHTML =
    '<div style="position:absolute;top:16px;left:0;right:0;text-align:center;font-size:13px;color:#94a3b8">' +
      'Click Left / Right to rotate the object to match the target</div>' +
    '<div style="position:absolute;top:52px;left:0;right:0;display:flex;justify-content:center;gap:32px;align-items:center">' +
      '<div style="text-align:center"><div style="font-size:11px;color:#64748b;margin-bottom:6px">TARGET</div>' +
        '<div style="width:90px;height:90px;perspective:220px;margin:0 auto">' +
          '<div id="lr-target-cube" style="width:90px;height:90px;position:relative;transform-style:preserve-3d;transform:rotateX(-10deg) rotateY('+targetY+'deg)"></div>' +
        '</div>' +
        '<div style="font-size:11px;color:#f59e0b;margin-top:6px">'+targetY+'°</div>' +
      '</div>' +
      '<div style="font-size:24px;color:#475569">→</div>' +
      '<div style="text-align:center"><div style="font-size:11px;color:#64748b;margin-bottom:6px">YOUR OBJECT</div>' +
        '<div style="width:130px;height:130px;perspective:320px;margin:0 auto">' +
          '<div id="lr-cube" style="width:130px;height:130px;position:relative;transform-style:preserve-3d;transition:transform 0.15s ease-out"></div>' +
        '</div>' +
        '<div id="lr-angle" style="font-size:13px;color:#94a3b8;margin-top:6px">0°</div>' +
      '</div>' +
    '</div>' +
    '<div style="position:absolute;bottom:40px;left:0;right:0;display:flex;justify-content:center;gap:16px;align-items:center">' +
      '<button id="btn-lr-left" class="btn" style="font-size:22px;width:64px;height:52px;padding:0" onclick="orientLRMove(-1)">←</button>' +
      '<div id="lr-match" style="min-width:80px;text-align:center;font-size:13px;font-weight:600;color:#64748b"></div>' +
      '<button id="btn-lr-right" class="btn" style="font-size:22px;width:64px;height:52px;padding:0" onclick="orientLRMove(1)">→</button>' +
    '</div>';

  function buildCube(container, size) {
    const half = size / 2;
    const faces = [
      {transform:'translateZ('+half+'px)',                   bg:faceColors[0], label:faceLabels[0]},
      {transform:'rotateY(180deg) translateZ('+half+'px)',   bg:faceColors[1], label:faceLabels[1]},
      {transform:'rotateY(90deg) translateZ('+half+'px)',    bg:faceColors[2], label:faceLabels[2]},
      {transform:'rotateY(-90deg) translateZ('+half+'px)',   bg:faceColors[3], label:faceLabels[3]},
      {transform:'rotateX(90deg) translateZ('+half+'px)',    bg:faceColors[4], label:faceLabels[4]},
      {transform:'rotateX(-90deg) translateZ('+half+'px)',   bg:faceColors[5], label:faceLabels[5]},
    ];
    let html = '';
    faces.forEach(f => {
      html += '<div style="position:absolute;width:'+size+'px;height:'+size+'px;' +
        'background:'+f.bg+';opacity:0.85;border:2px solid rgba(255,255,255,0.3);' +
        'display:flex;align-items:center;justify-content:center;font-size:'+(size<100?11:15)+'px;' +
        'color:rgba(255,255,255,0.8);font-weight:600;backface-visibility:visible;' +
        'transform:'+f.transform+'">'+f.label+'</div>';
    });
    container.innerHTML = html;
  }

  buildCube(document.getElementById('lr-target-cube'), 90);
  buildCube(document.getElementById('lr-cube'), 130);

  const cube = document.getElementById('lr-cube');
  const angleLabel = document.getElementById('lr-angle');
  const matchLabel = document.getElementById('lr-match');

  function updateCube() {
    cube.style.transform = 'rotateX(-10deg) rotateY('+currentY+'deg)';
    angleLabel.textContent = currentY + '°';

    let diff = ((currentY - targetY) %% 360 + 360) %% 360;
    if (diff > 180) diff = 360 - diff;
    if (diff <= tolDeg) {
      matchLabel.textContent = 'MATCHED';
      matchLabel.style.color = '#4ade80';
    } else {
      matchLabel.textContent = diff + '° off';
      matchLabel.style.color = diff < 45 ? '#fbbf24' : '#64748b';
    }
  }
  updateCube();

  window.orientLRMove = function(dir) {
    currentY = ((currentY + dir * 15) %% 360 + 360) %% 360;
    updateCube();
  };

  // Keyboard
  area.setAttribute('tabindex', '0');
  area.focus();
  area._orientLRKeyHandler = function(e) {
    if (currentType !== 'orientlr') return;
    if (e.key === 'ArrowLeft')  { e.preventDefault(); orientLRMove(-1); }
    if (e.key === 'ArrowRight') { e.preventDefault(); orientLRMove(1); }
  };
  document.removeEventListener('keydown', area._orientLRKeyHandler);
  document.addEventListener('keydown', area._orientLRKeyHandler);
}

resetChallenge();
</script>
</body>
</html>`
