package challenge

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func humanLikeTurnstileEvents() []CaptchaEvent {
	base := time.Now().UnixMilli()
	return []CaptchaEvent{
		{Type: "mousemove", Timestamp: base + 0, X: 118, Y: 266},
		{Type: "mousemove", Timestamp: base + 94, X: 137, Y: 258},
		{Type: "mousemove", Timestamp: base + 213, X: 161, Y: 244},
		{Type: "mousemove", Timestamp: base + 371, X: 186, Y: 223},
		{Type: "mousemove", Timestamp: base + 522, X: 214, Y: 202},
		{Type: "mousemove", Timestamp: base + 705, X: 242, Y: 186},
		{Type: "mousemove", Timestamp: base + 881, X: 269, Y: 179},
		{Type: "wheel", Timestamp: base + 1048, Delta: 114},
		{Type: "wheel", Timestamp: base + 1235, Delta: 78},
		{Type: "mousemove", Timestamp: base + 1412, X: 294, Y: 173},
		{Type: "mousedown", Timestamp: base + 1554, X: 302, Y: 171},
		{Type: "mouseup", Timestamp: base + 1662, X: 303, Y: 170},
		{Type: "click", Timestamp: base + 1669, X: 303, Y: 170},
	}
}

func holdTurnstileEvents(requiredHoldMs int) []CaptchaEvent {
	base := time.Now().UnixMilli()
	if requiredHoldMs <= 0 {
		requiredHoldMs = 900
	}
	return []CaptchaEvent{
		{Type: "mousemove", Timestamp: base + 0, X: 126, Y: 250},
		{Type: "mousemove", Timestamp: base + 123, X: 152, Y: 230},
		{Type: "mousemove", Timestamp: base + 247, X: 174, Y: 214},
		{Type: "mousemove", Timestamp: base + 402, X: 198, Y: 198},
		{Type: "mousedown", Timestamp: base + 565, X: 206, Y: 194},
		{Type: "mousemove", Timestamp: base + 910, X: 207, Y: 194},
		{Type: "mousemove", Timestamp: base + int64(requiredHoldMs) + 705, X: 208, Y: 195},
		{Type: "mouseup", Timestamp: base + int64(requiredHoldMs) + 845, X: 208, Y: 195},
		{Type: "click", Timestamp: base + int64(requiredHoldMs) + 852, X: 208, Y: 195},
	}
}

func dragTurnstileEvents(requiredDistance int) []CaptchaEvent {
	base := time.Now().UnixMilli()
	if requiredDistance <= 0 {
		requiredDistance = 160
	}
	endX := float64(122 + requiredDistance + 32)
	return []CaptchaEvent{
		{Type: "mousemove", Timestamp: base + 0, X: 110, Y: 260},
		{Type: "mousemove", Timestamp: base + 96, X: 121, Y: 249},
		{Type: "mousedown", Timestamp: base + 211, X: 122, Y: 244},
		{Type: "mousemove", Timestamp: base + 418, X: 152, Y: 244},
		{Type: "mousemove", Timestamp: base + 605, X: 183, Y: 243},
		{Type: "mousemove", Timestamp: base + 781, X: 216, Y: 243},
		{Type: "mousemove", Timestamp: base + 954, X: 248, Y: 244},
		{Type: "mousemove", Timestamp: base + 1132, X: 281, Y: 244},
		{Type: "mousemove", Timestamp: base + 1317, X: endX, Y: 244},
		{Type: "mouseup", Timestamp: base + 1473, X: endX, Y: 244},
		{Type: "click", Timestamp: base + 1480, X: endX, Y: 244},
	}
}

func precisionDragTurnstileEvents(requiredDistance, requiredOvershoot, settleMs int) []CaptchaEvent {
	base := time.Now().UnixMilli()
	if requiredDistance <= 0 {
		requiredDistance = 162
	}
	if requiredOvershoot <= 0 {
		requiredOvershoot = 18
	}
	if settleMs <= 0 {
		settleMs = 180
	}
	startX := 122.0
	releaseX := startX + float64(requiredDistance) + 8
	maxX := releaseX + float64(requiredOvershoot) + 6

	return []CaptchaEvent{
		{Type: "mousemove", Timestamp: base + 0, X: 104, Y: 262},
		{Type: "mousemove", Timestamp: base + 88, X: 117, Y: 252},
		{Type: "mousemove", Timestamp: base + 179, X: 121, Y: 246},
		{Type: "wheel", Timestamp: base + 256, Delta: 72},
		{Type: "mousemove", Timestamp: base + 344, X: 122, Y: 244},
		{Type: "mousedown", Timestamp: base + 458, X: startX, Y: 244},
		{Type: "mousemove", Timestamp: base + 602, X: 168, Y: 243},
		{Type: "mousemove", Timestamp: base + 739, X: 214, Y: 242},
		{Type: "mousemove", Timestamp: base + 861, X: 256, Y: 243},
		{Type: "mousemove", Timestamp: base + 984, X: maxX, Y: 244},
		{Type: "mousemove", Timestamp: base + 1131, X: releaseX + 4, Y: 245},
		{Type: "mousemove", Timestamp: base + 1247, X: releaseX, Y: 244},
		{Type: "mouseup", Timestamp: base + 1247 + int64(settleMs) + 220, X: releaseX, Y: 244},
		{Type: "click", Timestamp: base + 1254 + int64(settleMs) + 220, X: releaseX, Y: 244},
	}
}

func precisionDragNoApproachEvents(requiredDistance, requiredOvershoot, settleMs int) []CaptchaEvent {
	base := time.Now().UnixMilli()
	if requiredDistance <= 0 {
		requiredDistance = 162
	}
	if requiredOvershoot <= 0 {
		requiredOvershoot = 18
	}
	if settleMs <= 0 {
		settleMs = 180
	}
	startX := 122.0
	releaseX := startX + float64(requiredDistance) + 7
	maxX := releaseX + float64(requiredOvershoot) + 5

	return []CaptchaEvent{
		{Type: "mousemove", Timestamp: base + 0, X: 48, Y: 286},
		{Type: "mousemove", Timestamp: base + 91, X: 68, Y: 279},
		{Type: "mousemove", Timestamp: base + 194, X: 81, Y: 271},
		{Type: "wheel", Timestamp: base + 266, Delta: 84},
		{Type: "mousedown", Timestamp: base + 458, X: startX, Y: 244},
		{Type: "mousemove", Timestamp: base + 612, X: 171, Y: 244},
		{Type: "mousemove", Timestamp: base + 755, X: 218, Y: 244},
		{Type: "mousemove", Timestamp: base + 898, X: 263, Y: 243},
		{Type: "mousemove", Timestamp: base + 1045, X: maxX, Y: 244},
		{Type: "mousemove", Timestamp: base + 1189, X: releaseX + 3, Y: 244},
		{Type: "mousemove", Timestamp: base + 1308, X: releaseX, Y: 244},
		{Type: "mouseup", Timestamp: base + 1308 + int64(settleMs) + 220, X: releaseX, Y: 244},
		{Type: "click", Timestamp: base + 1315 + int64(settleMs) + 220, X: releaseX, Y: 244},
	}
}

func straightLineTurnstileEvents() []CaptchaEvent {
	base := time.Now().UnixMilli()
	return []CaptchaEvent{
		{Type: "mousemove", Timestamp: base + 0, X: 100, Y: 200},
		{Type: "mousemove", Timestamp: base + 100, X: 140, Y: 200},
		{Type: "mousemove", Timestamp: base + 200, X: 180, Y: 200},
		{Type: "mousemove", Timestamp: base + 300, X: 220, Y: 200},
		{Type: "mousemove", Timestamp: base + 400, X: 260, Y: 200},
		{Type: "mousemove", Timestamp: base + 500, X: 300, Y: 200},
		{Type: "mousedown", Timestamp: base + 650, X: 300, Y: 200},
		{Type: "mouseup", Timestamp: base + 700, X: 300, Y: 200},
		{Type: "click", Timestamp: base + 701, X: 300, Y: 200},
	}
}

func humanLikeTurnstileSnapshot() *TurnstileClientSnapshot {
	return &TurnstileClientSnapshot{
		UserAgent:           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
		Language:            "en-US",
		Languages:           []string{"en-US", "en"},
		Platform:            "Win32",
		HardwareConcurrency: 8,
		ScreenWidth:         1920,
		ScreenHeight:        1080,
		ColorDepth:          24,
		Timezone:            "America/New_York",
		CookieEnabled:       true,
	}
}

func webdriverTurnstileSnapshot() *TurnstileClientSnapshot {
	snapshot := humanLikeTurnstileSnapshot()
	snapshot.Webdriver = true
	return snapshot
}

func checkboxTurnstileProof() *TurnstileInteractionProof {
	return &TurnstileInteractionProof{
		Type:           turnstileInteractionCheckbox,
		Completed:      true,
		CheckboxClicks: 1,
	}
}

func holdTurnstileProof(requiredHoldMs int) *TurnstileInteractionProof {
	if requiredHoldMs <= 0 {
		requiredHoldMs = 900
	}
	return &TurnstileInteractionProof{
		Type:           turnstileInteractionHold,
		Completed:      true,
		HoldDurationMs: requiredHoldMs + 260,
	}
}

func dragTurnstileProof(requiredDistance, requiredEvents int) *TurnstileInteractionProof {
	if requiredDistance <= 0 {
		requiredDistance = 160
	}
	if requiredEvents <= 0 {
		requiredEvents = 6
	}
	return &TurnstileInteractionProof{
		Type:           turnstileInteractionDrag,
		Completed:      true,
		DragDistancePx: requiredDistance + 28,
		DragEventCount: requiredEvents + 2,
	}
}

func precisionDragTurnstileProof(requiredDistance, requiredEvents, requiredOvershoot, settleMs, targetZoneWidth, directionChanges int) *TurnstileInteractionProof {
	if requiredDistance <= 0 {
		requiredDistance = 162
	}
	if requiredEvents <= 0 {
		requiredEvents = 8
	}
	if requiredOvershoot <= 0 {
		requiredOvershoot = 18
	}
	if settleMs <= 0 {
		settleMs = 180
	}
	if targetZoneWidth <= 0 {
		targetZoneWidth = 24
	}
	if directionChanges <= 0 {
		directionChanges = 1
	}
	return &TurnstileInteractionProof{
		Type:              turnstileInteractionPrecision,
		Completed:         true,
		DragDistancePx:    requiredDistance + requiredOvershoot + 6,
		DragEventCount:    requiredEvents + 1,
		ApproachHoverMs:   256,
		ApproachMoveCount: 4,
		ApproachSettleMs:  114,
		OvershootPx:       requiredOvershoot + 6,
		SettleDurationMs:  settleMs + 220,
		DirectionChanges:  directionChanges,
		FinalDragOffsetPx: requiredDistance + targetZoneWidth/3,
	}
}

func TestTurnstileInitExposesWidgetConfig(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/cloudflare/init", strings.NewReader(`{"challenge_type":"cloudflare_turnstile"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	cc.HandleInit(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		SessionID string                 `json:"session_id"`
		Turnstile *TurnstileWidgetConfig `json:"turnstile"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode init response: %v", err)
	}

	if resp.SessionID == "" {
		t.Fatal("expected session ID")
	}
	if resp.Turnstile == nil {
		t.Fatal("expected turnstile config")
	}
	if resp.Turnstile.Action == "" || resp.Turnstile.CData == "" {
		t.Fatalf("expected action/cdata, got %+v", resp.Turnstile)
	}
	if resp.Turnstile.TokenTTLSeconds != int(defaultTurnstileTokenTTL/time.Second) {
		t.Fatalf("unexpected token TTL: %d", resp.Turnstile.TokenTTLSeconds)
	}
	if resp.Turnstile.RetryPolicy.IntervalMs != 8000 {
		t.Fatalf("unexpected retry interval: %d", resp.Turnstile.RetryPolicy.IntervalMs)
	}
	if resp.Turnstile.CallbackState.Success {
		t.Fatal("callback state should start empty")
	}
	if resp.Turnstile.RiskLevel != "low" || resp.Turnstile.Interaction.Type != turnstileInteractionCheckbox {
		t.Fatalf("expected low-risk checkbox contract, got %+v", resp.Turnstile)
	}
}

func TestTurnstileInitEscalatesInteractionByRisk(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	testCases := []struct {
		name        string
		body        string
		wantRisk    string
		wantVariant string
	}{
		{name: "low", body: `{"challenge_type":"cloudflare_turnstile","detection_score":0.20}`, wantRisk: "low", wantVariant: turnstileInteractionCheckbox},
		{name: "medium", body: `{"challenge_type":"cloudflare_turnstile","detection_score":0.55}`, wantRisk: "medium", wantVariant: turnstileInteractionHold},
		{name: "high", body: `{"challenge_type":"cloudflare_turnstile","detection_score":0.85}`, wantRisk: "high", wantVariant: turnstileInteractionDrag},
		{name: "critical", body: `{"challenge_type":"cloudflare_turnstile","detection_score":0.92}`, wantRisk: "critical", wantVariant: turnstileInteractionPrecision},
		{name: "extreme", body: `{"challenge_type":"cloudflare_turnstile","detection_score":0.96}`, wantRisk: "extreme", wantVariant: turnstileInteractionRotate},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/cloudflare/init", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			cc.HandleInit(w, req)

			var resp struct {
				Turnstile *TurnstileWidgetConfig `json:"turnstile"`
			}
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("decode init response: %v", err)
			}
			if resp.Turnstile == nil {
				t.Fatal("expected turnstile config")
			}
			if resp.Turnstile.RiskLevel != tc.wantRisk || resp.Turnstile.Interaction.Type != tc.wantVariant {
				t.Fatalf("unexpected risk/variant: %+v", resp.Turnstile)
			}
		})
	}
}

func TestTurnstileWidgetPageContainsContractFields(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/cloudflare/turnstile/widget?session_id=widget-1&site_key=1x00000000000000000000AA", nil)
	w := httptest.NewRecorder()
	cc.HandleTurnstileWidgetPage(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 widget page, got %d", w.Code)
	}

	body := w.Body.String()
	checks := []string{
		`class="cf-turnstile"`,
		`data-action="managed"`,
		`data-cdata="widget-1"`,
		`data-risk-level="low"`,
		`data-interaction="checkbox"`,
		`data-retry-interval="8000"`,
		`data-refresh-expired="auto"`,
		`data-before-interactive-callback="__tsBeforeInteractive"`,
		`data-after-interactive-callback="__tsAfterInteractive"`,
		`data-callback="__tsSuccess"`,
	}
	for _, marker := range checks {
		if !strings.Contains(body, marker) {
			t.Fatalf("widget page missing %q", marker)
		}
	}

	session, ok := cc.GetSession("widget-1")
	if !ok {
		t.Fatal("expected session to be created")
	}
	if !session.TurnstilePresented {
		t.Fatal("expected widget presentation to be recorded")
	}
}

func TestTurnstileWidgetPageRendersRiskVariants(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	cases := []struct {
		name            string
		sessionID       string
		detectionScore  string
		wantRisk        string
		wantInteraction string
		wantLabel       string
		wantSubtitle    string
		extraMarkers    []string
	}{
		{
			name:            "low checkbox",
			sessionID:       "widget-low",
			detectionScore:  "0.20",
			wantRisk:        "low",
			wantInteraction: turnstileInteractionCheckbox,
			wantLabel:       `aria-label="Local Turnstile harness checkbox"`,
			wantSubtitle:    "Local Turnstile harness ready",
		},
		{
			name:            "medium hold",
			sessionID:       "widget-medium",
			detectionScore:  "0.55",
			wantRisk:        "medium",
			wantInteraction: turnstileInteractionHold,
			wantLabel:       `aria-label="Local Turnstile harness hold button"`,
			wantSubtitle:    "Press and hold to continue",
		},
		{
			name:            "high drag",
			sessionID:       "widget-high",
			detectionScore:  "0.85",
			wantRisk:        "high",
			wantInteraction: turnstileInteractionDrag,
			wantLabel:       `aria-label="Local Turnstile harness drag handle"`,
			wantSubtitle:    "Drag the handle to the end",
		},
		{
			name:            "critical precision drag",
			sessionID:       "widget-critical",
			detectionScore:  "0.92",
			wantRisk:        "critical",
			wantInteraction: turnstileInteractionPrecision,
			wantLabel:       `aria-label="Local Turnstile harness precision drag handle"`,
			wantSubtitle:    "Drag past the marker and release in the zone",
			extraMarkers: []string{
				`data-required-approach-hover-ms="220"`,
				`data-required-approach-moves="3"`,
				`data-required-approach-settle-ms="90"`,
				`data-required-overshoot="18"`,
				`data-required-settle-ms="180"`,
				`data-required-direction-changes="1"`,
				`data-target-zone-width="24"`,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/cloudflare/turnstile/widget?session_id="+tc.sessionID+"&site_key=1x00000000000000000000AA&detection_score="+tc.detectionScore, nil)
			w := httptest.NewRecorder()
			cc.HandleTurnstileWidgetPage(w, req)

			if w.Code != http.StatusForbidden {
				t.Fatalf("expected 403 widget page, got %d", w.Code)
			}

			body := w.Body.String()
			checks := []string{
				`data-risk-level="` + tc.wantRisk + `"`,
				`data-interaction="` + tc.wantInteraction + `"`,
				tc.wantLabel,
				tc.wantSubtitle,
			}
			checks = append(checks, tc.extraMarkers...)
			for _, marker := range checks {
				if !strings.Contains(body, marker) {
					t.Fatalf("widget page missing %q", marker)
				}
			}
		})
	}
}

func TestTurnstilePresentedSessionRequiresLifecycleCallbacks(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	session := cc.CreateTurnstileChallenge("widget-lifecycle", "1x00000000000000000000AA")
	cc.PresentTurnstileWidget(session.ID, "localhost")
	cc.RecordTurnstileClientSnapshot(session.ID, humanLikeTurnstileSnapshot())
	cc.RecordTurnstileInteractionProof(session.ID, checkboxTurnstileProof())

	solution, err := SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, session.PoW.MaxIterations)
	if err != nil {
		t.Fatalf("SolvePoW failed: %v", err)
	}

	if _, err := cc.CompleteTurnstile(session.ID, solution, humanLikeTurnstileEvents()); err == nil {
		t.Fatal("expected solve without widget callbacks to be rejected once presented")
	}

	cc.RecordTurnstileCallback(session.ID, "before-interactive")
	cc.RecordTurnstileCallback(session.ID, "after-interactive")
	if _, err := cc.CompleteTurnstile(session.ID, solution, humanLikeTurnstileEvents()); err != nil {
		t.Fatalf("expected solve to pass with lifecycle callbacks: %v", err)
	}
}

func TestTurnstileRejectsTimeoutCallback(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	session := cc.CreateTurnstileChallenge("widget-timeout", "1x00000000000000000000AA")
	cc.PresentTurnstileWidget(session.ID, "localhost")
	cc.RecordTurnstileClientSnapshot(session.ID, humanLikeTurnstileSnapshot())
	cc.RecordTurnstileCallback(session.ID, "before-interactive")
	cc.RecordTurnstileCallback(session.ID, "timeout")
	cc.RecordTurnstileInteractionProof(session.ID, checkboxTurnstileProof())

	solution, err := SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, session.PoW.MaxIterations)
	if err != nil {
		t.Fatalf("SolvePoW failed: %v", err)
	}

	if _, err := cc.CompleteTurnstile(session.ID, solution, humanLikeTurnstileEvents()); err == nil {
		t.Fatal("expected timeout lifecycle to force rejection")
	}
}

func TestTurnstileHoldVariantRequiresHoldProof(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	session := cc.CreateTurnstileChallengeWithRisk("widget-hold", "1x00000000000000000000AA", 0.55)
	cc.PresentTurnstileWidget(session.ID, "localhost")
	cc.RecordTurnstileClientSnapshot(session.ID, humanLikeTurnstileSnapshot())
	cc.RecordTurnstileCallback(session.ID, "before-interactive")
	cc.RecordTurnstileCallback(session.ID, "after-interactive")

	solution, err := SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, session.PoW.MaxIterations)
	if err != nil {
		t.Fatalf("SolvePoW failed: %v", err)
	}

	cc.RecordTurnstileInteractionProof(session.ID, &TurnstileInteractionProof{
		Type:           turnstileInteractionHold,
		Completed:      false,
		HoldDurationMs: 320,
	})
	if _, err := cc.CompleteTurnstile(session.ID, solution, holdTurnstileEvents(320)); err == nil {
		t.Fatal("expected short hold proof to be rejected")
	}

	session = cc.CreateTurnstileChallengeWithRisk("widget-hold-pass", "1x00000000000000000000AA", 0.55)
	cc.PresentTurnstileWidget(session.ID, "localhost")
	cc.RecordTurnstileClientSnapshot(session.ID, humanLikeTurnstileSnapshot())
	cc.RecordTurnstileCallback(session.ID, "before-interactive")
	cc.RecordTurnstileCallback(session.ID, "after-interactive")
	cc.RecordTurnstileInteractionProof(session.ID, holdTurnstileProof(session.TurnstileConfig.Interaction.RequiredHoldMs))
	solution, err = SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, session.PoW.MaxIterations)
	if err != nil {
		t.Fatalf("SolvePoW hold pass failed: %v", err)
	}
	if _, err := cc.CompleteTurnstile(session.ID, solution, holdTurnstileEvents(session.TurnstileConfig.Interaction.RequiredHoldMs)); err != nil {
		t.Fatalf("expected hold proof to pass: %v", err)
	}
}

func TestTurnstileDragVariantRequiresDragProof(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	session := cc.CreateTurnstileChallengeWithRisk("widget-drag", "1x00000000000000000000AA", 0.85)
	cc.PresentTurnstileWidget(session.ID, "localhost")
	cc.RecordTurnstileClientSnapshot(session.ID, humanLikeTurnstileSnapshot())
	cc.RecordTurnstileCallback(session.ID, "before-interactive")
	cc.RecordTurnstileCallback(session.ID, "after-interactive")

	solution, err := SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, session.PoW.MaxIterations)
	if err != nil {
		t.Fatalf("SolvePoW failed: %v", err)
	}

	cc.RecordTurnstileInteractionProof(session.ID, &TurnstileInteractionProof{
		Type:           turnstileInteractionDrag,
		Completed:      false,
		DragDistancePx: 84,
		DragEventCount: 3,
	})
	if _, err := cc.CompleteTurnstile(session.ID, solution, holdTurnstileEvents(900)); err == nil {
		t.Fatal("expected short drag proof to be rejected")
	}

	session = cc.CreateTurnstileChallengeWithRisk("widget-drag-pass", "1x00000000000000000000AA", 0.85)
	cc.PresentTurnstileWidget(session.ID, "localhost")
	cc.RecordTurnstileClientSnapshot(session.ID, humanLikeTurnstileSnapshot())
	cc.RecordTurnstileCallback(session.ID, "before-interactive")
	cc.RecordTurnstileCallback(session.ID, "after-interactive")
	cc.RecordTurnstileInteractionProof(session.ID, dragTurnstileProof(session.TurnstileConfig.Interaction.RequiredDragDistancePx, session.TurnstileConfig.Interaction.RequiredDragEventCount))
	solution, err = SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, session.PoW.MaxIterations)
	if err != nil {
		t.Fatalf("SolvePoW drag pass failed: %v", err)
	}
	if _, err := cc.CompleteTurnstile(session.ID, solution, dragTurnstileEvents(session.TurnstileConfig.Interaction.RequiredDragDistancePx)); err != nil {
		t.Fatalf("expected drag proof to pass: %v", err)
	}
}

func TestTurnstilePrecisionVariantRequiresOvershootAndSettle(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	session := cc.CreateTurnstileChallengeWithRisk("widget-precision", "1x00000000000000000000AA", 0.92)
	cc.PresentTurnstileWidget(session.ID, "localhost")
	cc.RecordTurnstileClientSnapshot(session.ID, humanLikeTurnstileSnapshot())
	cc.RecordTurnstileCallback(session.ID, "before-interactive")
	cc.RecordTurnstileCallback(session.ID, "after-interactive")

	solution, err := SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, session.PoW.MaxIterations)
	if err != nil {
		t.Fatalf("SolvePoW failed: %v", err)
	}

	cc.RecordTurnstileInteractionProof(session.ID, &TurnstileInteractionProof{
		Type:              turnstileInteractionPrecision,
		Completed:         true,
		DragDistancePx:    session.TurnstileConfig.Interaction.RequiredDragDistancePx + 4,
		DragEventCount:    session.TurnstileConfig.Interaction.RequiredDragEventCount,
		FinalDragOffsetPx: session.TurnstileConfig.Interaction.RequiredDragDistancePx + 4,
	})
	if _, err := cc.CompleteTurnstile(session.ID, solution, dragTurnstileEvents(session.TurnstileConfig.Interaction.RequiredDragDistancePx)); err == nil {
		t.Fatal("expected straight drag proof to be rejected for precision variant")
	}

	session = cc.CreateTurnstileChallengeWithRisk("widget-precision-pass", "1x00000000000000000000AA", 0.92)
	cc.PresentTurnstileWidget(session.ID, "localhost")
	cc.RecordTurnstileClientSnapshot(session.ID, humanLikeTurnstileSnapshot())
	cc.RecordTurnstileCallback(session.ID, "before-interactive")
	cc.RecordTurnstileCallback(session.ID, "after-interactive")
	cc.RecordTurnstileInteractionProof(session.ID, precisionDragTurnstileProof(
		session.TurnstileConfig.Interaction.RequiredDragDistancePx,
		session.TurnstileConfig.Interaction.RequiredDragEventCount,
		session.TurnstileConfig.Interaction.RequiredOvershootPx,
		session.TurnstileConfig.Interaction.RequiredSettleMs,
		session.TurnstileConfig.Interaction.TargetZoneWidthPx,
		session.TurnstileConfig.Interaction.RequiredDirectionChanges,
	))
	solution, err = SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, session.PoW.MaxIterations)
	if err != nil {
		t.Fatalf("SolvePoW precision pass failed: %v", err)
	}
	if _, err := cc.CompleteTurnstile(session.ID, solution, precisionDragTurnstileEvents(
		session.TurnstileConfig.Interaction.RequiredDragDistancePx,
		session.TurnstileConfig.Interaction.RequiredOvershootPx,
		session.TurnstileConfig.Interaction.RequiredSettleMs,
	)); err != nil {
		t.Fatalf("expected precision drag proof to pass: %v", err)
	}
}

func TestTurnstilePrecisionVariantRequiresApproachHover(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	session := cc.CreateTurnstileChallengeWithRisk("widget-precision-approach", "1x00000000000000000000AA", 0.92)
	cc.PresentTurnstileWidget(session.ID, "localhost")
	cc.RecordTurnstileClientSnapshot(session.ID, humanLikeTurnstileSnapshot())
	cc.RecordTurnstileCallback(session.ID, "before-interactive")
	cc.RecordTurnstileCallback(session.ID, "after-interactive")

	solution, err := SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, session.PoW.MaxIterations)
	if err != nil {
		t.Fatalf("SolvePoW failed: %v", err)
	}

	cc.RecordTurnstileInteractionProof(session.ID, &TurnstileInteractionProof{
		Type:              turnstileInteractionPrecision,
		Completed:         true,
		DragDistancePx:    session.TurnstileConfig.Interaction.RequiredDragDistancePx + session.TurnstileConfig.Interaction.RequiredOvershootPx + 5,
		DragEventCount:    session.TurnstileConfig.Interaction.RequiredDragEventCount,
		ApproachHoverMs:   0,
		ApproachMoveCount: 0,
		ApproachSettleMs:  0,
		OvershootPx:       session.TurnstileConfig.Interaction.RequiredOvershootPx + 5,
		SettleDurationMs:  session.TurnstileConfig.Interaction.RequiredSettleMs + 220,
		DirectionChanges:  session.TurnstileConfig.Interaction.RequiredDirectionChanges,
		FinalDragOffsetPx: session.TurnstileConfig.Interaction.RequiredDragDistancePx + session.TurnstileConfig.Interaction.TargetZoneWidthPx/3,
	})
	if _, err := cc.CompleteTurnstile(session.ID, solution, precisionDragNoApproachEvents(
		session.TurnstileConfig.Interaction.RequiredDragDistancePx,
		session.TurnstileConfig.Interaction.RequiredOvershootPx,
		session.TurnstileConfig.Interaction.RequiredSettleMs,
	)); err == nil {
		t.Fatal("expected precision drag without approach hover to be rejected")
	}
}

func TestTurnstileSiteVerifySingleUseAndExpiry(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	session := cc.CreateTurnstileChallenge("siteverify-1", "1x00000000000000000000AA")
	session.Hostname = "localhost"
	cc.PresentTurnstileWidget(session.ID, "localhost")
	cc.RecordTurnstileClientSnapshot(session.ID, humanLikeTurnstileSnapshot())
	cc.RecordTurnstileCallback(session.ID, "before-interactive")
	cc.RecordTurnstileCallback(session.ID, "after-interactive")
	cc.RecordTurnstileInteractionProof(session.ID, checkboxTurnstileProof())
	solution, err := SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, session.PoW.MaxIterations)
	if err != nil {
		t.Fatalf("SolvePoW failed: %v", err)
	}

	result, err := cc.CompleteTurnstile(session.ID, solution, humanLikeTurnstileEvents())
	if err != nil {
		t.Fatalf("CompleteTurnstile failed: %v", err)
	}

	postVerify := func(token string) map[string]any {
		body, _ := json.Marshal(map[string]string{
			"secret":   cc.TurnstileSecretKey(),
			"response": token,
		})
		req := httptest.NewRequest(http.MethodPost, "/turnstile/v0/siteverify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Host = "localhost"
		w := httptest.NewRecorder()
		cc.HandleTurnstileSiteVerify(w, req)

		var decoded map[string]any
		if err := json.NewDecoder(w.Body).Decode(&decoded); err != nil {
			t.Fatalf("decode verify response: %v", err)
		}
		return decoded
	}

	first := postVerify(result.TurnstileToken)
	if success, _ := first["success"].(bool); !success {
		t.Fatalf("expected first verification to succeed: %+v", first)
	}

	second := postVerify(result.TurnstileToken)
	if success, _ := second["success"].(bool); success {
		t.Fatalf("expected duplicate verification to fail: %+v", second)
	}

	expiredSession := cc.CreateTurnstileChallenge("siteverify-expired", "1x00000000000000000000AA")
	expiredSession.Hostname = "localhost"
	cc.PresentTurnstileWidget(expiredSession.ID, "localhost")
	cc.RecordTurnstileClientSnapshot(expiredSession.ID, humanLikeTurnstileSnapshot())
	cc.RecordTurnstileCallback(expiredSession.ID, "before-interactive")
	cc.RecordTurnstileCallback(expiredSession.ID, "after-interactive")
	cc.RecordTurnstileInteractionProof(expiredSession.ID, checkboxTurnstileProof())
	expiredSolution, err := SolvePoW(expiredSession.PoW.Prefix, expiredSession.PoW.Difficulty, expiredSession.PoW.MaxIterations)
	if err != nil {
		t.Fatalf("SolvePoW expired failed: %v", err)
	}
	expiredResult, err := cc.CompleteTurnstile(expiredSession.ID, expiredSolution, humanLikeTurnstileEvents())
	if err != nil {
		t.Fatalf("CompleteTurnstile expired failed: %v", err)
	}

	cc.mu.Lock()
	cc.sessions[expiredSession.ID].TurnstileToken.ExpiresAt = time.Now().Add(-time.Second)
	cc.mu.Unlock()

	expired := postVerify(expiredResult.TurnstileToken)
	if success, _ := expired["success"].(bool); success {
		t.Fatalf("expected expired verification to fail: %+v", expired)
	}
}

func TestEvaluateTurnstileDefense(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	report, err := cc.EvaluateTurnstileDefense([]TurnstileEvaluationCase{
		{
			Name:               "human-like",
			ExpectPass:         true,
			PresentWidget:      true,
			LifecycleCallbacks: []string{"before-interactive", "after-interactive"},
			VerifyToken:        true,
			BuildEvents: func() []CaptchaEvent {
				return humanLikeTurnstileEvents()
			},
			BuildSnapshot:         humanLikeTurnstileSnapshot,
			BuildInteractionProof: checkboxTurnstileProof,
		},
		{
			Name:               "hold-human-like",
			DetectionScore:     0.55,
			ExpectPass:         true,
			PresentWidget:      true,
			LifecycleCallbacks: []string{"before-interactive", "after-interactive"},
			BuildEvents: func() []CaptchaEvent {
				return holdTurnstileEvents(900)
			},
			BuildSnapshot: humanLikeTurnstileSnapshot,
			BuildInteractionProof: func() *TurnstileInteractionProof {
				return holdTurnstileProof(900)
			},
		},
		{
			Name:               "drag-human-like",
			DetectionScore:     0.85,
			ExpectPass:         true,
			PresentWidget:      true,
			LifecycleCallbacks: []string{"before-interactive", "after-interactive"},
			BuildEvents: func() []CaptchaEvent {
				return dragTurnstileEvents(160)
			},
			BuildSnapshot: humanLikeTurnstileSnapshot,
			BuildInteractionProof: func() *TurnstileInteractionProof {
				return dragTurnstileProof(160, 6)
			},
		},
		{
			Name:               "precision-human-like",
			DetectionScore:     0.92,
			ExpectPass:         true,
			PresentWidget:      true,
			LifecycleCallbacks: []string{"before-interactive", "after-interactive"},
			BuildEvents: func() []CaptchaEvent {
				return precisionDragTurnstileEvents(162, 18, 180)
			},
			BuildSnapshot: humanLikeTurnstileSnapshot,
			BuildInteractionProof: func() *TurnstileInteractionProof {
				return precisionDragTurnstileProof(162, 8, 18, 180, 24, 1)
			},
		},
		{
			Name:               "straight-line-bot",
			ExpectPass:         false,
			PresentWidget:      true,
			LifecycleCallbacks: []string{"before-interactive", "after-interactive"},
			BuildEvents: func() []CaptchaEvent {
				return straightLineTurnstileEvents()
			},
			BuildSnapshot:         humanLikeTurnstileSnapshot,
			BuildInteractionProof: checkboxTurnstileProof,
		},
		{
			Name:               "timed-out-widget",
			ExpectPass:         false,
			PresentWidget:      true,
			LifecycleCallbacks: []string{"before-interactive", "timeout"},
			BuildEvents: func() []CaptchaEvent {
				return humanLikeTurnstileEvents()
			},
			BuildSnapshot:         humanLikeTurnstileSnapshot,
			BuildInteractionProof: checkboxTurnstileProof,
		},
		{
			Name:               "webdriver-bot",
			ExpectPass:         false,
			PresentWidget:      true,
			LifecycleCallbacks: []string{"before-interactive", "after-interactive"},
			BuildEvents: func() []CaptchaEvent {
				return humanLikeTurnstileEvents()
			},
			BuildSnapshot:         webdriverTurnstileSnapshot,
			BuildInteractionProof: checkboxTurnstileProof,
		},
		{
			Name:               "drag-short",
			DetectionScore:     0.85,
			ExpectPass:         false,
			PresentWidget:      true,
			LifecycleCallbacks: []string{"before-interactive", "after-interactive"},
			BuildEvents: func() []CaptchaEvent {
				return holdTurnstileEvents(900)
			},
			BuildSnapshot: humanLikeTurnstileSnapshot,
			BuildInteractionProof: func() *TurnstileInteractionProof {
				return &TurnstileInteractionProof{
					Type:           turnstileInteractionDrag,
					Completed:      false,
					DragDistancePx: 72,
					DragEventCount: 3,
				}
			},
		},
		{
			Name:               "precision-no-settle",
			DetectionScore:     0.92,
			ExpectPass:         false,
			PresentWidget:      true,
			LifecycleCallbacks: []string{"before-interactive", "after-interactive"},
			BuildEvents: func() []CaptchaEvent {
				return dragTurnstileEvents(170)
			},
			BuildSnapshot: humanLikeTurnstileSnapshot,
			BuildInteractionProof: func() *TurnstileInteractionProof {
				return &TurnstileInteractionProof{
					Type:              turnstileInteractionPrecision,
					Completed:         true,
					DragDistancePx:    170,
					DragEventCount:    8,
					FinalDragOffsetPx: 170,
				}
			},
		},
		{
			Name:               "precision-no-approach",
			DetectionScore:     0.92,
			ExpectPass:         false,
			PresentWidget:      true,
			LifecycleCallbacks: []string{"before-interactive", "after-interactive"},
			BuildEvents: func() []CaptchaEvent {
				return precisionDragNoApproachEvents(162, 18, 180)
			},
			BuildSnapshot: humanLikeTurnstileSnapshot,
			BuildInteractionProof: func() *TurnstileInteractionProof {
				return &TurnstileInteractionProof{
					Type:              turnstileInteractionPrecision,
					Completed:         true,
					DragDistancePx:    186,
					DragEventCount:    9,
					ApproachHoverMs:   0,
					ApproachMoveCount: 0,
					ApproachSettleMs:  0,
					OvershootPx:       23,
					SettleDurationMs:  400,
					DirectionChanges:  1,
					FinalDragOffsetPx: 170,
				}
			},
		},
		{
			Name:       "empty-bot",
			ExpectPass: false,
			BuildEvents: func() []CaptchaEvent {
				return nil
			},
		},
	}, 3)
	if err != nil {
		t.Fatalf("EvaluateTurnstileDefense failed: %v", err)
	}

	if len(report.Samples) != 11 {
		t.Fatalf("expected 11 samples, got %d", len(report.Samples))
	}

	if report.Samples[0].PassRate <= 0 {
		t.Fatalf("expected human-like sample to pass at least once: %+v", report.Samples[0])
	}
	if report.Samples[0].VerificationPasses != report.Samples[0].Passes {
		t.Fatalf("expected human-like sample to verify each issued token: %+v", report.Samples[0])
	}
	if report.Samples[1].PassRate <= 0 {
		t.Fatalf("expected hold sample to pass at least once: %+v", report.Samples[1])
	}
	if report.Samples[2].PassRate <= 0 {
		t.Fatalf("expected drag sample to pass at least once: %+v", report.Samples[2])
	}
	if report.Samples[3].PassRate <= 0 {
		t.Fatalf("expected precision sample to pass at least once: %+v", report.Samples[3])
	}
	if report.Samples[4].RejectRate != 1 {
		t.Fatalf("expected straight-line bot sample to reject every time: %+v", report.Samples[4])
	}
	if report.Samples[5].RejectRate != 1 {
		t.Fatalf("expected timeout sample to reject every time: %+v", report.Samples[5])
	}
	if report.Samples[6].RejectRate != 1 {
		t.Fatalf("expected webdriver sample to reject every time: %+v", report.Samples[6])
	}
	if report.Samples[7].RejectRate != 1 {
		t.Fatalf("expected short drag sample to reject every time: %+v", report.Samples[7])
	}
	if report.Samples[8].RejectRate != 1 {
		t.Fatalf("expected precision-no-settle sample to reject every time: %+v", report.Samples[8])
	}
	if report.Samples[9].RejectRate != 1 {
		t.Fatalf("expected precision-no-approach sample to reject every time: %+v", report.Samples[9])
	}
	if report.Samples[10].RejectRate != 1 {
		t.Fatalf("expected empty bot sample to reject every time: %+v", report.Samples[10])
	}
	if report.Accuracy < 0.75 {
		t.Fatalf("expected aggregate accuracy >= 0.75, got %.2f", report.Accuracy)
	}
}

func TestTurnstileRejectsWebdriverSnapshot(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	session := cc.CreateTurnstileChallenge("webdriver-session", "1x00000000000000000000AA")
	cc.PresentTurnstileWidget(session.ID, "localhost")
	cc.RecordTurnstileClientSnapshot(session.ID, webdriverTurnstileSnapshot())
	cc.RecordTurnstileCallback(session.ID, "before-interactive")
	cc.RecordTurnstileCallback(session.ID, "after-interactive")
	cc.RecordTurnstileInteractionProof(session.ID, checkboxTurnstileProof())

	solution, err := SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, session.PoW.MaxIterations)
	if err != nil {
		t.Fatalf("SolvePoW failed: %v", err)
	}

	if _, err := cc.CompleteTurnstile(session.ID, solution, humanLikeTurnstileEvents()); err == nil {
		t.Fatal("expected webdriver snapshot to be rejected")
	}
}

func TestTurnstileSiteVerifyRejectsHostnameMismatch(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	session := cc.CreateTurnstileChallenge("siteverify-hostname", "1x00000000000000000000AA")
	cc.PresentTurnstileWidget(session.ID, "localhost")
	cc.RecordTurnstileClientSnapshot(session.ID, humanLikeTurnstileSnapshot())
	cc.RecordTurnstileCallback(session.ID, "before-interactive")
	cc.RecordTurnstileCallback(session.ID, "after-interactive")
	cc.RecordTurnstileInteractionProof(session.ID, checkboxTurnstileProof())

	solution, err := SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, session.PoW.MaxIterations)
	if err != nil {
		t.Fatalf("SolvePoW failed: %v", err)
	}

	result, err := cc.CompleteTurnstile(session.ID, solution, humanLikeTurnstileEvents())
	if err != nil {
		t.Fatalf("CompleteTurnstile failed: %v", err)
	}

	verify := cc.VerifyTurnstileToken(cc.TurnstileSecretKey(), result.TurnstileToken, "example.com")
	if verify.Success {
		t.Fatalf("expected hostname mismatch verification to fail: %+v", verify)
	}
}

func TestTurnstileStatusReturnsSessionTelemetry(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	session := cc.CreateTurnstileChallenge("status-turnstile", "1x00000000000000000000AA")
	cc.PresentTurnstileWidget(session.ID, "localhost")
	cc.RecordTurnstileClientSnapshot(session.ID, humanLikeTurnstileSnapshot())
	cc.RecordTurnstileCallback(session.ID, "before-interactive")
	cc.RecordTurnstileInteractionProof(session.ID, checkboxTurnstileProof())

	req := httptest.NewRequest(http.MethodGet, "/api/cloudflare/status?session_id="+session.ID, nil)
	w := httptest.NewRecorder()
	cc.HandleStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		SessionID          string                   `json:"session_id"`
		TurnstilePresented bool                     `json:"turnstile_presented"`
		WidgetTelemetry    *WidgetTelemetry         `json:"widget_telemetry"`
		TurnstileSnapshot  *TurnstileClientSnapshot `json:"turnstile_snapshot"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode status response: %v", err)
	}

	if resp.SessionID != session.ID {
		t.Fatalf("expected session %q, got %q", session.ID, resp.SessionID)
	}
	if !resp.TurnstilePresented {
		t.Fatal("expected presented session to be reported")
	}
	if resp.WidgetTelemetry == nil || !resp.WidgetTelemetry.CallbackState.BeforeInteractive {
		t.Fatalf("expected widget telemetry in status response: %+v", resp.WidgetTelemetry)
	}
	if resp.TurnstileSnapshot == nil || resp.TurnstileSnapshot.UserAgent == "" {
		t.Fatalf("expected turnstile snapshot in status response: %+v", resp.TurnstileSnapshot)
	}
}

func TestTurnstileHeuristicReportFlagsImpossibleSubmissionGap(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	session := cc.CreateTurnstileChallengeWithRisk("heuristic-precision", "1x00000000000000000000AA", 0.95)
	cc.PresentTurnstileWidget(session.ID, "localhost")
	cc.RecordTurnstileClientSnapshot(session.ID, humanLikeTurnstileSnapshot())
	cc.RecordTurnstileCallback(session.ID, "before-interactive")
	cc.RecordTurnstileCallback(session.ID, "after-interactive")
	cc.RecordTurnstileInteractionProof(session.ID, precisionDragTurnstileProof(
		session.TurnstileConfig.Interaction.RequiredDragDistancePx,
		session.TurnstileConfig.Interaction.RequiredDragEventCount,
		session.TurnstileConfig.Interaction.RequiredOvershootPx,
		session.TurnstileConfig.Interaction.RequiredSettleMs,
		session.TurnstileConfig.Interaction.TargetZoneWidthPx,
		session.TurnstileConfig.Interaction.RequiredDirectionChanges,
	))

	base := time.Now().UTC()
	session.TurnstileTelemetry.PresentedAt = base
	session.TurnstileTelemetry.SnapshotAt = base.Add(20 * time.Millisecond)
	session.TurnstileTelemetry.BeforeAt = base.Add(45 * time.Millisecond)
	session.TurnstileTelemetry.AfterAt = base.Add(80 * time.Millisecond)
	session.TurnstileTelemetry.InteractionAt = base.Add(210 * time.Millisecond)

	report := evaluateTurnstileHeuristics(session, precisionDragTurnstileEvents(
		session.TurnstileConfig.Interaction.RequiredDragDistancePx,
		session.TurnstileConfig.Interaction.RequiredOvershootPx,
		session.TurnstileConfig.Interaction.RequiredSettleMs,
	))
	if report == nil {
		t.Fatal("expected heuristic report")
	}
	if !report.Flagged {
		t.Fatalf("expected impossible submission gap to be flagged: %+v", report)
	}
	found := false
	for _, signal := range report.Signals {
		if signal.Name == "interaction_submitted_too_quickly" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected timing mismatch signal, got %+v", report.Signals)
	}
}

func TestTurnstileSolvedStatusIncludesHeuristicReport(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)

	session := cc.CreateTurnstileChallengeWithRisk("status-heuristic", "1x00000000000000000000AA", 0.92)
	cc.PresentTurnstileWidget(session.ID, "localhost")
	cc.RecordTurnstileClientSnapshot(session.ID, humanLikeTurnstileSnapshot())
	cc.RecordTurnstileCallback(session.ID, "before-interactive")
	cc.RecordTurnstileCallback(session.ID, "after-interactive")
	cc.RecordTurnstileInteractionProof(session.ID, precisionDragTurnstileProof(
		session.TurnstileConfig.Interaction.RequiredDragDistancePx,
		session.TurnstileConfig.Interaction.RequiredDragEventCount,
		session.TurnstileConfig.Interaction.RequiredOvershootPx,
		session.TurnstileConfig.Interaction.RequiredSettleMs,
		session.TurnstileConfig.Interaction.TargetZoneWidthPx,
		session.TurnstileConfig.Interaction.RequiredDirectionChanges,
	))

	base := time.Now().UTC()
	session.TurnstileTelemetry.PresentedAt = base
	session.TurnstileTelemetry.SnapshotAt = base.Add(20 * time.Millisecond)
	session.TurnstileTelemetry.BeforeAt = base.Add(45 * time.Millisecond)
	session.TurnstileTelemetry.AfterAt = base.Add(80 * time.Millisecond)
	session.TurnstileTelemetry.InteractionAt = base.Add(210 * time.Millisecond)

	solution, err := SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, session.PoW.MaxIterations)
	if err != nil {
		t.Fatalf("SolvePoW failed: %v", err)
	}
	if _, err := cc.CompleteTurnstile(session.ID, solution, precisionDragTurnstileEvents(
		session.TurnstileConfig.Interaction.RequiredDragDistancePx,
		session.TurnstileConfig.Interaction.RequiredOvershootPx,
		session.TurnstileConfig.Interaction.RequiredSettleMs,
	)); err != nil {
		t.Fatalf("expected solve to pass while retaining heuristic report: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/cloudflare/status?session_id="+session.ID, nil)
	w := httptest.NewRecorder()
	cc.HandleStatus(w, req)

	var resp struct {
		WidgetTelemetry *WidgetTelemetry `json:"widget_telemetry"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode status response: %v", err)
	}
	if resp.WidgetTelemetry == nil || resp.WidgetTelemetry.HeuristicReport == nil {
		t.Fatalf("expected heuristic report in solved status: %+v", resp.WidgetTelemetry)
	}
	if !resp.WidgetTelemetry.HeuristicReport.Flagged {
		t.Fatalf("expected solved status to retain heuristic flag: %+v", resp.WidgetTelemetry.HeuristicReport)
	}
}
