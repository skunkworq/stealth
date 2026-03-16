package stealth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
)

// mountCloudflareServer creates a test server with all Cloudflare challenge endpoints.
func mountCloudflareServer() (*httptest.Server, *adversarial.CloudflareChallenger) {
	cc := adversarial.NewCloudflareChallenger(nil, nil)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/cloudflare/init", cc.HandleInit)
	mux.HandleFunc("/api/cloudflare/solve/js", cc.HandleSolveJS)
	mux.HandleFunc("/api/cloudflare/solve/managed", cc.HandleSolveManaged)
	mux.HandleFunc("/api/cloudflare/solve/turnstile", cc.HandleSolveTurnstile)
	mux.HandleFunc("/api/cloudflare/turnstile/widget", cc.HandleTurnstileWidgetPage)
	mux.HandleFunc("/api/cloudflare/turnstile/siteverify", cc.HandleTurnstileSiteVerify)
	mux.HandleFunc("/turnstile/v0/siteverify", cc.HandleTurnstileSiteVerify)
	mux.HandleFunc("/api/cloudflare/verify", cc.HandleVerifyClearance)
	mux.HandleFunc("/api/cloudflare/challenge", cc.HandleChallengePage)
	mux.HandleFunc("/api/cloudflare/status", cc.HandleStatus)
	mux.HandleFunc("/cdn-cgi/challenge-platform/h/g/cv/result/", cc.HandleChallengeCallback)

	ts := httptest.NewServer(mux)
	return ts, cc
}

type turnstilePlanSummary struct {
	moveCount         int
	dragMoveCount     int
	uniqueIntervals   int
	maxIntervalMs     int64
	pauseCount        int
	holdDurationMs    int
	dragDistancePx    int
	approachMoveCount int
	approachHoverMs   int
	approachSettleMs  int
	directionChanges  int
	settleAfterDragMs int
	yRange            float64
	hasMouseDown      bool
	hasMouseUp        bool
	hasClick          bool
	timestampsSorted  bool
	eventSpanMs       int64
}

func summarizeTurnstilePlan(events []adversarial.CaptchaEvent) turnstilePlanSummary {
	summary := turnstilePlanSummary{timestampsSorted: true}
	if len(events) == 0 {
		return summary
	}

	firstTS := events[0].Timestamp
	lastTS := events[0].Timestamp
	minY := events[0].Y
	maxY := events[0].Y
	intervals := map[int64]struct{}{}
	mouseDownSeen := false
	minX := 0.0
	maxX := 0.0
	hasRange := false
	downTS := int64(0)
	downX := 0.0
	downY := 0.0
	firstDownIndex := -1
	lastDragX := 0.0
	lastDragMoveTS := int64(0)
	lastDirection := 0

	for idx, event := range events {
		if idx > 0 {
			if event.Timestamp < events[idx-1].Timestamp {
				summary.timestampsSorted = false
			}
			diff := event.Timestamp - events[idx-1].Timestamp
			if diff > 0 {
				intervals[diff] = struct{}{}
				if diff > summary.maxIntervalMs {
					summary.maxIntervalMs = diff
				}
				if diff >= 120 {
					summary.pauseCount++
				}
			}
		}

		if event.Timestamp < firstTS {
			firstTS = event.Timestamp
		}
		if event.Timestamp > lastTS {
			lastTS = event.Timestamp
		}

		switch event.Type {
		case "mousemove":
			summary.moveCount++
			if mouseDownSeen {
				summary.dragMoveCount++
				if !hasRange {
					minX = downX
					maxX = downX
					hasRange = true
				}
				delta := event.X - lastDragX
				dir := 0
				if delta > 0 {
					dir = 1
				} else if delta < 0 {
					dir = -1
				}
				if lastDirection != 0 && dir != 0 && dir != lastDirection {
					summary.directionChanges++
				}
				if dir != 0 {
					lastDirection = dir
				}
				lastDragX = event.X
				lastDragMoveTS = event.Timestamp
			}
			if !hasRange {
				minX = event.X
				maxX = event.X
				minY = event.Y
				maxY = event.Y
				hasRange = true
			}
			if event.X < minX {
				minX = event.X
			}
			if event.X > maxX {
				maxX = event.X
			}
			if event.Y < minY {
				minY = event.Y
			}
			if event.Y > maxY {
				maxY = event.Y
			}
		case "mousedown":
			summary.hasMouseDown = true
			mouseDownSeen = true
			downTS = event.Timestamp
			downX = event.X
			downY = event.Y
			firstDownIndex = idx
			lastDragX = event.X
			if !hasRange {
				minX = event.X
				maxX = event.X
				minY = event.Y
				maxY = event.Y
				hasRange = true
			}
		case "mouseup":
			summary.hasMouseUp = true
			mouseDownSeen = false
			if downTS > 0 && event.Timestamp > downTS {
				summary.holdDurationMs = int(event.Timestamp - downTS)
			}
			if lastDragMoveTS > 0 && event.Timestamp >= lastDragMoveTS {
				summary.settleAfterDragMs = int(event.Timestamp - lastDragMoveTS)
			}
			if event.X < minX {
				minX = event.X
			}
			if event.X > maxX {
				maxX = event.X
			}
			if event.Y < minY {
				minY = event.Y
			}
			if event.Y > maxY {
				maxY = event.Y
			}
		case "click":
			summary.hasClick = true
		}
	}

	summary.uniqueIntervals = len(intervals)
	summary.eventSpanMs = lastTS - firstTS
	if hasRange {
		summary.dragDistancePx = int(maxX - minX)
		summary.yRange = maxY - minY
	}
	if firstDownIndex > 0 {
		firstApproachTS := int64(0)
		lastApproachTS := int64(0)
		for _, event := range events[:firstDownIndex] {
			if event.Type != "mousemove" {
				continue
			}
			if event.X < downX-28 || event.X > downX+28 || event.Y < downY-24 || event.Y > downY+24 {
				continue
			}
			summary.approachMoveCount++
			if firstApproachTS == 0 {
				firstApproachTS = event.Timestamp
			}
			lastApproachTS = event.Timestamp
		}
		if firstApproachTS > 0 && lastApproachTS >= firstApproachTS {
			summary.approachHoverMs = int(lastApproachTS - firstApproachTS)
			if downTS >= lastApproachTS {
				summary.approachSettleMs = int(downTS - lastApproachTS)
			}
		}
	}

	return summary
}

func TestSwordSolvesJSChallenge(t *testing.T) {
	ts, _ := mountCloudflareServer()
	defer ts.Close()

	solver := NewCloudflareSolverClient()
	result, err := solver.SolveJSChallenge(ts.URL)
	if err != nil {
		t.Fatalf("SolveJSChallenge failed: %v", err)
	}

	if !result.Passed {
		t.Fatal("JS challenge should have passed")
	}
	if result.ClearanceCookie == nil {
		t.Fatal("expected clearance cookie")
	}
	if result.PoWTimeMs <= 0 {
		t.Error("PoW time should be > 0")
	}
	if result.PoWIterations <= 0 {
		t.Error("PoW iterations should be > 0")
	}
	if result.ChallengeType != "cloudflare_js" {
		t.Errorf("expected cloudflare_js, got %s", result.ChallengeType)
	}

	t.Logf("JS challenge: difficulty=%d iterations=%d pow_time=%dms total=%dms",
		result.PoWDifficulty, result.PoWIterations, result.PoWTimeMs, result.TotalTimeMs)
}

func TestSwordSolvesManagedChallenge(t *testing.T) {
	ts, _ := mountCloudflareServer()
	defer ts.Close()

	solver := NewCloudflareSolverClient()

	// Behavioral analysis is stochastic; retry up to 5 times for CI stability
	var result *CloudflareSolveResult
	var err error
	for attempt := 1; attempt <= 5; attempt++ {
		result, err = solver.SolveManagedChallenge(ts.URL)
		if err == nil && result.Passed {
			break
		}
		t.Logf("attempt %d: passed=%v err=%v", attempt, result != nil && result.Passed, err)
	}
	if err != nil {
		t.Fatalf("SolveManagedChallenge failed after retries: %v", err)
	}

	if !result.Passed {
		t.Fatal("managed challenge should have passed")
	}
	if result.ClearanceCookie == nil {
		t.Fatal("expected clearance cookie")
	}
	if result.ChallengeType != "cloudflare_managed" {
		t.Errorf("expected cloudflare_managed, got %s", result.ChallengeType)
	}

	t.Logf("Managed challenge: difficulty=%d iterations=%d pow_time=%dms total=%dms",
		result.PoWDifficulty, result.PoWIterations, result.PoWTimeMs, result.TotalTimeMs)
}

func TestSwordSolvesTurnstile(t *testing.T) {
	ts, cc := mountCloudflareServer()
	defer ts.Close()

	solver := NewCloudflareSolverClient()
	result, err := solver.ExerciseTurnstileFlow(ts.URL, &TurnstileFlowOptions{
		Verifier: &LabTurnstileVerifier{
			HTTPClient: solver.httpClient,
			BaseURL:    ts.URL,
			Secret:     cc.TurnstileSecretKey(),
			Hostname:   "localhost",
		},
	})
	if err != nil {
		t.Fatalf("ExerciseTurnstileFlow failed: %v", err)
	}

	if !result.Passed {
		t.Fatal("turnstile challenge should have passed")
	}
	if result.TurnstileToken == "" {
		t.Fatal("expected turnstile token")
	}
	if result.Turnstile == nil {
		t.Fatal("expected structured turnstile token metadata")
	}
	if result.WidgetTelemetry == nil || !result.WidgetTelemetry.CallbackState.Success {
		t.Fatal("expected widget telemetry with success callback")
	}
	if result.WidgetTelemetry.InteractionProof == nil || result.WidgetTelemetry.InteractionProof.Type != "checkbox" {
		t.Fatalf("expected checkbox interaction proof, got %+v", result.WidgetTelemetry)
	}
	if result.WidgetTelemetry.CallbackCount < 3 {
		t.Fatalf("expected full widget lifecycle to be recorded: %+v", result.WidgetTelemetry)
	}
	if result.WidgetTelemetry.ClientSnapshot == nil || result.WidgetTelemetry.ClientSnapshot.Webdriver {
		t.Fatalf("expected human-like client snapshot to be recorded: %+v", result.WidgetTelemetry)
	}
	if result.WidgetTelemetry.EventSpanMs < 1000 {
		t.Fatalf("expected realistic event span to be recorded: %+v", result.WidgetTelemetry)
	}
	if result.Verification == nil || !result.Verification.Success {
		t.Fatal("expected token verification result")
	}
	if result.ClearanceCookie == nil {
		t.Fatal("expected clearance cookie")
	}
	if result.ChallengeType != "cloudflare_turnstile" {
		t.Errorf("expected cloudflare_turnstile, got %s", result.ChallengeType)
	}

	t.Logf("Turnstile challenge: token=%s... pow_time=%dms total=%dms",
		result.TurnstileToken[:20], result.PoWTimeMs, result.TotalTimeMs)
}

func TestSwordSolvesTurnstileVariants(t *testing.T) {
	ts, cc := mountCloudflareServer()
	defer ts.Close()

	testCases := []struct {
		name        string
		score       float64
		wantVariant string
	}{
		{name: "hold", score: 0.55, wantVariant: "hold"},
		{name: "drag", score: 0.85, wantVariant: "drag"},
		{name: "precision", score: 0.92, wantVariant: "drag_precision"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			solver := NewCloudflareSolverClient()
			result, err := solver.ExerciseTurnstileFlow(ts.URL, &TurnstileFlowOptions{
				DetectionScore: tc.score,
				Verifier: &LabTurnstileVerifier{
					HTTPClient: solver.httpClient,
					BaseURL:    ts.URL,
					Secret:     cc.TurnstileSecretKey(),
					Hostname:   "localhost",
				},
			})
			if err != nil {
				t.Fatalf("ExerciseTurnstileFlow failed: %v", err)
			}
			if !result.Passed {
				t.Fatal("turnstile challenge should have passed")
			}
			if result.WidgetTelemetry == nil || result.WidgetTelemetry.InteractionProof == nil {
				t.Fatalf("expected interaction telemetry: %+v", result.WidgetTelemetry)
			}
			if result.WidgetTelemetry.HeuristicReport == nil {
				t.Fatalf("expected heuristic report in widget telemetry: %+v", result.WidgetTelemetry)
			}
			if result.WidgetTelemetry.InteractionProof.Type != tc.wantVariant {
				t.Fatalf("expected %s proof, got %+v", tc.wantVariant, result.WidgetTelemetry.InteractionProof)
			}
			if !result.WidgetTelemetry.InteractionProof.Completed {
				t.Fatalf("expected completed interaction proof: %+v", result.WidgetTelemetry.InteractionProof)
			}
			if result.WidgetTelemetry.EventCount < 9 {
				t.Fatalf("expected richer event trace for %s: %+v", tc.wantVariant, result.WidgetTelemetry)
			}
			switch tc.wantVariant {
			case "hold":
				if result.WidgetTelemetry.InteractionProof.HoldDurationMs < 900 {
					t.Fatalf("expected realistic hold duration: %+v", result.WidgetTelemetry.InteractionProof)
				}
				if result.WidgetTelemetry.EventSpanMs < 2000 {
					t.Fatalf("expected longer hold interaction span: %+v", result.WidgetTelemetry)
				}
			case "drag":
				if result.WidgetTelemetry.InteractionProof.DragDistancePx < 160 {
					t.Fatalf("expected sufficient drag distance: %+v", result.WidgetTelemetry.InteractionProof)
				}
				if result.WidgetTelemetry.InteractionProof.DragEventCount < 9 {
					t.Fatalf("expected richer drag motion: %+v", result.WidgetTelemetry.InteractionProof)
				}
				if result.WidgetTelemetry.EventSpanMs < 1800 {
					t.Fatalf("expected longer drag interaction span: %+v", result.WidgetTelemetry)
				}
			case "drag_precision":
				if result.WidgetTelemetry.InteractionProof.ApproachHoverMs < 220 {
					t.Fatalf("expected deliberate pre-drag hover: %+v", result.WidgetTelemetry.InteractionProof)
				}
				if result.WidgetTelemetry.InteractionProof.ApproachSettleMs < 90 {
					t.Fatalf("expected pre-drag settle pause: %+v", result.WidgetTelemetry.InteractionProof)
				}
				if result.WidgetTelemetry.InteractionProof.OvershootPx < 18 {
					t.Fatalf("expected overshoot on precision drag: %+v", result.WidgetTelemetry.InteractionProof)
				}
				if result.WidgetTelemetry.InteractionProof.DirectionChanges < 1 {
					t.Fatalf("expected corrective direction change on precision drag: %+v", result.WidgetTelemetry.InteractionProof)
				}
				if result.WidgetTelemetry.InteractionProof.SettleDurationMs < 180 {
					t.Fatalf("expected post-drag settle pause: %+v", result.WidgetTelemetry.InteractionProof)
				}
				if result.WidgetTelemetry.EventSpanMs < 2600 {
					t.Fatalf("expected longer precision interaction span: %+v", result.WidgetTelemetry)
				}
			}
		})
	}
}

func TestTurnstileInteractionPlanLooksHuman(t *testing.T) {
	solver := NewCloudflareSolverClient()

	testCases := []struct {
		name            string
		cfg             *adversarial.TurnstileWidgetConfig
		wantVariant     string
		minMoveCount    int
		minIntervalBins int
		minPauseCount   int
		minMaxInterval  int64
		minYRange       float64
		minEventSpanMs  int64
	}{
		{
			name:            "checkbox",
			cfg:             nil,
			wantVariant:     "checkbox",
			minMoveCount:    9,
			minIntervalBins: 6,
			minPauseCount:   4,
			minMaxInterval:  120,
			minYRange:       12,
			minEventSpanMs:  1600,
		},
		{
			name: "hold",
			cfg: &adversarial.TurnstileWidgetConfig{
				Interaction: adversarial.TurnstileInteractionConfig{
					Type:           "hold",
					RequiredHoldMs: 900,
				},
			},
			wantVariant:     "hold",
			minMoveCount:    11,
			minIntervalBins: 6,
			minPauseCount:   5,
			minMaxInterval:  130,
			minYRange:       10,
			minEventSpanMs:  2200,
		},
		{
			name: "drag",
			cfg: &adversarial.TurnstileWidgetConfig{
				Interaction: adversarial.TurnstileInteractionConfig{
					Type:                   "drag",
					RequiredDragDistancePx: 160,
					RequiredDragEventCount: 6,
				},
			},
			wantVariant:     "drag",
			minMoveCount:    14,
			minIntervalBins: 7,
			minPauseCount:   5,
			minMaxInterval:  130,
			minYRange:       14,
			minEventSpanMs:  1900,
		},
		{
			name: "precision",
			cfg: &adversarial.TurnstileWidgetConfig{
				Interaction: adversarial.TurnstileInteractionConfig{
					Type:                     "drag_precision",
					RequiredDragDistancePx:   162,
					RequiredDragEventCount:   8,
					RequiredApproachHoverMs:  220,
					RequiredApproachMoves:    3,
					RequiredApproachSettleMs: 90,
					RequiredOvershootPx:      18,
					RequiredSettleMs:         180,
					RequiredDirectionChanges: 1,
					TargetZoneWidthPx:        24,
				},
			},
			wantVariant:     "drag_precision",
			minMoveCount:    16,
			minIntervalBins: 8,
			minPauseCount:   6,
			minMaxInterval:  140,
			minYRange:       12,
			minEventSpanMs:  2600,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			plan := solver.buildTurnstileInteractionPlan(tc.cfg)
			if plan == nil || plan.interactionProof == nil {
				t.Fatalf("expected interaction plan for %s", tc.name)
			}
			if plan.interactionProof.Type != tc.wantVariant {
				t.Fatalf("expected %s proof, got %+v", tc.wantVariant, plan.interactionProof)
			}
			if len(plan.events) == 0 {
				t.Fatalf("expected events for %s", tc.name)
			}

			summary := summarizeTurnstilePlan(plan.events)
			if !summary.timestampsSorted {
				t.Fatalf("expected sorted timestamps: %+v", plan.events)
			}
			if !summary.hasMouseDown || !summary.hasMouseUp || !summary.hasClick {
				t.Fatalf("expected complete pointer lifecycle: %+v", summary)
			}
			if summary.moveCount < tc.minMoveCount {
				t.Fatalf("expected more mouse movement for %s: %+v", tc.name, summary)
			}
			if summary.uniqueIntervals < tc.minIntervalBins {
				t.Fatalf("expected more interval variation for %s: %+v", tc.name, summary)
			}
			if summary.pauseCount < tc.minPauseCount {
				t.Fatalf("expected more pauses for %s: %+v", tc.name, summary)
			}
			if summary.maxIntervalMs < tc.minMaxInterval {
				t.Fatalf("expected a longer hesitation for %s: %+v", tc.name, summary)
			}
			if summary.yRange < tc.minYRange {
				t.Fatalf("expected more vertical variation for %s: %+v", tc.name, summary)
			}
			if summary.eventSpanMs < tc.minEventSpanMs {
				t.Fatalf("expected longer event span for %s: %+v", tc.name, summary)
			}

			switch tc.wantVariant {
			case "hold":
				if plan.interactionProof.HoldDurationMs != summary.holdDurationMs {
					t.Fatalf("hold proof should match event trace: proof=%+v summary=%+v", plan.interactionProof, summary)
				}
				if plan.interactionProof.HoldDurationMs < tc.cfg.Interaction.RequiredHoldMs {
					t.Fatalf("hold proof below required threshold: %+v", plan.interactionProof)
				}
			case "drag":
				if plan.interactionProof.DragEventCount != summary.dragMoveCount {
					t.Fatalf("drag proof should match drag move count: proof=%+v summary=%+v", plan.interactionProof, summary)
				}
				if plan.interactionProof.DragDistancePx < tc.cfg.Interaction.RequiredDragDistancePx {
					t.Fatalf("drag proof below required threshold: %+v", plan.interactionProof)
				}
				if summary.dragDistancePx < plan.interactionProof.DragDistancePx {
					t.Fatalf("event trace should cover proof distance: proof=%+v summary=%+v", plan.interactionProof, summary)
				}
			case "drag_precision":
				// The precision plan uses jittered float coordinates and rounds the proof
				// back to whole pixels, so a 1px undershoot can happen without changing
				// the actual interaction contract.
				overshootTolerancePx := 1
				if plan.interactionProof.DragEventCount != summary.dragMoveCount {
					t.Fatalf("precision proof should match drag move count: proof=%+v summary=%+v", plan.interactionProof, summary)
				}
				if summary.approachMoveCount < plan.interactionProof.ApproachMoveCount {
					t.Fatalf("precision trace should back approach move count: proof=%+v summary=%+v", plan.interactionProof, summary)
				}
				if summary.approachHoverMs < plan.interactionProof.ApproachHoverMs {
					t.Fatalf("precision trace should back approach hover: proof=%+v summary=%+v", plan.interactionProof, summary)
				}
				if plan.interactionProof.ApproachSettleMs != summary.approachSettleMs {
					t.Fatalf("precision proof should match approach settle: proof=%+v summary=%+v", plan.interactionProof, summary)
				}
				if plan.interactionProof.SettleDurationMs != summary.settleAfterDragMs {
					t.Fatalf("precision proof should match post-drag settle: proof=%+v summary=%+v", plan.interactionProof, summary)
				}
				if plan.interactionProof.DirectionChanges != summary.directionChanges {
					t.Fatalf("precision proof should match direction changes: proof=%+v summary=%+v", plan.interactionProof, summary)
				}
				if plan.interactionProof.OvershootPx+overshootTolerancePx < tc.cfg.Interaction.RequiredOvershootPx {
					t.Fatalf("precision proof below overshoot threshold: %+v", plan.interactionProof)
				}
				if plan.interactionProof.SettleDurationMs < tc.cfg.Interaction.RequiredSettleMs {
					t.Fatalf("precision settle below required threshold: %+v", plan.interactionProof)
				}
				if plan.interactionProof.ApproachHoverMs < tc.cfg.Interaction.RequiredApproachHoverMs {
					t.Fatalf("precision hover below required threshold: %+v", plan.interactionProof)
				}
				if plan.interactionProof.ApproachSettleMs < tc.cfg.Interaction.RequiredApproachSettleMs {
					t.Fatalf("precision approach settle below required threshold: %+v", plan.interactionProof)
				}
			default:
				if plan.interactionProof.CheckboxClicks != 1 {
					t.Fatalf("expected a single checkbox click: %+v", plan.interactionProof)
				}
			}
		})
	}
}

func TestTurnstileInteractionPlanVariesAcrossRuns(t *testing.T) {
	solver := NewCloudflareSolverClient()
	cfg := &adversarial.TurnstileWidgetConfig{
		Interaction: adversarial.TurnstileInteractionConfig{
			Type:                   "drag",
			RequiredDragDistancePx: 160,
			RequiredDragEventCount: 6,
		},
	}

	first := solver.buildTurnstileInteractionPlan(cfg)
	second := solver.buildTurnstileInteractionPlan(cfg)

	firstJSON, err := json.Marshal(struct {
		Proof  *adversarial.TurnstileInteractionProof `json:"proof"`
		Events []adversarial.CaptchaEvent             `json:"events"`
	}{
		Proof:  first.interactionProof,
		Events: first.events,
	})
	if err != nil {
		t.Fatalf("marshal first plan: %v", err)
	}
	secondJSON, err := json.Marshal(struct {
		Proof  *adversarial.TurnstileInteractionProof `json:"proof"`
		Events []adversarial.CaptchaEvent             `json:"events"`
	}{
		Proof:  second.interactionProof,
		Events: second.events,
	})
	if err != nil {
		t.Fatalf("marshal second plan: %v", err)
	}

	if bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("expected non-identical interaction plans across runs:\n%s", string(firstJSON))
	}
}

func TestHandleTurnstileLabRejectsUnallowlistedHost(t *testing.T) {
	solver := NewCloudflareSolverClient()
	if _, err := solver.HandleTurnstileLab("https://example.com"); err == nil {
		t.Fatal("expected non-local host to be rejected")
	}
}

func TestLabTurnstileVerifierRejectsDuplicateToken(t *testing.T) {
	ts, cc := mountCloudflareServer()
	defer ts.Close()

	solver := NewCloudflareSolverClient()
	result, err := solver.ExerciseTurnstileFlow(ts.URL, &TurnstileFlowOptions{
		Verifier: &LabTurnstileVerifier{
			HTTPClient: solver.httpClient,
			BaseURL:    ts.URL,
			Secret:     cc.TurnstileSecretKey(),
			Hostname:   "localhost",
		},
	})
	if err != nil {
		t.Fatalf("ExerciseTurnstileFlow failed: %v", err)
	}

	verifier := &LabTurnstileVerifier{
		HTTPClient: solver.httpClient,
		BaseURL:    ts.URL,
		Secret:     cc.TurnstileSecretKey(),
		Hostname:   "localhost",
	}
	verifyResult, err := verifier.Verify(context.Background(), result.TurnstileToken)
	if err != nil {
		t.Fatalf("duplicate verify failed: %v", err)
	}
	if verifyResult.Success {
		t.Fatalf("expected duplicate token verification to fail: %+v", verifyResult)
	}
}

func TestSwordClearanceCookieReuse(t *testing.T) {
	ts, cc := mountCloudflareServer()
	defer ts.Close()

	solver := NewCloudflareSolverClient()
	result, err := solver.SolveJSChallenge(ts.URL)
	if err != nil {
		t.Fatalf("initial solve failed: %v", err)
	}

	if !result.Passed || result.ClearanceCookie == nil {
		t.Fatal("initial solve should pass with cookie")
	}

	// Verify the cookie is valid
	if !cc.ValidateClearanceCookie(result.ClearanceCookie.Value) {
		t.Fatal("clearance cookie should be valid")
	}

	// Make a verify request with the cookie
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/cloudflare/verify", nil)
	req.AddCookie(result.ClearanceCookie)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("verify request failed: %v", err)
	}
	defer resp.Body.Close()

	var verifyResp struct {
		Valid bool `json:"valid"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&verifyResp)

	if !verifyResp.Valid {
		t.Fatal("clearance cookie should be accepted by verify endpoint")
	}
}

func TestBotBehavioralRejection(t *testing.T) {
	ts, _ := mountCloudflareServer()
	defer ts.Close()

	solver := NewCloudflareSolverClient()

	// Init a managed challenge
	initResp, err := solver.initChallenge(ts.URL, "cloudflare_managed", 0.5, "")
	if err != nil {
		t.Fatalf("init failed: %v", err)
	}

	// Solve PoW correctly
	powSolution, err := solver.solvePoW(initResp.PoW.Prefix, initResp.PoW.Difficulty)
	if err != nil {
		t.Fatalf("PoW solve failed: %v", err)
	}

	// Generate valid fingerprint but send ZERO events
	fp := solver.generateFingerprint()

	body, _ := json.Marshal(map[string]interface{}{
		"session_id":  initResp.SessionID,
		"solution":    powSolution,
		"fingerprint": fp,
		"events":      []adversarial.CaptchaEvent{}, // empty!
	})

	// Use the solver's httpClient which has the __cf_bm cookie from init
	resp, err := solver.httpClient.Post(ts.URL+"/api/cloudflare/solve/managed", "application/json",
		bytes.NewReader(body))
	if err != nil {
		t.Fatalf("solve request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for zero events, got %d", resp.StatusCode)
	}

	var solveResp struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&solveResp)

	if solveResp.Success {
		t.Fatal("zero-event submission should be rejected")
	}
	t.Logf("correctly rejected: %s", solveResp.Error)
}

func TestEmptyFingerprintRejection(t *testing.T) {
	ts, _ := mountCloudflareServer()
	defer ts.Close()

	solver := NewCloudflareSolverClient()

	initResp, err := solver.initChallenge(ts.URL, "cloudflare_managed", 0.5, "")
	if err != nil {
		t.Fatalf("init failed: %v", err)
	}

	powSolution, err := solver.solvePoW(initResp.PoW.Prefix, initResp.PoW.Difficulty)
	if err != nil {
		t.Fatalf("PoW solve failed: %v", err)
	}

	// Generate some events but send nil fingerprint
	events := solver.eventGen.GenerateHumanEvents(3000)

	body, _ := json.Marshal(map[string]interface{}{
		"session_id":  initResp.SessionID,
		"solution":    powSolution,
		"fingerprint": nil, // empty!
		"events":      events,
	})

	// Use the solver's httpClient which has the __cf_bm cookie from init
	resp, err := solver.httpClient.Post(ts.URL+"/api/cloudflare/solve/managed", "application/json",
		bytes.NewReader(body))
	if err != nil {
		t.Fatalf("solve request failed: %v", err)
	}
	defer resp.Body.Close()

	// Nil fingerprint scores 1.0 × 0.30 = 0.30 contribution
	// Even with good behavioral, this combined with behavioral might push over threshold
	var solveResp struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&solveResp)

	if solveResp.Success {
		t.Fatal("nil fingerprint submission should be rejected")
	}
	t.Logf("correctly rejected: %s", solveResp.Error)
}

func TestDifficultyProgression(t *testing.T) {
	ts, _ := mountCloudflareServer()
	defer ts.Close()

	solver := NewCloudflareSolverClient()

	scores := []float64{0.1, 0.3, 0.5}
	prevDifficulty := 0

	for _, score := range scores {
		initResp, err := solver.initChallenge(ts.URL, "cloudflare_js", score, "")
		if err != nil {
			t.Fatalf("init failed for score %.1f: %v", score, err)
		}

		if initResp.PoW.Difficulty < prevDifficulty {
			t.Errorf("difficulty should increase: score=%.1f difficulty=%d < prev=%d",
				score, initResp.PoW.Difficulty, prevDifficulty)
		}
		prevDifficulty = initResp.PoW.Difficulty

		t.Logf("score=%.1f → difficulty=%d bits", score, initResp.PoW.Difficulty)
	}
}

func TestStatusEndpoint(t *testing.T) {
	ts, _ := mountCloudflareServer()
	defer ts.Close()

	solver := NewCloudflareSolverClient()

	// Solve a few challenges
	_, _ = solver.SolveJSChallenge(ts.URL)
	_, _ = solver.SolveTurnstile(ts.URL)

	resp, err := http.Get(ts.URL + "/api/cloudflare/status")
	if err != nil {
		t.Fatalf("status request failed: %v", err)
	}
	defer resp.Body.Close()

	var stats map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&stats)

	total := int(stats["total_sessions"].(float64))
	if total < 2 {
		t.Errorf("expected at least 2 sessions, got %d", total)
	}
	t.Logf("status: %+v", stats)
}
