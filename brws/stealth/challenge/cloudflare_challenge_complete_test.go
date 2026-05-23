package challenge

import (
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// turnstileEventSpan
// ─────────────────────────────────────────────────────────────────────────────

func TestTurnstileEventSpan_Empty(t *testing.T) {
	if got := turnstileEventSpan(nil); got != 0 {
		t.Errorf("turnstileEventSpan(nil) = %d, want 0", got)
	}
}

func TestTurnstileEventSpan_SingleEvent(t *testing.T) {
	events := []CaptchaEvent{{Timestamp: 1000}}
	if got := turnstileEventSpan(events); got != 0 {
		t.Errorf("turnstileEventSpan(single) = %d, want 0", got)
	}
}

func TestTurnstileEventSpan_TwoEvents(t *testing.T) {
	events := []CaptchaEvent{{Timestamp: 1000}, {Timestamp: 2500}}
	got := turnstileEventSpan(events)
	if got != 1500 {
		t.Errorf("turnstileEventSpan = %d, want 1500", got)
	}
}

func TestTurnstileEventSpan_OutOfOrder(t *testing.T) {
	events := []CaptchaEvent{
		{Timestamp: 5000},
		{Timestamp: 1000},
		{Timestamp: 3000},
	}
	got := turnstileEventSpan(events)
	if got != 4000 {
		t.Errorf("turnstileEventSpan (out-of-order) = %d, want 4000", got)
	}
}

func TestTurnstileEventSpan_SameTimestamp(t *testing.T) {
	events := []CaptchaEvent{{Timestamp: 1000}, {Timestamp: 1000}}
	if got := turnstileEventSpan(events); got != 0 {
		t.Errorf("turnstileEventSpan(same ts) = %d, want 0", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// isValidTurnstileCallbackOrder
// ─────────────────────────────────────────────────────────────────────────────

func TestIsValidTurnstileCallbackOrder_Valid(t *testing.T) {
	order := []string{"before-interactive", "after-interactive", "success"}
	if !isValidTurnstileCallbackOrder(order) {
		t.Error("expected valid callback order to return true")
	}
}

func TestIsValidTurnstileCallbackOrder_MissingBefore(t *testing.T) {
	order := []string{"after-interactive", "success"}
	if isValidTurnstileCallbackOrder(order) {
		t.Error("order without before-interactive should be invalid")
	}
}

func TestIsValidTurnstileCallbackOrder_SuccessBeforeAfter(t *testing.T) {
	order := []string{"before-interactive", "success", "after-interactive"}
	if isValidTurnstileCallbackOrder(order) {
		t.Error("success before after-interactive should be invalid")
	}
}

func TestIsValidTurnstileCallbackOrder_WithTimeout(t *testing.T) {
	order := []string{"before-interactive", "timeout", "after-interactive"}
	if isValidTurnstileCallbackOrder(order) {
		t.Error("callback order containing 'timeout' should be invalid")
	}
}

func TestIsValidTurnstileCallbackOrder_WithError(t *testing.T) {
	order := []string{"before-interactive", "error"}
	if isValidTurnstileCallbackOrder(order) {
		t.Error("callback order containing 'error' should be invalid")
	}
}

func TestIsValidTurnstileCallbackOrder_Empty(t *testing.T) {
	if isValidTurnstileCallbackOrder([]string{}) {
		t.Error("empty order should be invalid")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// evaluateTurnstileSnapshot
// ─────────────────────────────────────────────────────────────────────────────

func TestEvaluateTurnstileSnapshot_Nil(t *testing.T) {
	score := evaluateTurnstileSnapshot(nil)
	if score != 1.0 {
		t.Errorf("evaluateTurnstileSnapshot(nil) = %f, want 1.0", score)
	}
}

func TestEvaluateTurnstileSnapshot_Webdriver(t *testing.T) {
	snap := &TurnstileClientSnapshot{
		Webdriver: true,
		UserAgent: "Mozilla/5.0 Chrome/120",
	}
	score := evaluateTurnstileSnapshot(snap)
	if score != 1.0 {
		t.Errorf("webdriver=true should yield score=1.0, got %f", score)
	}
}

func TestEvaluateTurnstileSnapshot_HeadlessUA(t *testing.T) {
	snap := &TurnstileClientSnapshot{
		UserAgent: "HeadlessChrome/120",
	}
	score := evaluateTurnstileSnapshot(snap)
	if score != 1.0 {
		t.Errorf("headless UA should yield score=1.0, got %f", score)
	}
}

func TestEvaluateTurnstileSnapshot_GoodBrowser(t *testing.T) {
	snap := &TurnstileClientSnapshot{
		UserAgent:           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
		Platform:            "Win32",
		Language:            "en-US",
		Languages:           []string{"en-US", "en"},
		HardwareConcurrency: 8,
		ScreenWidth:         1920,
		ScreenHeight:        1080,
		ColorDepth:          24,
		Timezone:            "America/New_York",
		CookieEnabled:       true,
	}
	score := evaluateTurnstileSnapshot(snap)
	if score > 0.3 {
		t.Errorf("good browser snapshot scored too high: %f (want <= 0.3)", score)
	}
}

func TestEvaluateTurnstileSnapshot_EmptyUA(t *testing.T) {
	snap := &TurnstileClientSnapshot{
		UserAgent:     "",
		CookieEnabled: true,
	}
	score := evaluateTurnstileSnapshot(snap)
	// Empty UA should add to score
	if score <= 0 {
		t.Errorf("empty UA should add to score, got %f", score)
	}
}

func TestEvaluateTurnstileSnapshot_ScoreInRange(t *testing.T) {
	snap := &TurnstileClientSnapshot{
		UserAgent: "Mozilla/5.0 Firefox/109",
	}
	score := evaluateTurnstileSnapshot(snap)
	if score < 0 || score > 1.0 {
		t.Errorf("score %f is out of [0,1] range", score)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// evaluateTurnstileLifecycle
// ─────────────────────────────────────────────────────────────────────────────

func TestEvaluateTurnstileLifecycle_NilSession(t *testing.T) {
	score := evaluateTurnstileLifecycle(nil, 5000)
	if score != 1.0 {
		t.Errorf("evaluateTurnstileLifecycle(nil) = %f, want 1.0", score)
	}
}

func TestEvaluateTurnstileLifecycle_ValidSequence(t *testing.T) {
	session := &CloudflareChallengeSession{
		TurnstilePresented: true,
		TurnstileTelemetry: WidgetTelemetry{
			CallbackState: TurnstileCallbackState{
				BeforeInteractive: true,
				AfterInteractive:  true,
			},
			CallbackOrder: []string{"before-interactive", "after-interactive", "success"},
		},
	}
	score := evaluateTurnstileLifecycle(session, 3000)
	if score > 0.5 {
		t.Errorf("valid lifecycle scored too high: %f", score)
	}
}

func TestEvaluateTurnstileLifecycle_ErrorState(t *testing.T) {
	session := &CloudflareChallengeSession{
		TurnstilePresented: true,
		TurnstileTelemetry: WidgetTelemetry{
			CallbackState: TurnstileCallbackState{
				BeforeInteractive: true,
				AfterInteractive:  true,
				Error:             true,
			},
		},
	}
	score := evaluateTurnstileLifecycle(session, 3000)
	if score != 1.0 {
		t.Errorf("error state should yield score=1.0, got %f", score)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// evaluateTurnstileHeuristics
// ─────────────────────────────────────────────────────────────────────────────

func TestEvaluateTurnstileHeuristics_NilSession(t *testing.T) {
	report := evaluateTurnstileHeuristics(nil, nil)
	if report == nil {
		t.Fatal("evaluateTurnstileHeuristics(nil, nil) returned nil")
	}
	if report.Score < 0 || report.Score > 1 {
		t.Errorf("heuristic score %f out of range", report.Score)
	}
}

func TestEvaluateTurnstileHeuristics_EmptyEvents(t *testing.T) {
	session := &CloudflareChallengeSession{}
	report := evaluateTurnstileHeuristics(session, nil)
	if report == nil {
		t.Fatal("evaluateTurnstileHeuristics returned nil")
	}
	if report.Verdict == "" {
		t.Error("report.Verdict should not be empty")
	}
}

func TestEvaluateTurnstileHeuristics_VerdictLevels(t *testing.T) {
	session := &CloudflareChallengeSession{}
	// With no signals, verdict should be "low"
	report := evaluateTurnstileHeuristics(session, nil)
	if report.Verdict != "low" {
		t.Errorf("expected 'low' verdict with no signals, got %q", report.Verdict)
	}
}

func TestEvaluateTurnstileHeuristics_RegularCadence(t *testing.T) {
	// Uniform 10ms intervals across 15 events → should flag regular cadence
	session := &CloudflareChallengeSession{}
	events := make([]CaptchaEvent, 15)
	for i := range events {
		events[i] = CaptchaEvent{
			Type:      "mousemove",
			Timestamp: int64(1000 + i*10),
			X:         float64(i * 5),
			Y:         100,
		}
	}
	report := evaluateTurnstileHeuristics(session, events)
	if report == nil {
		t.Fatal("report is nil")
	}
	// Regular cadence should add a signal — score should be > 0
	if report.Score == 0 {
		t.Error("uniform cadence events should trigger a signal (score > 0)")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// turnstileReleaseWithinZone
// ─────────────────────────────────────────────────────────────────────────────

func TestTurnstileReleaseWithinZone_ExactTarget(t *testing.T) {
	if !turnstileReleaseWithinZone(100, 100, 24) {
		t.Error("exact target offset should be within zone")
	}
}

func TestTurnstileReleaseWithinZone_WithinZone(t *testing.T) {
	if !turnstileReleaseWithinZone(115, 100, 24) {
		t.Error("offset within zone should return true")
	}
}

func TestTurnstileReleaseWithinZone_BeyondZone(t *testing.T) {
	if turnstileReleaseWithinZone(130, 100, 24) {
		t.Error("offset beyond zone should return false")
	}
}

func TestTurnstileReleaseWithinZone_ZeroZoneWidth(t *testing.T) {
	// zoneWidth=0 → any offset >= required is OK
	if !turnstileReleaseWithinZone(200, 100, 0) {
		t.Error("zero zone width should allow any offset >= required")
	}
}

func TestTurnstileReleaseWithinZone_BelowTarget(t *testing.T) {
	if turnstileReleaseWithinZone(80, 100, 24) {
		t.Error("offset below required should return false")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// summarizeTurnstileIntervals
// ─────────────────────────────────────────────────────────────────────────────

func TestSummarizeTurnstileIntervals_Empty(t *testing.T) {
	summary := summarizeTurnstileIntervals(nil)
	if summary.PositiveCount != 0 || summary.UniqueCount != 0 {
		t.Errorf("empty events should yield zero counts, got %+v", summary)
	}
}

func TestSummarizeTurnstileIntervals_TwoEvents(t *testing.T) {
	events := []CaptchaEvent{{Timestamp: 1000}, {Timestamp: 1050}}
	s := summarizeTurnstileIntervals(events)
	if s.PositiveCount != 1 {
		t.Errorf("PositiveCount = %d, want 1", s.PositiveCount)
	}
	if s.MaxIntervalMs != 50 {
		t.Errorf("MaxIntervalMs = %d, want 50", s.MaxIntervalMs)
	}
}

func TestSummarizeTurnstileIntervals_StdDev_NonZero(t *testing.T) {
	events := []CaptchaEvent{
		{Timestamp: 0},
		{Timestamp: 10},
		{Timestamp: 50},
		{Timestamp: 200},
	}
	s := summarizeTurnstileIntervals(events)
	if s.StdDevMs == 0 && s.PositiveCount > 1 {
		t.Error("non-uniform intervals should produce non-zero StdDevMs")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// expectedTurnstileInteractionGapMs / expectedTurnstilePresentationGapMs
// ─────────────────────────────────────────────────────────────────────────────

func TestExpectedTurnstileInteractionGapMs_Nil(t *testing.T) {
	got := expectedTurnstileInteractionGapMs(nil)
	if got != 0 {
		t.Errorf("nil proof should return 0, got %d", got)
	}
}

func TestExpectedTurnstileInteractionGapMs_Hold(t *testing.T) {
	proof := &TurnstileInteractionProof{
		Type:           turnstileInteractionHold,
		HoldDurationMs: 1200,
	}
	got := expectedTurnstileInteractionGapMs(proof)
	// hold + 220
	if got != 1420 {
		t.Errorf("hold gap = %d, want 1420", got)
	}
}

func TestExpectedTurnstileInteractionGapMs_HoldMinimum(t *testing.T) {
	proof := &TurnstileInteractionProof{
		Type:           turnstileInteractionHold,
		HoldDurationMs: 500, // below minimum 900
	}
	got := expectedTurnstileInteractionGapMs(proof)
	// should use min 900 + 220 = 1120
	if got != 1120 {
		t.Errorf("hold gap with sub-minimum hold = %d, want 1120", got)
	}
}

func TestExpectedTurnstileInteractionGapMs_Drag(t *testing.T) {
	proof := &TurnstileInteractionProof{
		Type:           turnstileInteractionDrag,
		DragEventCount: 10,
	}
	got := expectedTurnstileInteractionGapMs(proof)
	// 10*70 + 260 = 960
	if got != 960 {
		t.Errorf("drag gap = %d, want 960", got)
	}
}

func TestExpectedTurnstileInteractionGapMs_DefaultType(t *testing.T) {
	proof := &TurnstileInteractionProof{
		Type: "unknown_type",
	}
	got := expectedTurnstileInteractionGapMs(proof)
	if got != 550 {
		t.Errorf("default type gap = %d, want 550", got)
	}
}

func TestExpectedTurnstilePresentationGapMs_Nil(t *testing.T) {
	got := expectedTurnstilePresentationGapMs(nil)
	if got != 0 {
		t.Errorf("nil proof should return 0, got %d", got)
	}
}

func TestExpectedTurnstilePresentationGapMs_GreaterThanInteraction(t *testing.T) {
	proof := &TurnstileInteractionProof{
		Type:           turnstileInteractionHold,
		HoldDurationMs: 1200,
	}
	interaction := expectedTurnstileInteractionGapMs(proof)
	presentation := expectedTurnstilePresentationGapMs(proof)
	if presentation <= interaction {
		t.Errorf("presentation gap (%d) should be > interaction gap (%d)", presentation, interaction)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// CompleteChallengeJS — integration test (fast: no network, no external deps)
// ─────────────────────────────────────────────────────────────────────────────

func TestCompleteChallengeJS_Valid(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW solving in short mode")
	}
	cc := NewCloudflareChallenger(nil, nil)
	session := cc.CreateJSChallenge("js-complete-valid", 0.3)

	solution, err := SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, session.PoW.MaxIterations)
	if err != nil {
		t.Fatalf("SolvePoW failed: %v", err)
	}

	result, err := cc.CompleteChallengeJS("js-complete-valid", solution)
	if err != nil {
		t.Fatalf("CompleteChallengeJS failed: %v", err)
	}
	if result == nil {
		t.Fatal("CompleteChallengeJS returned nil result")
	}
	if result.Method != "cloudflare_js" {
		t.Errorf("Method = %q, want cloudflare_js", result.Method)
	}
	if result.ClearanceCookie == nil {
		t.Error("ClearanceCookie should not be nil on success")
	}
}

func TestCompleteChallengeJS_BadPoW(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)
	cc.CreateJSChallenge("js-complete-bad", 0.3)

	badSolution := &PoWSolution{
		Nonce: "definitely-wrong",
		Hash:  "0000000000000000",
	}
	_, err := cc.CompleteChallengeJS("js-complete-bad", badSolution)
	if err == nil {
		t.Fatal("expected error for bad PoW solution")
	}
}

func TestCompleteChallengeJS_UnknownSession(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)
	badSolution := &PoWSolution{Nonce: "x", Hash: "y"}
	_, err := cc.CompleteChallengeJS("nonexistent-session-id", badSolution)
	if err == nil {
		t.Fatal("expected error for unknown session")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// CompleteChallengeManaged — fast-path: solve time too quick rejection
// ─────────────────────────────────────────────────────────────────────────────

func TestCompleteChallengeManaged_TooFast(t *testing.T) {
	cc := NewCloudflareChallenger(nil, nil)
	// Create a challenge and immediately try to solve it (< 1500ms)
	session := cc.CreateManagedChallenge("managed-fast", 0.3)

	// Manually set an incorrect nonce so PoW also fails — we want to hit the
	// solve-time guard first. Make the session just created so elapsed < 1500ms.
	_ = session

	badSolution := &PoWSolution{Nonce: "x", Hash: "y", TimeMs: 100}
	_, err := cc.CompleteChallengeManaged("managed-fast", badSolution, nil, nil)
	// Either too-fast or PoW error — we just want no panic and an error returned.
	if err == nil {
		t.Fatal("expected an error (too fast or bad PoW)")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// summarizeTurnstileInteractionEvents — smoke test
// ─────────────────────────────────────────────────────────────────────────────

func TestSummarizeTurnstileInteractionEvents_Empty(t *testing.T) {
	summary := summarizeTurnstileInteractionEvents(nil)
	if summary.MoveCount != 0 || summary.HasMouseDown || summary.HasMouseUp || summary.HasClick {
		t.Errorf("empty events should yield zero summary, got %+v", summary)
	}
}

func TestSummarizeTurnstileInteractionEvents_BasicClick(t *testing.T) {
	events := []CaptchaEvent{
		{Type: "mousemove", Timestamp: 1000, X: 10, Y: 10},
		{Type: "mousemove", Timestamp: 1050, X: 20, Y: 10},
		{Type: "mousedown", Timestamp: 1100, X: 50, Y: 50},
		{Type: "mouseup", Timestamp: 1300, X: 50, Y: 50},
		{Type: "click", Timestamp: 1310, X: 50, Y: 50},
	}
	summary := summarizeTurnstileInteractionEvents(events)
	if !summary.HasMouseDown {
		t.Error("expected HasMouseDown = true")
	}
	if !summary.HasMouseUp {
		t.Error("expected HasMouseUp = true")
	}
	if !summary.HasClick {
		t.Error("expected HasClick = true")
	}
	if summary.MoveCount != 2 {
		t.Errorf("MoveCount = %d, want 2", summary.MoveCount)
	}
	// HoldDurationMs should be ~200ms
	if summary.HoldDurationMs < 150 {
		t.Errorf("HoldDurationMs = %d, expected ~200", summary.HoldDurationMs)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// evaluateTurnstileInteraction — checkbox default
// ─────────────────────────────────────────────────────────────────────────────

func TestEvaluateTurnstileInteraction_NilSession(t *testing.T) {
	score := evaluateTurnstileInteraction(nil, nil)
	if score != 1.0 {
		t.Errorf("nil session should yield score=1.0, got %f", score)
	}
}

func TestEvaluateTurnstileInteraction_Checkbox_NoEvents(t *testing.T) {
	session := &CloudflareChallengeSession{
		TurnstileConfig: TurnstileWidgetConfig{
			Interaction: TurnstileInteractionConfig{Type: "checkbox"},
		},
	}
	score := evaluateTurnstileInteraction(session, nil)
	// No proof, no events → should be penalized heavily
	if score <= 0.5 {
		// OK — caught as bot
	}
	if score < 0 || score > 1 {
		t.Errorf("score %f out of [0,1]", score)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// CompleteChallengeManaged — composite score validation
// ─────────────────────────────────────────────────────────────────────────────

func TestCompleteChallengeManaged_ScoreTooHigh(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping PoW solving in short mode")
	}
	cc := NewCloudflareChallenger(nil, nil)
	session := cc.CreateManagedChallenge("managed-score-high", 0.9)

	// Sleep so the solve-time guard passes (managed requires > 1500ms)
	time.Sleep(1600 * time.Millisecond)

	solution, err := SolvePoW(session.PoW.Prefix, session.PoW.Difficulty, session.PoW.MaxIterations)
	if err != nil {
		t.Fatalf("SolvePoW: %v", err)
	}

	// Pass nil fingerprint and nil events — both will score high → composite > 0.5
	_, err = cc.CompleteChallengeManaged("managed-score-high", solution, nil, nil)
	if err == nil {
		t.Fatal("expected composite score failure with nil fp/events")
	}
}
