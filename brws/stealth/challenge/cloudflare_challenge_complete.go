package challenge

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// CompleteChallengeJS validates a JS challenge (PoW only).
func (cc *CloudflareChallenger) CompleteChallengeJS(sessionID string, solution *PoWSolution) (*CloudflareSolution, error) {
	if err := cc.ValidatePoW(sessionID, solution); err != nil {
		cc.recordFailedAttempt(sessionID)
		return nil, fmt.Errorf("PoW validation failed: %w", err)
	}

	cookie := cc.generateClearanceCookie(sessionID)

	cc.mu.Lock()
	if session, ok := cc.sessions[sessionID]; ok {
		session.Passed = true
		session.SolvedAt = time.Now()
		session.ClearanceCookie = cookie.Value
		session.Score = 0.0
		session.State = StateSolved
	}
	cc.mu.Unlock()

	return &CloudflareSolution{
		ClearanceCookie: cookie,
		SolvedAt:        time.Now(),
		SolveTimeMs:     solution.TimeMs,
		Method:          "cloudflare_js",
	}, nil
}

// CompleteChallengeManaged validates a managed challenge (PoW 30% + fp 30% + behavioral 40%).
func (cc *CloudflareChallenger) CompleteChallengeManaged(
	sessionID string,
	solution *PoWSolution,
	fp *FingerprintPayload,
	events []CaptchaEvent,
) (*CloudflareSolution, error) {
	// Solve time bounds: reject superhuman solve times (< 1.5s for managed)
	cc.mu.RLock()
	session, exists := cc.sessions[sessionID]
	cc.mu.RUnlock()
	if exists {
		elapsed := time.Since(session.CreatedAt)
		if elapsed < 1500*time.Millisecond {
			cc.recordFailedAttempt(sessionID)
			return nil, fmt.Errorf("solve time too fast: %dms (minimum 1500ms)", elapsed.Milliseconds())
		}
	}

	if err := cc.ValidatePoW(sessionID, solution); err != nil {
		cc.recordFailedAttempt(sessionID)
		return nil, fmt.Errorf("PoW validation failed: %w", err)
	}

	fpScore := cc.ValidateFingerprint(sessionID, fp)
	behScore := cc.ValidateBehavioral(sessionID, events)

	// Composite score: lower is better (more human-like)
	// Weights: PoW=0.30 (binary pass/fail, already passed), fp=0.30, behavioral=0.40
	compositeScore := fpScore*0.30 + behScore*0.40

	// Hard reject: if any single signal is extremely bot-like, reject regardless of composite
	if behScore > 0.90 || fpScore > 0.90 {
		compositeScore = math.Max(compositeScore, 0.55)
	}

	if compositeScore > 0.50 {
		cc.recordFailedAttempt(sessionID)
		return nil, fmt.Errorf("managed challenge failed: composite score %.2f exceeds threshold", compositeScore)
	}

	cookie := cc.generateClearanceCookie(sessionID)

	cc.mu.Lock()
	if s, ok := cc.sessions[sessionID]; ok {
		s.Passed = true
		s.SolvedAt = time.Now()
		s.ClearanceCookie = cookie.Value
		s.Score = compositeScore
		s.State = StateSolved
	}
	cc.mu.Unlock()

	return &CloudflareSolution{
		ClearanceCookie: cookie,
		SolvedAt:        time.Now(),
		SolveTimeMs:     solution.TimeMs,
		Method:          "cloudflare_managed",
	}, nil
}

// CompleteTurnstile validates a Turnstile challenge (PoW + light behavioral).
// Turnstile uses a simpler behavioral check than the managed challenge:
// it only requires minimum event count and basic sanity, mirroring
// real Turnstile which is lighter than the full managed challenge.
func (cc *CloudflareChallenger) CompleteTurnstile(
	sessionID string,
	solution *PoWSolution,
	events []CaptchaEvent,
) (*CloudflareSolution, error) {
	if err := cc.ValidatePoW(sessionID, solution); err != nil {
		cc.recordFailedAttempt(sessionID)
		return nil, fmt.Errorf("PoW validation failed: %w", err)
	}

	behScore := cc.ValidateBehavioral(sessionID, events)
	eventSpan := turnstileEventSpan(events)

	cc.mu.RLock()
	session, exists := cc.sessions[sessionID]
	cc.mu.RUnlock()
	lifecycleScore := 0.0
	snapshotScore := 0.0
	interactionScore := 0.0
	heuristicScore := 0.0
	var heuristicReport *TurnstileHeuristicReport
	if exists {
		switch {
		case session.TurnstileTelemetry.CallbackState.Error:
			cc.recordFailedAttempt(sessionID)
			return nil, fmt.Errorf("turnstile challenge failed: widget reported error state")
		case session.TurnstileTelemetry.CallbackState.Timeout:
			cc.recordFailedAttempt(sessionID)
			return nil, fmt.Errorf("turnstile challenge failed: widget reported timeout state")
		case session.TurnstilePresented &&
			(!session.TurnstileTelemetry.CallbackState.BeforeInteractive ||
				!session.TurnstileTelemetry.CallbackState.AfterInteractive):
			behScore = math.Max(behScore, 0.75)
		}
		lifecycleScore = evaluateTurnstileLifecycle(session, eventSpan)
		snapshotScore = evaluateTurnstileSnapshot(session.TurnstileSnapshot)
		interactionScore = evaluateTurnstileInteraction(session, events)
		heuristicReport = evaluateTurnstileHeuristics(session, events)
		if heuristicReport != nil {
			heuristicScore = heuristicReport.Score
		}
		if session.TurnstilePresented && session.TurnstileSnapshot == nil {
			snapshotScore = math.Max(snapshotScore, 0.95)
		}
	}

	mouseCount := 0
	mouseYConst := true
	lastMouseY := 0.0
	haveMouseY := false
	hasMouseDown := false
	hasMouseUp := false
	hasClick := false
	for _, e := range events {
		if e.Type == "mousemove" {
			mouseCount++
			if haveMouseY && math.Abs(e.Y-lastMouseY) > 2 {
				mouseYConst = false
			}
			lastMouseY = e.Y
			haveMouseY = true
		}
		switch e.Type {
		case "mousedown":
			hasMouseDown = true
		case "mouseup":
			hasMouseUp = true
		case "click":
			hasClick = true
		}
	}

	switch {
	case len(events) < 5:
		behScore = math.Max(behScore, 1.0)
	case mouseCount < 3:
		behScore = math.Max(behScore, 0.85)
	case eventSpan > 0 && eventSpan < 1100:
		behScore = math.Max(behScore, 0.80)
	case haveMouseY && mouseYConst:
		behScore = math.Max(behScore, 0.78)
	case !(hasMouseDown && hasMouseUp && hasClick):
		behScore = math.Max(behScore, 0.82)
	case behScore > 0.65:
		behScore = math.Max(behScore, 0.75)
	}

	compositeScore := behScore*0.40 + snapshotScore*0.20 + lifecycleScore*0.15 + interactionScore*0.25
	if lifecycleScore >= 0.90 || snapshotScore >= 0.90 || interactionScore >= 0.90 {
		compositeScore = math.Max(compositeScore, 0.85)
	}
	if eventSpan > 0 && eventSpan < 1100 {
		compositeScore = math.Max(compositeScore, 0.82)
	}
	if haveMouseY && mouseYConst {
		compositeScore = math.Max(compositeScore, 0.82)
	}
	if !(hasMouseDown && hasMouseUp && hasClick) {
		compositeScore = math.Max(compositeScore, 0.82)
	}
	if interactionScore >= 0.70 {
		compositeScore = math.Max(compositeScore, 0.83)
	}
	if exists && session.TurnstileConfig.RiskLevel == "critical" {
		if eventSpan > 0 && eventSpan < 1600 {
			compositeScore = math.Max(compositeScore, 0.86)
		}
		if interactionScore >= 0.55 {
			compositeScore = math.Max(compositeScore, 0.86)
		}
	}
	if heuristicScore >= 0.90 && (interactionScore >= 0.55 || behScore >= 0.70) {
		compositeScore = math.Max(compositeScore, 0.84)
	}

	if compositeScore > 0.70 {
		cc.mu.Lock()
		if session, ok := cc.sessions[sessionID]; ok {
			session.Score = compositeScore
			session.State = StateFailed
			session.TurnstileTelemetry.EventCount = len(events)
			session.TurnstileTelemetry.EventSpanMs = eventSpan
			session.TurnstileTelemetry.HeuristicReport = heuristicReport
			if len(events) > 0 {
				lastTS := events[len(events)-1].Timestamp
				if lastTS > 0 {
					session.TurnstileTelemetry.LastEventAt = time.UnixMilli(lastTS)
				}
			}
		}
		cc.mu.Unlock()
		cc.recordFailedAttempt(sessionID)
		return nil, fmt.Errorf("turnstile challenge failed: composite score %.2f exceeds threshold", compositeScore)
	}

	token := cc.issueTurnstileToken(sessionID)
	cookie := cc.generateClearanceCookie(sessionID)

	cc.mu.Lock()
	if session, ok := cc.sessions[sessionID]; ok {
		session.Passed = true
		session.SolvedAt = time.Now()
		session.ClearanceCookie = cookie.Value
		session.Score = behScore
		session.Score = compositeScore
		session.State = StateSolved
		session.TurnstileToken = token
		session.TurnstileTokenUsed = false
		session.TurnstileTelemetry.EventCount = len(events)
		session.TurnstileTelemetry.EventSpanMs = eventSpan
		if len(events) > 0 {
			lastTS := events[len(events)-1].Timestamp
			if lastTS > 0 {
				session.TurnstileTelemetry.LastEventAt = time.UnixMilli(lastTS)
			}
		}
		session.TurnstileTelemetry.HeuristicReport = heuristicReport
		if session.TurnstileTelemetry.CallbackCount == 0 {
			session.TurnstileTelemetry.RecordCallback("before-interactive")
			session.TurnstileTelemetry.RecordCallback("after-interactive")
		}
		session.TurnstileTelemetry.RecordCallback("success")
		session.TurnstileConfig.CallbackState = session.TurnstileTelemetry.CallbackState
	}
	cc.mu.Unlock()

	var telemetry *WidgetTelemetry
	cc.mu.RLock()
	if session, ok := cc.sessions[sessionID]; ok {
		copyTelemetry := session.TurnstileTelemetry
		telemetry = &copyTelemetry
	}
	cc.mu.RUnlock()

	return &CloudflareSolution{
		ClearanceCookie: cookie,
		TurnstileToken:  token.Value,
		Turnstile:       token,
		Telemetry:       telemetry,
		SolvedAt:        time.Now(),
		SolveTimeMs:     solution.TimeMs,
		Method:          "cloudflare_turnstile",
	}, nil
}

// turnstileEventSpan returns the time span in milliseconds across all events.
func turnstileEventSpan(events []CaptchaEvent) int64 {
	if len(events) < 2 {
		return 0
	}

	first := events[0].Timestamp
	last := events[0].Timestamp
	for _, event := range events[1:] {
		if event.Timestamp < first {
			first = event.Timestamp
		}
		if event.Timestamp > last {
			last = event.Timestamp
		}
	}
	if last <= first {
		return 0
	}
	return last - first
}

func evaluateTurnstileLifecycle(session *CloudflareChallengeSession, eventSpan int64) float64 {
	if session == nil {
		return 1.0
	}
	if session.TurnstilePresented &&
		(!session.TurnstileTelemetry.CallbackState.BeforeInteractive ||
			!session.TurnstileTelemetry.CallbackState.AfterInteractive) {
		return 1.0
	}

	score := 0.0
	weights := 0.0
	order := session.TurnstileTelemetry.CallbackOrder

	if !session.TurnstilePresented {
		score += 0.45
	}
	weights += 0.45

	if len(order) < 2 || !isValidTurnstileCallbackOrder(order) {
		score += 0.35
	}
	weights += 0.35

	if session.TurnstileTelemetry.DuplicateCallbacks > 0 {
		score += 0.10
	}
	weights += 0.10

	if eventSpan > 0 && eventSpan < 1100 {
		score += 0.10
	}
	weights += 0.10

	if session.TurnstileTelemetry.CallbackState.Timeout ||
		session.TurnstileTelemetry.CallbackState.Error ||
		session.TurnstileTelemetry.CallbackState.Expired {
		return 1.0
	}

	if weights == 0 {
		return 0
	}
	return score / weights
}

func isValidTurnstileCallbackOrder(order []string) bool {
	beforeIdx := -1
	afterIdx := -1

	for idx, name := range order {
		switch name {
		case "before-interactive":
			if beforeIdx == -1 {
				beforeIdx = idx
			}
		case "after-interactive":
			if afterIdx == -1 {
				afterIdx = idx
			}
		case "success":
			if afterIdx == -1 || idx < afterIdx {
				return false
			}
		case "timeout", "error", "expired":
			return false
		}
	}

	return beforeIdx >= 0 && afterIdx > beforeIdx
}

func evaluateTurnstileSnapshot(snapshot *TurnstileClientSnapshot) float64 {
	if snapshot == nil {
		return 1.0
	}

	score := 0.0
	weights := 0.0
	ua := strings.ToLower(strings.TrimSpace(snapshot.UserAgent))
	platform := strings.TrimSpace(snapshot.Platform)

	if snapshot.Webdriver ||
		strings.Contains(ua, "headless") ||
		strings.Contains(ua, "playwright") ||
		strings.Contains(ua, "selenium") {
		return 1.0
	}

	if ua == "" {
		score += 0.35
	}
	weights += 0.35

	weights += 0.30

	if snapshot.Language == "" || len(snapshot.Languages) == 0 || snapshot.Language != snapshot.Languages[0] {
		score += 0.10
	}
	weights += 0.10

	if snapshot.HardwareConcurrency <= 0 || snapshot.HardwareConcurrency > 64 {
		score += 0.05
	}
	weights += 0.05

	if snapshot.ScreenWidth < 640 || snapshot.ScreenHeight < 480 {
		score += 0.05
	}
	weights += 0.05

	if snapshot.ColorDepth != 24 && snapshot.ColorDepth != 30 && snapshot.ColorDepth != 32 {
		score += 0.05
	}
	weights += 0.05

	if snapshot.Timezone == "" {
		score += 0.05
	}
	weights += 0.05

	if !snapshot.CookieEnabled {
		score += 0.05
	}
	weights += 0.05

	switch {
	case strings.Contains(ua, "windows") && platform != "Win32":
		score += 0.10
	case strings.Contains(ua, "macintosh") && platform != "MacIntel":
		score += 0.10
	case strings.Contains(ua, "linux") && !strings.Contains(strings.ToLower(platform), "linux"):
		score += 0.10
	}
	weights += 0.10

	if weights == 0 {
		return 0
	}

	return math.Min(1.0, score/weights)
}

type turnstileEventInteractionSummary struct {
	HasMouseDown      bool
	HasMouseUp        bool
	HasClick          bool
	MoveCount         int
	HoldDurationMs    int
	DragDistancePx    int
	ApproachHoverMs   int
	ApproachMoveCount int
	ApproachSettleMs  int
	OvershootPx       int
	SettleDurationMs  int
	DirectionChanges  int
	FinalDragOffsetPx int
}

type turnstileIntervalSummary struct {
	PositiveCount int
	UniqueCount   int
	MaxIntervalMs int64
	PauseCount    int
	StdDevMs      float64
}

func summarizeTurnstileIntervals(events []CaptchaEvent) turnstileIntervalSummary {
	summary := turnstileIntervalSummary{}
	if len(events) < 2 {
		return summary
	}

	unique := make(map[int64]struct{})
	values := make([]float64, 0, len(events)-1)
	for idx := 1; idx < len(events); idx++ {
		diff := events[idx].Timestamp - events[idx-1].Timestamp
		if diff <= 0 {
			continue
		}
		summary.PositiveCount++
		unique[diff] = struct{}{}
		values = append(values, float64(diff))
		if diff > summary.MaxIntervalMs {
			summary.MaxIntervalMs = diff
		}
		if diff >= 120 {
			summary.PauseCount++
		}
	}
	summary.UniqueCount = len(unique)
	if len(values) == 0 {
		return summary
	}

	mean := 0.0
	for _, value := range values {
		mean += value
	}
	mean /= float64(len(values))

	variance := 0.0
	for _, value := range values {
		diff := value - mean
		variance += diff * diff
	}
	variance /= float64(len(values))
	summary.StdDevMs = math.Sqrt(variance)
	return summary
}

func expectedTurnstileInteractionGapMs(proof *TurnstileInteractionProof) int64 {
	if proof == nil {
		return 0
	}

	switch strings.TrimSpace(proof.Type) {
	case turnstileInteractionHold:
		hold := proof.HoldDurationMs
		if hold < 900 {
			hold = 900
		}
		return int64(hold + 220)
	case turnstileInteractionPrecision:
		dragMoves := proof.DragEventCount
		if dragMoves < 8 {
			dragMoves = 8
		}
		return int64(proof.ApproachHoverMs + proof.ApproachSettleMs + proof.SettleDurationMs + dragMoves*60 + 220)
	case turnstileInteractionDrag:
		dragMoves := proof.DragEventCount
		if dragMoves < 6 {
			dragMoves = 6
		}
		return int64(dragMoves*70 + 260)
	default:
		return 550
	}
}

func expectedTurnstilePresentationGapMs(proof *TurnstileInteractionProof) int64 {
	expected := expectedTurnstileInteractionGapMs(proof)
	if expected == 0 {
		return 0
	}
	return expected + 180
}

func evaluateTurnstileHeuristics(session *CloudflareChallengeSession, events []CaptchaEvent) *TurnstileHeuristicReport {
	report := &TurnstileHeuristicReport{
		Verdict: "low",
		Signals: make([]TurnstileHeuristicSignal, 0, 4),
	}
	if session == nil {
		return report
	}

	intervals := summarizeTurnstileIntervals(events)
	summary := summarizeTurnstileInteractionEvents(events)
	proof := session.TurnstileTelemetry.InteractionProof

	score := 0.0
	addSignal := func(name string, weight float64, detail string) {
		score += weight
		report.Signals = append(report.Signals, TurnstileHeuristicSignal{
			Name:   name,
			Weight: weight,
			Detail: detail,
		})
	}

	if proof != nil && !session.TurnstileTelemetry.AfterAt.IsZero() && !session.TurnstileTelemetry.InteractionAt.IsZero() {
		observedGap := session.TurnstileTelemetry.InteractionAt.Sub(session.TurnstileTelemetry.AfterAt).Milliseconds()
		expectedGap := expectedTurnstileInteractionGapMs(proof)
		if expectedGap > 0 && observedGap+120 < expectedGap {
			weight := 0.18
			if expectedGap-observedGap > 500 {
				weight = 0.42
			} else if expectedGap-observedGap > 250 {
				weight = 0.28
			}
			addSignal(
				"interaction_submitted_too_quickly",
				weight,
				fmt.Sprintf("observed %dms after after-interactive, expected >= %dms from proof", observedGap, expectedGap),
			)
		}
	}

	if proof != nil && !session.TurnstileTelemetry.PresentedAt.IsZero() && !session.TurnstileTelemetry.InteractionAt.IsZero() {
		observedGap := session.TurnstileTelemetry.InteractionAt.Sub(session.TurnstileTelemetry.PresentedAt).Milliseconds()
		expectedGap := expectedTurnstilePresentationGapMs(proof)
		if expectedGap > 0 && observedGap+160 < expectedGap {
			addSignal(
				"presented_to_interaction_gap_implausible",
				0.16,
				fmt.Sprintf("observed %dms from render to interaction, expected >= %dms", observedGap, expectedGap),
			)
		}
	}

	if intervals.PositiveCount >= 8 && intervals.UniqueCount <= 4 && intervals.StdDevMs < 26 {
		addSignal(
			"regular_event_cadence",
			0.16,
			fmt.Sprintf("only %d unique positive intervals with stddev %.1fms", intervals.UniqueCount, intervals.StdDevMs),
		)
	}

	if intervals.PositiveCount >= 8 && intervals.PauseCount == 0 && intervals.MaxIntervalMs < 120 {
		addSignal(
			"pause_free_pointer_trace",
			0.12,
			fmt.Sprintf("max interval %dms across %d positive intervals", intervals.MaxIntervalMs, intervals.PositiveCount),
		)
	}

	if proof != nil && strings.TrimSpace(proof.Type) == turnstileInteractionPrecision &&
		summary.DirectionChanges <= 1 && proof.DirectionChanges <= 1 &&
		proof.OvershootPx > 0 && proof.OvershootPx <= 22 &&
		proof.SettleDurationMs > 0 && proof.SettleDurationMs <= 240 {
		addSignal(
			"precision_variant_minimum_margin",
			0.10,
			fmt.Sprintf("precision proof stays close to minimums (overshoot=%d, settle=%d)", proof.OvershootPx, proof.SettleDurationMs),
		)
	}

	if score > 1 {
		score = 1
	}
	report.Score = score
	switch {
	case score >= 0.75:
		report.Verdict = "high"
	case score >= 0.35:
		report.Verdict = "medium"
	default:
		report.Verdict = "low"
	}
	report.Flagged = score >= 0.55
	if len(report.Signals) == 0 {
		report.Signals = nil
	}
	return report
}

func evaluateTurnstileInteraction(session *CloudflareChallengeSession, events []CaptchaEvent) float64 {
	if session == nil {
		return 1.0
	}

	config := session.TurnstileConfig.Interaction
	if config.Type == "" {
		config.Type = turnstileInteractionCheckbox
	}

	summary := summarizeTurnstileInteractionEvents(events)
	proof := session.TurnstileTelemetry.InteractionProof
	if session.TurnstilePresented && proof == nil {
		return 1.0
	}

	score := 0.0
	weights := 0.0
	precisionApproachFailed := false
	addPenalty := func(condition bool, weight float64) {
		if condition {
			score += weight
		}
		weights += weight
	}

	if proof != nil && proof.Type != "" && proof.Type != config.Type {
		return 1.0
	}

	switch config.Type {
	case turnstileInteractionHold:
		addPenalty(proof == nil || !proof.Completed, 0.30)
		addPenalty(proof == nil || proof.HoldDurationMs < config.RequiredHoldMs, 0.25)
		addPenalty(summary.HoldDurationMs < config.RequiredHoldMs, 0.25)
		addPenalty(!(summary.HasMouseDown && summary.HasMouseUp && summary.HasClick), 0.10)
		addPenalty(summary.MoveCount < 2, 0.10)
	case turnstileInteractionPrecision:
		requiredDistance := config.RequiredDragDistancePx + config.RequiredOvershootPx
		requiredDirectionChanges := config.RequiredDirectionChanges
		if requiredDirectionChanges <= 0 {
			requiredDirectionChanges = 1
		}
		targetZoneWidth := config.TargetZoneWidthPx
		if targetZoneWidth <= 0 {
			targetZoneWidth = 24
		}
		requiredApproachHoverMs := config.RequiredApproachHoverMs
		if requiredApproachHoverMs <= 0 {
			requiredApproachHoverMs = 220
		}
		requiredApproachMoves := config.RequiredApproachMoves
		if requiredApproachMoves <= 0 {
			requiredApproachMoves = 3
		}
		requiredApproachSettleMs := config.RequiredApproachSettleMs
		if requiredApproachSettleMs <= 0 {
			requiredApproachSettleMs = 90
		}
		precisionApproachFailed = proof == nil ||
			proof.ApproachHoverMs < requiredApproachHoverMs ||
			proof.ApproachMoveCount < requiredApproachMoves ||
			proof.ApproachSettleMs < requiredApproachSettleMs ||
			summary.ApproachHoverMs < requiredApproachHoverMs ||
			summary.ApproachMoveCount < requiredApproachMoves ||
			summary.ApproachSettleMs < requiredApproachSettleMs

		addPenalty(proof == nil || !proof.Completed, 0.18)
		addPenalty(proof == nil || proof.ApproachHoverMs < requiredApproachHoverMs, 0.10)
		addPenalty(proof == nil || proof.ApproachMoveCount < requiredApproachMoves, 0.08)
		addPenalty(proof == nil || proof.ApproachSettleMs < requiredApproachSettleMs, 0.08)
		addPenalty(proof == nil || proof.DragDistancePx < requiredDistance, 0.12)
		addPenalty(proof == nil || proof.DragEventCount < config.RequiredDragEventCount, 0.08)
		addPenalty(proof == nil || proof.OvershootPx < config.RequiredOvershootPx, 0.10)
		addPenalty(proof == nil || proof.SettleDurationMs < config.RequiredSettleMs, 0.10)
		addPenalty(proof == nil || proof.DirectionChanges < requiredDirectionChanges, 0.10)
		addPenalty(proof == nil || !turnstileReleaseWithinZone(proof.FinalDragOffsetPx, config.RequiredDragDistancePx, targetZoneWidth), 0.10)
		addPenalty(summary.ApproachHoverMs < requiredApproachHoverMs, 0.10)
		addPenalty(summary.ApproachMoveCount < requiredApproachMoves, 0.08)
		addPenalty(summary.ApproachSettleMs < requiredApproachSettleMs, 0.08)
		addPenalty(summary.DragDistancePx < requiredDistance, 0.12)
		addPenalty(summary.MoveCount < config.RequiredDragEventCount+2, 0.08)
		addPenalty(summary.OvershootPx < config.RequiredOvershootPx, 0.10)
		addPenalty(summary.SettleDurationMs < config.RequiredSettleMs, 0.10)
		addPenalty(summary.DirectionChanges < requiredDirectionChanges, 0.10)
		addPenalty(!turnstileReleaseWithinZone(summary.FinalDragOffsetPx, config.RequiredDragDistancePx, targetZoneWidth), 0.10)
		addPenalty(!(summary.HasMouseDown && summary.HasMouseUp && summary.HasClick), 0.10)
	case turnstileInteractionDrag:
		addPenalty(proof == nil || !proof.Completed, 0.30)
		addPenalty(proof == nil || proof.DragDistancePx < config.RequiredDragDistancePx, 0.20)
		addPenalty(proof == nil || proof.DragEventCount < config.RequiredDragEventCount, 0.10)
		addPenalty(summary.DragDistancePx < config.RequiredDragDistancePx, 0.20)
		addPenalty(summary.MoveCount < config.RequiredDragEventCount, 0.10)
		addPenalty(!(summary.HasMouseDown && summary.HasMouseUp && summary.HasClick), 0.10)
	default:
		addPenalty(proof == nil || !proof.Completed || proof.CheckboxClicks < 1, 0.35)
		addPenalty(!(summary.HasMouseDown && summary.HasMouseUp && summary.HasClick), 0.35)
		addPenalty(summary.MoveCount < 3, 0.10)
	}

	if weights == 0 {
		return 0.0
	}
	result := math.Min(1.0, score/weights)
	if config.Type == turnstileInteractionPrecision && precisionApproachFailed {
		return math.Max(0.74, result)
	}
	return result
}

func summarizeTurnstileInteractionEvents(events []CaptchaEvent) turnstileEventInteractionSummary {
	summary := turnstileEventInteractionSummary{}
	var downTS int64
	minX := math.MaxFloat64
	maxX := -math.MaxFloat64
	var downX float64
	var downY float64
	firstDownIndex := -1
	haveDown := false
	lastDragX := 0.0
	lastMoveTS := int64(0)
	lastDirection := 0

	for idx, event := range events {
		switch event.Type {
		case "mousemove":
			summary.MoveCount++
			if haveDown {
				if event.X < minX {
					minX = event.X
				}
				if event.X > maxX {
					maxX = event.X
				}
				delta := event.X - lastDragX
				if math.Abs(delta) >= 3 {
					direction := 1
					if delta < 0 {
						direction = -1
					}
					if lastDirection != 0 && direction != lastDirection {
						summary.DirectionChanges++
					}
					lastDirection = direction
				}
				lastDragX = event.X
				lastMoveTS = event.Timestamp
			}
		case "mousedown":
			summary.HasMouseDown = true
			if downTS == 0 {
				downTS = event.Timestamp
				firstDownIndex = idx
			}
			downX = event.X
			downY = event.Y
			haveDown = true
			minX = event.X
			maxX = event.X
			lastDragX = event.X
		case "mouseup":
			summary.HasMouseUp = true
			if downTS > 0 && event.Timestamp >= downTS {
				summary.HoldDurationMs = int(event.Timestamp - downTS)
			}
			if haveDown {
				if event.X < minX {
					minX = event.X
				}
				if event.X > maxX {
					maxX = event.X
				}
				summary.FinalDragOffsetPx = int(math.Round(event.X - downX))
				if maxX > event.X {
					summary.OvershootPx = int(math.Round(maxX - event.X))
				}
				if lastMoveTS > 0 && event.Timestamp >= lastMoveTS {
					summary.SettleDurationMs = int(event.Timestamp - lastMoveTS)
				}
			}
		case "click":
			summary.HasClick = true
		}
	}

	if haveDown && maxX >= minX {
		summary.DragDistancePx = int(math.Round(maxX - downX))
	}
	if firstDownIndex > 0 {
		approachMoves := 0
		firstApproachTS := int64(0)
		lastApproachTS := int64(0)
		for _, event := range events[:firstDownIndex] {
			if event.Type != "mousemove" {
				continue
			}
			if math.Abs(event.X-downX) > 28 || math.Abs(event.Y-downY) > 24 {
				continue
			}
			approachMoves++
			if firstApproachTS == 0 {
				firstApproachTS = event.Timestamp
			}
			lastApproachTS = event.Timestamp
		}
		summary.ApproachMoveCount = approachMoves
		if firstApproachTS > 0 && lastApproachTS >= firstApproachTS {
			summary.ApproachHoverMs = int(lastApproachTS - firstApproachTS)
			if downTS >= lastApproachTS {
				summary.ApproachSettleMs = int(downTS - lastApproachTS)
			}
		}
	}

	return summary
}

func turnstileReleaseWithinZone(offset, requiredDistance, zoneWidth int) bool {
	if requiredDistance <= 0 {
		requiredDistance = 0
	}
	if zoneWidth <= 0 {
		return offset >= requiredDistance
	}

	return offset >= requiredDistance && offset <= requiredDistance+zoneWidth
}
