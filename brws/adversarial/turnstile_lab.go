package adversarial

import (
	"net"
	"strings"
	"time"
)

const defaultTurnstileTokenTTL = 5 * time.Minute

const (
	turnstileInteractionCheckbox  = "checkbox"
	turnstileInteractionHold      = "hold"
	turnstileInteractionDrag      = "drag"
	turnstileInteractionPrecision = "drag_precision"
)

// TurnstileRetryPolicy models the widget retry behavior exposed to the client.
type TurnstileRetryPolicy struct {
	Mode       string `json:"mode"`
	IntervalMs int    `json:"interval_ms"`
}

// TurnstileRefreshPolicy models how the widget refreshes expired or timed-out challenges.
type TurnstileRefreshPolicy struct {
	Expired string `json:"expired"`
	Timeout string `json:"timeout"`
}

// TurnstileInteractionConfig describes the specific interaction the local widget expects.
type TurnstileInteractionConfig struct {
	Type                     string `json:"type"`
	RequiredHoldMs           int    `json:"required_hold_ms,omitempty"`
	RequiredDragDistancePx   int    `json:"required_drag_distance_px,omitempty"`
	RequiredDragEventCount   int    `json:"required_drag_event_count,omitempty"`
	DragTrackLengthPx        int    `json:"drag_track_length_px,omitempty"`
	RequiredApproachHoverMs  int    `json:"required_approach_hover_ms,omitempty"`
	RequiredApproachMoves    int    `json:"required_approach_moves,omitempty"`
	RequiredApproachSettleMs int    `json:"required_approach_settle_ms,omitempty"`
	RequiredOvershootPx      int    `json:"required_overshoot_px,omitempty"`
	RequiredSettleMs         int    `json:"required_settle_ms,omitempty"`
	RequiredDirectionChanges int    `json:"required_direction_changes,omitempty"`
	TargetZoneWidthPx        int    `json:"target_zone_width_px,omitempty"`
}

// TurnstileInteractionProof captures the interaction performed against the widget.
type TurnstileInteractionProof struct {
	Type              string `json:"type"`
	Completed         bool   `json:"completed"`
	CheckboxClicks    int    `json:"checkbox_clicks,omitempty"`
	HoldDurationMs    int    `json:"hold_duration_ms,omitempty"`
	DragDistancePx    int    `json:"drag_distance_px,omitempty"`
	DragEventCount    int    `json:"drag_event_count,omitempty"`
	ApproachHoverMs   int    `json:"approach_hover_duration_ms,omitempty"`
	ApproachMoveCount int    `json:"approach_move_count,omitempty"`
	ApproachSettleMs  int    `json:"approach_settle_duration_ms,omitempty"`
	OvershootPx       int    `json:"overshoot_px,omitempty"`
	SettleDurationMs  int    `json:"settle_duration_ms,omitempty"`
	DirectionChanges  int    `json:"direction_changes,omitempty"`
	FinalDragOffsetPx int    `json:"final_drag_offset_px,omitempty"`
}

// TurnstileHeuristicSignal captures one heuristic bot-detection indicator.
type TurnstileHeuristicSignal struct {
	Name   string  `json:"name"`
	Weight float64 `json:"weight"`
	Detail string  `json:"detail,omitempty"`
}

// TurnstileHeuristicReport summarizes post-solve heuristic analysis.
type TurnstileHeuristicReport struct {
	Score   float64                    `json:"score"`
	Verdict string                     `json:"verdict"`
	Flagged bool                       `json:"flagged"`
	Signals []TurnstileHeuristicSignal `json:"signals,omitempty"`
}

// TurnstileCallbackState tracks the current lifecycle callback state for a widget.
type TurnstileCallbackState struct {
	BeforeInteractive bool `json:"before_interactive"`
	AfterInteractive  bool `json:"after_interactive"`
	Success           bool `json:"success"`
	Expired           bool `json:"expired"`
	Timeout           bool `json:"timeout"`
	Error             bool `json:"error"`
}

// WidgetTelemetry captures widget callback ordering and event metadata.
type WidgetTelemetry struct {
	CallbackState      TurnstileCallbackState     `json:"callback_state"`
	CallbackOrder      []string                   `json:"callback_order,omitempty"`
	CallbackCount      int                        `json:"callback_count"`
	DuplicateCallbacks int                        `json:"duplicate_callbacks"`
	EventCount         int                        `json:"event_count"`
	EventSpanMs        int64                      `json:"event_span_ms,omitempty"`
	LastEventAt        time.Time                  `json:"last_event_at,omitempty"`
	PresentedAt        time.Time                  `json:"presented_at,omitempty"`
	SnapshotAt         time.Time                  `json:"snapshot_at,omitempty"`
	BeforeAt           time.Time                  `json:"before_interactive_at,omitempty"`
	AfterAt            time.Time                  `json:"after_interactive_at,omitempty"`
	InteractionAt      time.Time                  `json:"interaction_at,omitempty"`
	SuccessAt          time.Time                  `json:"success_at,omitempty"`
	LastCallbackAt     time.Time                  `json:"last_callback_at,omitempty"`
	ClientSnapshot     *TurnstileClientSnapshot   `json:"client_snapshot,omitempty"`
	InteractionProof   *TurnstileInteractionProof `json:"interaction_proof,omitempty"`
	HeuristicReport    *TurnstileHeuristicReport  `json:"heuristic_report,omitempty"`
}

// TurnstileClientSnapshot captures the browser state observed while the widget is rendered.
type TurnstileClientSnapshot struct {
	UserAgent           string   `json:"user_agent,omitempty"`
	Language            string   `json:"language,omitempty"`
	Languages           []string `json:"languages,omitempty"`
	Platform            string   `json:"platform,omitempty"`
	HardwareConcurrency int      `json:"hardware_concurrency"`
	Webdriver           bool     `json:"webdriver"`
	ScreenWidth         int      `json:"screen_width"`
	ScreenHeight        int      `json:"screen_height"`
	ColorDepth          int      `json:"color_depth"`
	Timezone            string   `json:"timezone,omitempty"`
	MaxTouchPoints      int      `json:"max_touch_points"`
	CookieEnabled       bool     `json:"cookie_enabled"`
}

// TurnstileWidgetConfig captures the local widget contract returned by init.
type TurnstileWidgetConfig struct {
	Mode            string                     `json:"mode"`
	RiskLevel       string                     `json:"risk_level"`
	Appearance      string                     `json:"appearance"`
	Execution       string                     `json:"execution"`
	Action          string                     `json:"action,omitempty"`
	CData           string                     `json:"cdata,omitempty"`
	Theme           string                     `json:"theme"`
	Size            string                     `json:"size"`
	Interaction     TurnstileInteractionConfig `json:"interaction"`
	TokenTTLSeconds int                        `json:"token_ttl_seconds"`
	RetryPolicy     TurnstileRetryPolicy       `json:"retry_policy"`
	RefreshPolicy   TurnstileRefreshPolicy     `json:"refresh_policy"`
	CallbackState   TurnstileCallbackState     `json:"callback_state"`
}

// LabTurnstileToken represents a locally issued Turnstile token for owned-environment testing.
type LabTurnstileToken struct {
	Value     string    `json:"value"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Hostname  string    `json:"hostname"`
	Action    string    `json:"action,omitempty"`
	CData     string    `json:"cdata,omitempty"`
}

// VerificationResult mirrors a siteverify-style response for locally issued tokens.
type VerificationResult struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts,omitempty"`
	Hostname    string   `json:"hostname,omitempty"`
	Action      string   `json:"action,omitempty"`
	CData       string   `json:"cdata,omitempty"`
	ErrorCodes  []string `json:"error_codes,omitempty"`
}

func defaultTurnstileWidgetConfig(sessionID string) TurnstileWidgetConfig {
	cdata := sanitizeTurnstileData(sessionID, 32)
	if cdata == "" {
		cdata = "lab"
	}

	return TurnstileWidgetConfig{
		Mode:       "managed",
		RiskLevel:  "low",
		Appearance: "always",
		Execution:  "render",
		Action:     "managed",
		CData:      cdata,
		Theme:      "auto",
		Size:       "normal",
		Interaction: TurnstileInteractionConfig{
			Type: turnstileInteractionCheckbox,
		},
		TokenTTLSeconds: int(defaultTurnstileTokenTTL / time.Second),
		RetryPolicy: TurnstileRetryPolicy{
			Mode:       "auto",
			IntervalMs: 8000,
		},
		RefreshPolicy: TurnstileRefreshPolicy{
			Expired: "auto",
			Timeout: "auto",
		},
	}
}

func turnstileWidgetConfigForRisk(sessionID string, detectionScore float64) TurnstileWidgetConfig {
	cfg := defaultTurnstileWidgetConfig(sessionID)
	switch {
	case detectionScore >= 0.90:
		cfg.RiskLevel = "critical"
		cfg.Interaction = TurnstileInteractionConfig{
			Type:                     turnstileInteractionPrecision,
			RequiredDragDistancePx:   162,
			RequiredDragEventCount:   8,
			DragTrackLengthPx:        236,
			RequiredApproachHoverMs:  220,
			RequiredApproachMoves:    3,
			RequiredApproachSettleMs: 90,
			RequiredOvershootPx:      18,
			RequiredSettleMs:         180,
			RequiredDirectionChanges: 1,
			TargetZoneWidthPx:        24,
		}
	case detectionScore >= 0.75:
		cfg.RiskLevel = "high"
		cfg.Interaction = TurnstileInteractionConfig{
			Type:                   turnstileInteractionDrag,
			RequiredDragDistancePx: 160,
			RequiredDragEventCount: 6,
			DragTrackLengthPx:      220,
		}
	case detectionScore >= 0.45:
		cfg.RiskLevel = "medium"
		cfg.Interaction = TurnstileInteractionConfig{
			Type:           turnstileInteractionHold,
			RequiredHoldMs: 900,
		}
	default:
		cfg.RiskLevel = "low"
		cfg.Interaction = TurnstileInteractionConfig{
			Type: turnstileInteractionCheckbox,
		}
	}
	return cfg
}

func sanitizeTurnstileData(value string, maxLen int) string {
	if value == "" || maxLen <= 0 {
		return ""
	}

	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_' || r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
		if b.Len() >= maxLen {
			break
		}
	}

	return strings.Trim(b.String(), "_")
}

func (wt *WidgetTelemetry) recordCallback(name string) {
	now := time.Now().UTC()
	if wt.PresentedAt.IsZero() {
		wt.PresentedAt = now
	}

	duplicate := false
	switch name {
	case "before-interactive":
		duplicate = wt.CallbackState.BeforeInteractive
		wt.CallbackState.BeforeInteractive = true
		if wt.BeforeAt.IsZero() {
			wt.BeforeAt = now
		}
	case "after-interactive":
		duplicate = wt.CallbackState.AfterInteractive
		wt.CallbackState.AfterInteractive = true
		if wt.AfterAt.IsZero() {
			wt.AfterAt = now
		}
	case "success":
		duplicate = wt.CallbackState.Success
		wt.CallbackState.Success = true
		if wt.SuccessAt.IsZero() {
			wt.SuccessAt = now
		}
	case "expired":
		duplicate = wt.CallbackState.Expired
		wt.CallbackState.Expired = true
	case "timeout":
		duplicate = wt.CallbackState.Timeout
		wt.CallbackState.Timeout = true
	case "error":
		duplicate = wt.CallbackState.Error
		wt.CallbackState.Error = true
	}

	if name != "" {
		if duplicate {
			wt.DuplicateCallbacks++
		}
		wt.CallbackOrder = append(wt.CallbackOrder, name)
		wt.CallbackCount++
		wt.LastCallbackAt = now
	}
}

func (wt *WidgetTelemetry) recordInteraction(proof *TurnstileInteractionProof) {
	if proof == nil {
		return
	}

	copyProof := *proof
	copyProof.Type = strings.TrimSpace(copyProof.Type)
	wt.InteractionProof = &copyProof
	wt.InteractionAt = time.Now().UTC()
}

func isLoopbackOrLocalHost(host string) bool {
	if host == "" {
		return false
	}

	host = strings.TrimSpace(strings.ToLower(host))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	return ip.IsLoopback()
}
