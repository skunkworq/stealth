package cloudflare

import (
	"net"
	"strings"
	"time"

	"github.com/skunkworq/stealth/brws/stealth/challenge"
)

const defaultTurnstileTokenTTL = 5 * time.Minute

const (
	turnstileInteractionCheckbox    = "checkbox"
	turnstileInteractionHold        = "hold"
	turnstileInteractionDrag        = "drag"
	turnstileInteractionPrecision   = "drag_precision"
	turnstileInteractionRotate      = "rotate"
	turnstileInteractionSlidePuzzle = "slide_puzzle"
)

// Type aliases that re-export the canonical definitions from brws/stealth/challenge.
// This lets lab/research code in this package use the same types without re-defining them.
type (
	TurnstileRetryPolicy       = challenge.TurnstileRetryPolicy
	TurnstileRefreshPolicy     = challenge.TurnstileRefreshPolicy
	TurnstileInteractionConfig = challenge.TurnstileInteractionConfig
	TurnstileInteractionProof  = challenge.TurnstileInteractionProof
	TurnstileHeuristicSignal   = challenge.TurnstileHeuristicSignal
	TurnstileHeuristicReport   = challenge.TurnstileHeuristicReport
	TurnstileCallbackState     = challenge.TurnstileCallbackState
	WidgetTelemetry            = challenge.WidgetTelemetry
	TurnstileClientSnapshot    = challenge.TurnstileClientSnapshot
	TurnstileWidgetConfig      = challenge.TurnstileWidgetConfig
	LabTurnstileToken          = challenge.LabTurnstileToken
	VerificationResult         = challenge.VerificationResult
	CloudflareChallengeSession = challenge.CloudflareChallengeSession
	PoWChallenge               = challenge.PoWChallenge
	PoWSolution                = challenge.PoWSolution
)

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
	case detectionScore >= 0.95:
		// Maximum risk: visual puzzle (rotate or slide)
		cfg.RiskLevel = "extreme"
		cfg.Interaction = turnstileRotateConfig(270) // default target 270°
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

// turnstileRotateConfig returns a rotate challenge configuration.
func turnstileRotateConfig(targetDeg int) TurnstileInteractionConfig {
	return TurnstileInteractionConfig{
		Type:                 turnstileInteractionRotate,
		TargetAngleDeg:       targetDeg,
		AngleToleranceDeg:    15,
		DialRadiusPx:         80,
		MinRotationEvents:    10,
		RequiredOvershootDeg: 8, // must overshoot target then correct back
	}
}

// turnstileSlidePuzzleConfig returns a slide puzzle challenge configuration.
func turnstileSlidePuzzleConfig(targetXPx int) TurnstileInteractionConfig {
	return TurnstileInteractionConfig{
		Type:                 turnstileInteractionSlidePuzzle,
		TargetSlideXPx:       targetXPx,
		SlideTolerancePx:     8,
		SlideTrackWidthPx:    300,
		MinSlideEvents:       12,
		RequiredSlideYJitter: 3, // humans wobble ≥3px on Y axis during horizontal drag
	}
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
