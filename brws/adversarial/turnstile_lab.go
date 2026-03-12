package adversarial

import (
	"net"
	"strings"
	"time"
)

const defaultTurnstileTokenTTL = 5 * time.Minute

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
	CallbackState TurnstileCallbackState `json:"callback_state"`
	CallbackOrder []string               `json:"callback_order,omitempty"`
	CallbackCount int                    `json:"callback_count"`
	EventCount    int                    `json:"event_count"`
	LastEventAt   time.Time              `json:"last_event_at,omitempty"`
}

// TurnstileWidgetConfig captures the local widget contract returned by init.
type TurnstileWidgetConfig struct {
	Mode            string                 `json:"mode"`
	Appearance      string                 `json:"appearance"`
	Execution       string                 `json:"execution"`
	Action          string                 `json:"action,omitempty"`
	CData           string                 `json:"cdata,omitempty"`
	Theme           string                 `json:"theme"`
	Size            string                 `json:"size"`
	TokenTTLSeconds int                    `json:"token_ttl_seconds"`
	RetryPolicy     TurnstileRetryPolicy   `json:"retry_policy"`
	RefreshPolicy   TurnstileRefreshPolicy `json:"refresh_policy"`
	CallbackState   TurnstileCallbackState `json:"callback_state"`
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
		Mode:            "managed",
		Appearance:      "always",
		Execution:       "render",
		Action:          "managed",
		CData:           cdata,
		Theme:           "auto",
		Size:            "normal",
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
	switch name {
	case "before-interactive":
		wt.CallbackState.BeforeInteractive = true
	case "after-interactive":
		wt.CallbackState.AfterInteractive = true
	case "success":
		wt.CallbackState.Success = true
	case "expired":
		wt.CallbackState.Expired = true
	case "timeout":
		wt.CallbackState.Timeout = true
	case "error":
		wt.CallbackState.Error = true
	}

	if name != "" {
		wt.CallbackOrder = append(wt.CallbackOrder, name)
		wt.CallbackCount++
	}
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
