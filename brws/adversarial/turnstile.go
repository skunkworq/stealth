package adversarial

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/net/html"
)

const (
	// Public Cloudflare Turnstile testing keys from the official documentation.
	TurnstileTestingSiteKeyVisiblePass   = "1x00000000000000000000AA"
	TurnstileTestingSiteKeyVisibleFail   = "2x00000000000000000000AB"
	TurnstileTestingSiteKeyInvisiblePass = "1x00000000000000000000BB"
	TurnstileTestingSiteKeyInvisibleFail = "2x00000000000000000000BB"
	TurnstileTestingSecretKeyPass        = "1x0000000000000000000000000000000AA"
	TurnstileTestingSecretKeyFail        = "2x0000000000000000000000000000000AA"
	TurnstileTestingSecretKeyDuplicate   = "3x0000000000000000000000000000000AA"
	TurnstileTestingDummyToken           = "XXXX.DUMMY.TOKEN.XXXX"
)

const (
	TurnstileModeManaged        = "managed"
	TurnstileModeInvisible      = "invisible"
	TurnstileModeNonInteractive = "non-interactive"
)

const (
	TurnstileRetryAuto  = "auto"
	TurnstileRetryNever = "never"
)

const (
	TurnstileRefreshAuto   = "auto"
	TurnstileRefreshManual = "manual"
	TurnstileRefreshNever  = "never"
)

// TurnstileWidgetConfig models the public widget configuration surface used by
// the local lab harness and by owned-environment testing flows.
type TurnstileWidgetConfig struct {
	SiteKey           string `json:"site_key"`
	Mode              string `json:"mode"`
	Action            string `json:"action,omitempty"`
	CData             string `json:"cdata,omitempty"`
	Theme             string `json:"theme,omitempty"`
	Size              string `json:"size,omitempty"`
	Appearance        string `json:"appearance,omitempty"`
	Execution         string `json:"execution,omitempty"`
	Retry             string `json:"retry,omitempty"`
	RetryIntervalMS   int    `json:"retry_interval_ms,omitempty"`
	RefreshExpired    string `json:"refresh_expired,omitempty"`
	RefreshTimeout    string `json:"refresh_timeout,omitempty"`
	ResponseField     bool   `json:"response_field"`
	ResponseFieldName string `json:"response_field_name,omitempty"`
	TokenTTLSeconds   int    `json:"token_ttl_seconds"`
}

// WidgetCallbackState tracks the local widget lifecycle for contract-faithful
// testing and browser assertions.
type WidgetCallbackState struct {
	Ready           bool      `json:"ready"`
	Rendered        bool      `json:"rendered"`
	Executed        bool      `json:"executed"`
	Succeeded       bool      `json:"succeeded"`
	Expired         bool      `json:"expired"`
	TimedOut        bool      `json:"timed_out"`
	ErrorCode       string    `json:"error_code,omitempty"`
	LastCallback    string    `json:"last_callback,omitempty"`
	RenderCount     int       `json:"render_count"`
	ResetCount      int       `json:"reset_count"`
	LastRenderedAt  time.Time `json:"last_rendered_at,omitempty"`
	LastExecutedAt  time.Time `json:"last_executed_at,omitempty"`
	LastSucceededAt time.Time `json:"last_succeeded_at,omitempty"`
	LastExpiredAt   time.Time `json:"last_expired_at,omitempty"`
}

// WidgetTelemetry captures the interaction summary that the sword sends back to
// the harness when it exercises the local or owned test-mode flow.
type WidgetTelemetry struct {
	WidgetFound    bool      `json:"widget_found"`
	Mode           string    `json:"mode,omitempty"`
	Appearance     string    `json:"appearance,omitempty"`
	Execution      string    `json:"execution,omitempty"`
	EventCount     int       `json:"event_count"`
	MouseMoves     int       `json:"mouse_moves"`
	Clicks         int       `json:"clicks"`
	KeyPresses     int       `json:"key_presses"`
	Scrolls        int       `json:"scrolls"`
	ViewportWidth  int       `json:"viewport_width,omitempty"`
	ViewportHeight int       `json:"viewport_height,omitempty"`
	UserAgent      string    `json:"user_agent,omitempty"`
	StartedAt      time.Time `json:"started_at,omitempty"`
	CompletedAt    time.Time `json:"completed_at,omitempty"`
	LastEventAt    time.Time `json:"last_event_at,omitempty"`
}

// LabTurnstileToken is the server-issued lab token metadata retained for
// verification and debugging.
type LabTurnstileToken struct {
	Token     string    `json:"token"`
	SessionID string    `json:"session_id"`
	SiteKey   string    `json:"site_key"`
	Hostname  string    `json:"hostname"`
	Action    string    `json:"action,omitempty"`
	CData     string    `json:"cdata,omitempty"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	SingleUse bool      `json:"single_use"`
	Used      bool      `json:"used"`
	Source    string    `json:"source"`
}

// VerificationResult mirrors the important parts of Cloudflare's Siteverify
// response while keeping the lab metadata attached when available.
type VerificationResult struct {
	Success     bool               `json:"success"`
	ChallengeTS string             `json:"challenge_ts,omitempty"`
	Hostname    string             `json:"hostname,omitempty"`
	ErrorCodes  []string           `json:"error-codes,omitempty"`
	Action      string             `json:"action,omitempty"`
	CData       string             `json:"cdata,omitempty"`
	Token       *LabTurnstileToken `json:"token,omitempty"`
}

// DefaultTurnstileWidgetConfig returns the stricter lab defaults. These map to
// public Turnstile options while keeping the harness visibly interactive.
func DefaultTurnstileWidgetConfig(siteKey string) *TurnstileWidgetConfig {
	if siteKey == "" {
		siteKey = TurnstileTestingSiteKeyVisiblePass
	}
	return &TurnstileWidgetConfig{
		SiteKey:           siteKey,
		Mode:              TurnstileModeManaged,
		Action:            "lab-turnstile",
		CData:             "lab-session",
		Theme:             "light",
		Size:              "normal",
		Appearance:        "always",
		Execution:         "render",
		Retry:             TurnstileRetryAuto,
		RetryIntervalMS:   800,
		RefreshExpired:    TurnstileRefreshAuto,
		RefreshTimeout:    TurnstileRefreshManual,
		ResponseField:     true,
		ResponseFieldName: "cf-turnstile-response",
		TokenTTLSeconds:   300,
	}
}

// Normalize applies defaults and derives a consistent mode for downstream use.
func (cfg *TurnstileWidgetConfig) Normalize() *TurnstileWidgetConfig {
	if cfg == nil {
		return DefaultTurnstileWidgetConfig("")
	}

	normalized := *cfg
	if normalized.SiteKey == "" {
		normalized.SiteKey = TurnstileTestingSiteKeyVisiblePass
	}
	if normalized.Mode == "" {
		switch {
		case normalized.Size == "invisible":
			normalized.Mode = TurnstileModeInvisible
		case normalized.Appearance == "interaction-only":
			normalized.Mode = TurnstileModeNonInteractive
		default:
			normalized.Mode = TurnstileModeManaged
		}
	}
	if normalized.Action == "" {
		normalized.Action = "lab-turnstile"
	}
	if normalized.CData == "" {
		normalized.CData = "lab-session"
	}
	if normalized.Theme == "" {
		normalized.Theme = "light"
	}
	if normalized.Size == "" {
		if normalized.Mode == TurnstileModeInvisible {
			normalized.Size = "invisible"
		} else {
			normalized.Size = "normal"
		}
	}
	if normalized.Appearance == "" {
		normalized.Appearance = "always"
	}
	if normalized.Execution == "" {
		if normalized.Mode == TurnstileModeInvisible {
			normalized.Execution = "execute"
		} else {
			normalized.Execution = "render"
		}
	}
	if normalized.Retry == "" {
		normalized.Retry = TurnstileRetryAuto
	}
	if normalized.RetryIntervalMS <= 0 {
		normalized.RetryIntervalMS = 800
	}
	if normalized.RefreshExpired == "" {
		normalized.RefreshExpired = TurnstileRefreshAuto
	}
	if normalized.RefreshTimeout == "" {
		normalized.RefreshTimeout = TurnstileRefreshManual
	}
	if !normalized.ResponseField {
		normalized.ResponseField = true
	}
	if normalized.ResponseFieldName == "" {
		normalized.ResponseFieldName = "cf-turnstile-response"
	}
	if normalized.TokenTTLSeconds <= 0 {
		normalized.TokenTTLSeconds = 300
	}

	return &normalized
}

// ShouldAutoRetry reports whether retry behavior should happen automatically.
func (cfg *TurnstileWidgetConfig) ShouldAutoRetry() bool {
	return cfg.Normalize().Retry == TurnstileRetryAuto
}

// ShouldAutoRefreshExpired reports whether an expired token should trigger a
// widget reset automatically.
func (cfg *TurnstileWidgetConfig) ShouldAutoRefreshExpired() bool {
	return cfg.Normalize().RefreshExpired == TurnstileRefreshAuto
}

// ParseTurnstileWidgetConfigFromHTML extracts the public widget configuration
// from the first `.cf-turnstile` element on the page.
func ParseTurnstileWidgetConfigFromHTML(body string) *TurnstileWidgetConfig {
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return nil
	}

	var cfg *TurnstileWidgetConfig
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if cfg != nil || n == nil {
			return
		}
		if n.Type == html.ElementNode && n.Data == "div" && nodeHasClass(n, "cf-turnstile") {
			cfg = &TurnstileWidgetConfig{
				SiteKey:           nodeAttr(n, "data-sitekey"),
				Action:            nodeAttr(n, "data-action"),
				CData:             nodeAttr(n, "data-cdata"),
				Theme:             nodeAttr(n, "data-theme"),
				Size:              nodeAttr(n, "data-size"),
				Appearance:        nodeAttr(n, "data-appearance"),
				Execution:         nodeAttr(n, "data-execution"),
				Retry:             nodeAttr(n, "data-retry"),
				RefreshExpired:    nodeAttr(n, "data-refresh-expired"),
				RefreshTimeout:    nodeAttr(n, "data-refresh-timeout"),
				ResponseFieldName: nodeAttr(n, "data-response-field-name"),
			}

			if responseField := nodeAttr(n, "data-response-field"); responseField == "" || responseField == "true" {
				cfg.ResponseField = true
			}
			if retryInterval := nodeAttr(n, "data-retry-interval"); retryInterval != "" {
				fmt.Sscanf(retryInterval, "%d", &cfg.RetryIntervalMS)
			}
			if ttl := nodeAttr(n, "data-token-ttl"); ttl != "" {
				fmt.Sscanf(ttl, "%d", &cfg.TokenTTLSeconds)
			}
			if mode := nodeAttr(n, "data-mode"); mode != "" {
				cfg.Mode = mode
			}
			cfg = cfg.Normalize()
			return
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}

	walk(doc)
	return cfg
}

// BuildTurnstileTelemetry summarizes input events for lab-side verification and
// observability.
func BuildTurnstileTelemetry(events []CaptchaEvent, cfg *TurnstileWidgetConfig, userAgent string, width, height int) *WidgetTelemetry {
	normalized := cfg.Normalize()
	telemetry := &WidgetTelemetry{
		WidgetFound:    normalized != nil,
		UserAgent:      userAgent,
		ViewportWidth:  width,
		ViewportHeight: height,
	}
	if normalized != nil {
		telemetry.Mode = normalized.Mode
		telemetry.Appearance = normalized.Appearance
		telemetry.Execution = normalized.Execution
	}

	if len(events) == 0 {
		return telemetry
	}

	telemetry.EventCount = len(events)
	start := time.UnixMilli(events[0].Timestamp)
	last := start
	for _, event := range events {
		switch event.Type {
		case "mousemove":
			telemetry.MouseMoves++
		case "click", "mousedown", "mouseup":
			telemetry.Clicks++
		case "keydown", "keyup", "keypress":
			telemetry.KeyPresses++
		case "scroll", "wheel":
			telemetry.Scrolls++
		}
		if ts := time.UnixMilli(event.Timestamp); ts.After(last) {
			last = ts
		}
	}

	telemetry.StartedAt = start
	telemetry.CompletedAt = last
	telemetry.LastEventAt = last
	return telemetry
}

// MarshalJSON keeps zero-value slices stable for API responses.
func (vr VerificationResult) MarshalJSON() ([]byte, error) {
	type alias VerificationResult
	out := alias(vr)
	if out.ErrorCodes == nil {
		out.ErrorCodes = []string{}
	}
	return json.Marshal(out)
}

func nodeHasClass(n *html.Node, className string) bool {
	classes := strings.Fields(nodeAttr(n, "class"))
	for _, class := range classes {
		if class == className {
			return true
		}
	}
	return false
}

func nodeAttr(n *html.Node, key string) string {
	if n == nil {
		return ""
	}
	for _, attr := range n.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}
