package stealth

import (
	"context"

	"github.com/skunkworq/stealth/brws/browser/engine"
	pool "github.com/skunkworq/stealth/brws/network/proxy/connpool"
	wf "github.com/skunkworq/stealth/brws/browser/engine/meta/waterfall"
	"github.com/skunkworq/stealth/brws/stealth/profile/session"
)

// BanSignalStatus maps HTTP status codes to ban signal reasons.
var BanSignalStatus = map[int]string{
	401: "status_401_unauthorized",
	403: "status_403_forbidden",
	429: "status_429_rate_limited",
}

// EscalationConfig controls automatic anti-bot escalation behavior.
type EscalationConfig struct {
	Enabled              bool
	MaxEscalationRetries int   // max retries with escalated config (default 2)
	PromoteOnStatus      []int // HTTP status codes that trigger escalation (default [401, 403, 429])
	// DefaultTier is the waterfall tier to promote to for ban signals.
	// Defaults to "browser" if empty.
	DefaultTier          string
}

// DefaultEscalationConfig returns production-safe defaults.
func DefaultEscalationConfig() *EscalationConfig {
	return &EscalationConfig{
		Enabled:              false,
		MaxEscalationRetries: 2,
		PromoteOnStatus:      []int{401, 403, 429},
	}
}

// isBanSignal returns true for status codes that indicate bot detection.
func isBanSignal(cfg *EscalationConfig, status int) bool {
	for _, s := range cfg.PromoteOnStatus {
		if s == status {
			return true
		}
	}
	return false
}

// escalationTierFor maps an HTTP status code to a waterfall tier name.
func escalationTierFor(cfg *EscalationConfig, status int) string {
	if cfg != nil && cfg.DefaultTier != "" {
		return cfg.DefaultTier
	}
	switch status {
	case 429:
		return "stealth-tls"
	default:
		return "browser"
	}
}

// escalate is called after a ban-signal response.
// It records the ban, escalates proxy tier, promotes waterfall tier,
// and returns whether a retry should be attempted.
func (c *Client) escalate(ctx context.Context, resp *engine.Response, targetURL string, sess *session.Session) bool {
	reason, ok := BanSignalStatus[resp.Status]
	if !ok {
		reason = "unknown_ban_signal"
	}

	// Feed ban signal to evasion FSM if active
	if c.evasionFSM != nil {
		c.evasionFSM.RecordBanSignal(resp.Status)
	}

	// Record ban on session health
	if sess != nil {
		sess.Health().RecordBad(session.BanSignal{
			StatusCode: resp.Status,
			Reason:     reason,
		})
	}

	// Escalate proxy tier if tracker is configured
	if c.tierTracker != nil {
		c.tierTracker.RecordError(targetURL)
	}

	// Promote waterfall tier if waterfall engine is in use
	if c.waterfall != nil {
		tierName := escalationTierFor(c.escalation, resp.Status)
		c.waterfall.PromoteTier(tierName)
		c.logger.Info("escalated waterfall tier", "promoted", tierName, "status", resp.Status)
	}

	// Session is hard-blocked → don't retry with this session
	if sess != nil && sess.IsBlocked() {
		c.logger.Warn("session blocked after escalation", "session", sess.ID)
		return false
	}

	return true
}

// WithEscalation configures automatic anti-bot escalation.
func WithEscalation(cfg *EscalationConfig) Option {
	return func(c *Config) {
		c.Escalation = cfg
	}
}

// WithWaterfall sets a pre-built waterfall engine on the client config.
func WithWaterfall(w *wf.Waterfall) Option {
	return func(c *Config) {
		c.WaterfallEngine = w
	}
}

// WithTieredProxies configures per-domain proxy tier escalation.
func WithTieredProxies(tiers []pool.TieredProxy) Option {
	return func(c *Config) {
		c.TieredProxies = tiers
	}
}
