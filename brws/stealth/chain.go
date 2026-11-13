package stealth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/skunkworq/stealth/brws/engine"
)

// ChainConfig configures an escalation chain — the ordered tiers a request
// walks when a site walls it.
//
// The chain is SEQUENTIAL, unlike the waterfall engine (which races tiers
// for latency). Escalation is a decision, not a race: a 403 from the first
// tier is evidence that the second tier should try, and the tiers differ in
// kind, not merely in speed. A racing chain would spend a solver's budget on
// every request.
type ChainConfig struct {
	// Tiers are tried in order. A tier with a nil Engine is skipped.
	Tiers []ChainTier

	// MaxEscalations bounds how many times a request may climb the chain.
	// Zero means "no separate bound" — the chain length is the bound.
	MaxEscalations int

	// PerTierTimeout bounds one tier's attempt. Zero means no extra bound
	// beyond the request context.
	PerTierTimeout time.Duration

	// OnChallenge classifies a response body as a bot wall. A nil classifier
	// uses the default signature set.
	OnChallenge func(status int, body []byte) bool

	// EscalateOnStatus lists the HTTP statuses that promote to the next
	// tier. Zero value uses the default set.
	EscalateOnStatus []int
}

// Fetcher performs one fetch and returns the raw response.
//
// It is a function type on purpose. An engine.Engine cannot satisfy it
// directly (its Do takes a Request), and neither can the stealth Client
// (its Navigate returns a richer Response). A function lets a tier be
// either: EngineFetcher adapts an engine, ClientFetcher adapts the client.
type Fetcher func(ctx context.Context, url string) (*engine.Response, error)

// EngineFetcher adapts an engine into a Fetcher.
func EngineFetcher(eng engine.Engine) Fetcher {
	if eng == nil {
		return nil
	}
	return func(ctx context.Context, url string) (*engine.Response, error) {
		return eng.Do(ctx, &engine.Request{URL: url})
	}
}

// ClientFetcher adapts the stealth client into a Fetcher. The client is the
// richest tier available — TLS spoofing, behaviour simulation, the challenge
// FSM — so it usually leads the chain.
func ClientFetcher(client *Client) Fetcher {
	if client == nil {
		return nil
	}
	return func(ctx context.Context, url string) (*engine.Response, error) {
		resp, err := client.Navigate(ctx, url)
		if err != nil {
			return nil, err
		}
		return &engine.Response{
			Status:   resp.Status,
			Headers:  resp.Headers,
			Body:     resp.Body,
			FinalURL: resp.FinalURL,
			Trace:    resp.Trace,
		}, nil
	}
}

// EngineTier builds a chain tier from an engine, wiring the engine's Close
// so the chain can release it.
func EngineTier(name string, eng engine.Engine) ChainTier {
	tier := ChainTier{Name: name, Fetch: EngineFetcher(eng)}
	if eng != nil {
		tier.Close = eng.Close
	}
	return tier
}

// ChainTier is one rung of the escalation chain.
type ChainTier struct {
	// Name identifies the tier in traces and logs.
	Name string
	// Fetch performs the tier's request. A nil Fetch skips the tier.
	Fetch Fetcher
	// Close releases the tier's resources, when it owns any. A solver
	// engine holds a session; leaving it open leaks a browser.
	Close func() error
}

// Chain walks a request through ordered fetchers, promoting on a ban signal
// or a challenge body.
//
// The first tier that answers with a usable response wins. A tier that
// answers with a wall (401/403/429/503, or a body that matches a known
// challenge signature) is recorded and the next tier is tried. A tier that
// fails at the transport level is also promoted: a blackholed dial on one
// client says nothing about the next one.
type Chain struct {
	tiers          []ChainTier
	maxEscalations int
	perTierTimeout time.Duration
	onChallenge    func(status int, body []byte) bool
	escalateOn     []int
	closed         bool
	lastTrace      *ChainTrace
}

// ChainTrace records how a request walked the chain. It answers the
// question the crawl report asks — which tier actually served the page.
type ChainTrace struct {
	// Tiers is the ordered tier list.
	Tiers []string `json:"tiers,omitempty"`
	// Attempts is one entry per tier tried, in order.
	Attempts []ChainAttempt `json:"attempts,omitempty"`
	// ServedBy is the name of the tier that answered, empty when none did.
	ServedBy string `json:"served_by,omitempty"`
}

// ChainAttempt is one tier's outcome.
type ChainAttempt struct {
	Tier   string `json:"tier"`
	Status int    `json:"status,omitempty"`
	Bytes  int    `json:"bytes,omitempty"`
	// Escalated is true when this attempt's response promoted the request.
	Escalated bool `json:"escalated,omitempty"`
	// Reason explains the promotion ("status_403", "challenge_body",
	// "transport_error").
	Reason string `json:"reason,omitempty"`
	// Error is the transport error, when there was one.
	Error string `json:"error,omitempty"`
	// Elapsed is how long the tier took.
	Elapsed time.Duration `json:"elapsed,omitempty"`
}

// DefaultChainEscalateStatuses are the HTTP statuses that promote a request
// to the next tier. 403 and 429 are the classic bot walls; 503 is the
// "challenge in progress" answer some edges give.
var DefaultChainEscalateStatuses = []int{401, 403, 429, 503}

// NewChain creates an escalation chain from cfg.
func NewChain(cfg ChainConfig) (*Chain, error) {
	tiers := make([]ChainTier, 0, len(cfg.Tiers))
	for _, t := range cfg.Tiers {
		if t.Fetch == nil {
			continue
		}
		tiers = append(tiers, t)
	}
	if len(tiers) == 0 {
		return nil, errors.New("stealth: chain needs at least one tier")
	}
	statuses := cfg.EscalateOnStatus
	if len(statuses) == 0 {
		statuses = DefaultChainEscalateStatuses
	}
	return &Chain{
		tiers:          tiers,
		maxEscalations: cfg.MaxEscalations,
		perTierTimeout: cfg.PerTierTimeout,
		onChallenge:    cfg.OnChallenge,
		escalateOn:     statuses,
	}, nil
}

// Tiers returns the ordered tier names.
func (c *Chain) Tiers() []string {
	out := make([]string, 0, len(c.tiers))
	for _, t := range c.tiers {
		out = append(out, t.Name)
	}
	return out
}

// Close closes every tier's engine.
func (c *Chain) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	var firstErr error
	for _, t := range c.tiers {
		if t.Close == nil {
			continue
		}
		if err := t.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Trace returns the trace of the last request the chain served.
func (c *Chain) Trace() *ChainTrace { return c.lastTrace }

// Do walks the request through the chain.
func (c *Chain) Do(ctx context.Context, req *engine.Request) (*engine.Response, error) {
	trace := &ChainTrace{}
	for _, t := range c.tiers {
		trace.Tiers = append(trace.Tiers, t.Name)
	}
	c.lastTrace = trace

	maxEscalations := c.maxEscalations
	if maxEscalations <= 0 {
		maxEscalations = len(c.tiers) - 1
	}
	escalations := 0

	var lastErr error
	for i, tier := range c.tiers {
		if i > 0 && escalations > maxEscalations {
			break
		}
		attemptCtx := ctx
		var cancel context.CancelFunc
		if c.perTierTimeout > 0 {
			attemptCtx, cancel = context.WithTimeout(ctx, c.perTierTimeout)
		}

		started := time.Now()
		resp, err := tier.Fetch(attemptCtx, req.URL)
		if cancel != nil {
			cancel()
		}
		attempt := ChainAttempt{Tier: tier.Name, Elapsed: time.Since(started)}
		if err != nil {
			attempt.Error = err.Error()
			attempt.Reason = "transport_error"
			trace.Attempts = append(trace.Attempts, attempt)
			lastErr = err
			escalations++
			continue
		}
		attempt.Status = resp.Status
		attempt.Bytes = len(resp.Body)

		reason := c.promotionReason(resp)
		if reason != "" {
			attempt.Escalated = true
			attempt.Reason = reason
			trace.Attempts = append(trace.Attempts, attempt)
			lastErr = fmt.Errorf("tier %s: %s", tier.Name, reason)
			escalations++
			continue
		}

		trace.Attempts = append(trace.Attempts, attempt)
		trace.ServedBy = tier.Name
		return resp, nil
	}

	if lastErr == nil {
		lastErr = errors.New("stealth: chain exhausted")
	}
	return nil, fmt.Errorf("stealth: chain exhausted after %d tier(s): %w", len(trace.Attempts), lastErr)
}

// promotionReason reports why a response should promote to the next tier, or
// an empty string when the response is usable.
func (c *Chain) promotionReason(resp *engine.Response) string {
	if resp == nil {
		return "empty_response"
	}
	for _, status := range c.escalateOn {
		if resp.Status == status {
			return fmt.Sprintf("status_%d", status)
		}
	}
	classify := c.onChallenge
	if classify == nil {
		classify = DefaultChallengeClassifier
	}
	if classify(resp.Status, resp.Body) {
		return "challenge_body"
	}
	return ""
}

// DefaultChallengeClassifier reports whether a response body is a bot wall.
//
// The signatures are the ones observed in the field: Cloudflare's
// interstitial, its JS challenge, Akamai's "Access Denied" edge shell, the
// Vercel security checkpoint, and Imperva's "Pardon Our Interruption".
// A 200 that carries one of these is a wall, not content.
func DefaultChallengeClassifier(status int, body []byte) bool {
	if len(body) == 0 {
		return false
	}
	lower := strings.ToLower(string(body[:min(len(body), 8192)]))
	for _, marker := range []string{
		"just a moment",
		"cf-browser-verification",
		"cf_chl_opt",
		"checking your browser",
		"attention required",
		"access denied",
		"pardon our interruption",
		"enable javascript and cookies to continue",
		"the request could not be satisfied",
		"request unsuccessful. incapsula",
		"_incapsula_resource",
		"vercel security checkpoint",
		"sec-captcha",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
