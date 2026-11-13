package stealth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/skunkworq/stealth/brws/engine"
)

// chainStubEngine is a chain tier that answers with a fixed response or error.
type chainStubEngine struct {
	name     string
	response *engine.Response
	err      error
	closed   bool
}

func (s *chainStubEngine) Name() string                      { return s.name }
func (s *chainStubEngine) Capabilities() engine.Capabilities { return engine.Capabilities{} }
func (s *chainStubEngine) Close() error                      { s.closed = true; return nil }
func (s *chainStubEngine) Do(context.Context, *engine.Request) (*engine.Response, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.response, nil
}

// stubTier builds a chain tier backed by a stub engine.
func stubTier(name string, resp *engine.Response, err error) ChainTier {
	stub := &chainStubEngine{name: name, response: resp, err: err}
	tier := ChainTier{
		Name: name,
		Fetch: func(ctx context.Context, url string) (*engine.Response, error) {
			return stub.Do(ctx, &engine.Request{URL: url})
		},
		Close: stub.Close,
	}
	return tier
}

func okResponse(body string) *engine.Response {
	return &engine.Response{Status: 200, Body: []byte(body), FinalURL: "https://example.com/"}
}

func TestChainStopsAtTheFirstUsableTier(t *testing.T) {
	t.Parallel()

	chain, err := NewChain(ChainConfig{Tiers: []ChainTier{
		stubTier("fast", okResponse("<html>fast</html>"), nil),
		stubTier("slow", okResponse("<html>slow</html>"), nil),
	}})
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	resp, err := chain.Do(context.Background(), &engine.Request{URL: "https://example.com"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if string(resp.Body) != "<html>fast</html>" {
		t.Errorf("body = %q, want the fast tier's", resp.Body)
	}
	if chain.Trace().ServedBy != "fast" {
		t.Errorf("served by %q, want fast", chain.Trace().ServedBy)
	}
	if len(chain.Trace().Attempts) != 1 {
		t.Errorf("attempts = %d, want 1", len(chain.Trace().Attempts))
	}
}

func TestChainEscalatesOnABanStatus(t *testing.T) {
	t.Parallel()

	chain, err := NewChain(ChainConfig{Tiers: []ChainTier{
		stubTier("stealth", &engine.Response{Status: 403, Body: []byte("forbidden")}, nil),
		stubTier("flare", okResponse("<html>flare</html>"), nil),
	}})
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	resp, err := chain.Do(context.Background(), &engine.Request{URL: "https://example.com"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if string(resp.Body) != "<html>flare</html>" {
		t.Errorf("body = %q, want the flare tier's", resp.Body)
	}
	trace := chain.Trace()
	if trace.ServedBy != "flare" {
		t.Errorf("served by %q, want flare", trace.ServedBy)
	}
	if len(trace.Attempts) != 2 {
		t.Fatalf("attempts = %d, want 2", len(trace.Attempts))
	}
	if !trace.Attempts[0].Escalated {
		t.Error("the 403 attempt should be recorded as escalated")
	}
	if trace.Attempts[0].Reason != "status_403" {
		t.Errorf("reason = %q, want status_403", trace.Attempts[0].Reason)
	}
}

func TestChainEscalatesOnAChallengeBody(t *testing.T) {
	t.Parallel()

	// A 200 that carries a challenge signature is a wall, not content.
	chain, err := NewChain(ChainConfig{Tiers: []ChainTier{
		stubTier("stealth", &engine.Response{
			Status: 200,
			Body:   []byte("<html><head><title>Just a moment...</title></head></html>"),
		}, nil),
		stubTier("flare", okResponse("<html>real</html>"), nil),
	}})
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	resp, err := chain.Do(context.Background(), &engine.Request{URL: "https://example.com"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if string(resp.Body) != "<html>real</html>" {
		t.Errorf("body = %q, want the flare tier's", resp.Body)
	}
	if chain.Trace().Attempts[0].Reason != "challenge_body" {
		t.Errorf("reason = %q, want challenge_body", chain.Trace().Attempts[0].Reason)
	}
}

func TestChainEscalatesOnATransportError(t *testing.T) {
	t.Parallel()

	chain, err := NewChain(ChainConfig{Tiers: []ChainTier{
		stubTier("stealth", nil, errors.New("dial tcp: connection refused")),
		stubTier("flare", okResponse("<html>flare</html>"), nil),
	}})
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	resp, err := chain.Do(context.Background(), &engine.Request{URL: "https://example.com"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if string(resp.Body) != "<html>flare</html>" {
		t.Errorf("body = %q, want the flare tier's", resp.Body)
	}
	if chain.Trace().Attempts[0].Reason != "transport_error" {
		t.Errorf("reason = %q, want transport_error", chain.Trace().Attempts[0].Reason)
	}
}

func TestChainHonoursTheEscalationBudget(t *testing.T) {
	t.Parallel()

	chain, err := NewChain(ChainConfig{
		MaxEscalations: 1,
		Tiers: []ChainTier{
			stubTier("a", &engine.Response{Status: 403}, nil),
			stubTier("b", &engine.Response{Status: 403}, nil),
			stubTier("c", okResponse("<html>c</html>"), nil),
		},
	})
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	if _, err := chain.Do(context.Background(), &engine.Request{URL: "https://example.com"}); err == nil {
		t.Fatal("expected the chain to give up")
	}
	if got := len(chain.Trace().Attempts); got != 2 {
		t.Errorf("attempts = %d, want 2 (one escalation)", got)
	}
}

func TestChainReportsExhaustion(t *testing.T) {
	t.Parallel()

	chain, err := NewChain(ChainConfig{Tiers: []ChainTier{
		stubTier("a", &engine.Response{Status: 403}, nil),
		stubTier("b", &engine.Response{Status: 429}, nil),
	}})
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	_, err = chain.Do(context.Background(), &engine.Request{URL: "https://example.com"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "chain exhausted") {
		t.Errorf("error = %q, want it to say the chain was exhausted", err)
	}
}

func TestChainSkipsNilTiers(t *testing.T) {
	t.Parallel()

	chain, err := NewChain(ChainConfig{Tiers: []ChainTier{
		{Name: "missing"},
		stubTier("present", okResponse("<html>ok</html>"), nil),
	}})
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	if got := chain.Tiers(); len(got) != 1 || got[0] != "present" {
		t.Errorf("tiers = %v, want only the usable tier", got)
	}
}

func TestChainNeedsAtLeastOneTier(t *testing.T) {
	t.Parallel()

	if _, err := NewChain(ChainConfig{}); err == nil {
		t.Fatal("expected an error without tiers")
	}
}

func TestChainClosesEveryTier(t *testing.T) {
	t.Parallel()

	stub := &chainStubEngine{name: "a", response: okResponse("ok")}
	tier := ChainTier{
		Name: "a",
		Fetch: func(ctx context.Context, url string) (*engine.Response, error) {
			return stub.Do(ctx, &engine.Request{URL: url})
		},
		Close: stub.Close,
	}
	chain, err := NewChain(ChainConfig{Tiers: []ChainTier{tier}})
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	if err := chain.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !stub.closed {
		t.Error("the tier engine was not closed")
	}
}

func TestDefaultChallengeClassifier(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{name: "cloudflare interstitial", status: 503, body: "<title>Just a moment...</title>", want: true},
		{name: "akamai edge deny", status: 200, body: "<title>Access Denied</title>", want: true},
		{name: "imperva", status: 200, body: "<h1>Pardon Our Interruption</h1>", want: true},
		{name: "vercel checkpoint", status: 200, body: "<div>Vercel Security Checkpoint</div>", want: true},
		{name: "ordinary page", status: 200, body: "<html><body>hello</body></html>", want: false},
		{name: "empty body", status: 200, body: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := DefaultChallengeClassifier(tt.status, []byte(tt.body)); got != tt.want {
				t.Errorf("DefaultChallengeClassifier = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestChainAppliesThePerTierTimeout(t *testing.T) {
	t.Parallel()

	slow := &slowEngine{delay: 200 * time.Millisecond}
	chain, err := NewChain(ChainConfig{
		PerTierTimeout: 20 * time.Millisecond,
		Tiers: []ChainTier{
			{
				Name: "slow",
				Fetch: func(ctx context.Context, url string) (*engine.Response, error) {
					return slow.Do(ctx, &engine.Request{URL: url})
				},
			},
			stubTier("fast", okResponse("<html>fast</html>"), nil),
		},
	})
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	resp, err := chain.Do(context.Background(), &engine.Request{URL: "https://example.com"})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if string(resp.Body) != "<html>fast</html>" {
		t.Errorf("body = %q, want the fast tier's", resp.Body)
	}
}

// slowEngine blocks until its delay elapses or the context is cancelled.
type slowEngine struct {
	delay time.Duration
}

func (s *slowEngine) Name() string                      { return "slow" }
func (s *slowEngine) Capabilities() engine.Capabilities { return engine.Capabilities{} }
func (s *slowEngine) Close() error                      { return nil }
func (s *slowEngine) Do(ctx context.Context, _ *engine.Request) (*engine.Response, error) {
	select {
	case <-time.After(s.delay):
		return okResponse("<html>slow</html>"), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
