package stealth

import (
	"context"
	"sync"
	"testing"

	"github.com/skunkworq/stealth/brws/browser/engine"
)

// fakeEngine returns canned responses in order; the last response repeats.
type fakeEngine struct {
	mu        sync.Mutex
	callCount int
	responses []*engine.Response
}

func (f *fakeEngine) Name() string                    { return "fake" }
func (f *fakeEngine) Capabilities() engine.Capabilities { return engine.Capabilities{} }
func (f *fakeEngine) Close() error                    { return nil }

func (f *fakeEngine) Do(ctx context.Context, req *engine.Request) (*engine.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.callCount
	f.callCount++
	if i < len(f.responses) {
		return f.responses[i], nil
	}
	return f.responses[len(f.responses)-1], nil
}

func (f *fakeEngine) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.callCount
}

func okResponse() *engine.Response {
	return &engine.Response{Status: 200, Body: []byte("OK"), Headers: map[string][]string{}}
}

// cfWAFResponse returns a Cloudflare 403 that triggers isWAFResponse.
func cfWAFResponse() *engine.Response {
	return &engine.Response{
		Status: 403,
		Body:   []byte("Checking your browser..."),
		Headers: map[string][]string{
			"Cf-Ray": {"abc123-DEF"},
			"Server": {"cloudflare"},
		},
	}
}

// TestNavigate_CleanResponse verifies the happy path: a 200 OK response is
// returned without retries and with ChallengeSolved=false.
func TestNavigate_CleanResponse(t *testing.T) {
	fake := &fakeEngine{responses: []*engine.Response{okResponse()}}
	c := newAdaptiveFromEngines(fake, nil)

	resp, err := c.Navigate(context.Background(), "https://example.com/page")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Status != 200 {
		t.Errorf("expected status 200, got %d", resp.Status)
	}
	if resp.ChallengeSolved {
		t.Error("expected ChallengeSolved=false for a clean 200 response")
	}
	if fake.Calls() != 1 {
		t.Errorf("expected engine called once, got %d", fake.Calls())
	}
}

// TestNavigate_WAFResponseRetried verifies that a Cloudflare 403 triggers
// the WAF retry loop: the engine is called a second time and the clean
// response from the retry is returned.
func TestNavigate_WAFResponseRetried(t *testing.T) {
	if testing.Short() {
		t.Skip("WAF retry backoff (~2s) skipped in -short mode")
	}

	fake := &fakeEngine{responses: []*engine.Response{
		cfWAFResponse(), // call 1: WAF → triggers retry
		okResponse(),    // call 2: clean → retry succeeds
	}}
	c := newAdaptiveFromEngines(fake, nil)

	resp, err := c.Navigate(context.Background(), "https://example.com/page")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Status != 200 {
		t.Errorf("expected status 200 after WAF retry, got %d", resp.Status)
	}
	if fake.Calls() < 2 {
		t.Errorf("expected at least 2 engine calls (initial + retry), got %d", fake.Calls())
	}
}

// TestNavigate_BanSignalRecordedByFSM verifies that a 403 ban signal causes
// the evasion FSM to initialize, record the ban, and rotate to the next strategy.
func TestNavigate_BanSignalRecordedByFSM(t *testing.T) {
	fake := &fakeEngine{responses: []*engine.Response{
		{Status: 403, Body: []byte("Forbidden"), Headers: map[string][]string{}},
		okResponse(),
	}}

	c := newAdaptiveFromEngines(fake, nil)
	// Enable the evasion FSM (disabled by default in the minimal constructor).
	c.evasionFSMEnabled = true
	// Wire up escalation config so isBanSignal can check status codes.
	c.escalation = DefaultEscalationConfig()

	resp, err := c.Navigate(context.Background(), "https://example.com/page")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	fsm := c.EvasionFSM()
	if fsm == nil {
		t.Fatal("expected evasion FSM to be initialized after navigate")
	}
	if fsm.LastBanStatus() != 403 {
		t.Errorf("expected last ban status 403, got %d", fsm.LastBanStatus())
	}
	// Engine must be called at least twice: initial 403 + FSM retry.
	if fake.Calls() < 2 {
		t.Errorf("expected >= 2 engine calls (ban + FSM retry), got %d", fake.Calls())
	}
}

// TestNavigate_CaptchaHeaderPassthrough verifies that a response carrying the
// X-Captcha-Required header is returned as-is when no challenge orchestrator
// is configured, and Navigate does not return an error.
func TestNavigate_CaptchaHeaderPassthrough(t *testing.T) {
	captchaResp := &engine.Response{
		Status: 200,
		Body:   []byte("Please solve the captcha"),
		Headers: map[string][]string{
			"X-Captcha-Required": {"1"},
		},
	}
	fake := &fakeEngine{responses: []*engine.Response{captchaResp}}
	c := newAdaptiveFromEngines(fake, nil)

	resp, err := c.Navigate(context.Background(), "https://example.com/page")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	// Without an orchestrator or FSM, the response is returned unmodified.
	if resp.Status != 200 {
		t.Errorf("expected status 200 passthrough, got %d", resp.Status)
	}
	if resp.ChallengeSolved {
		t.Error("expected ChallengeSolved=false when no orchestrator is configured")
	}
}
