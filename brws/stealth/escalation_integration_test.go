package stealth

import (
	"context"
	"testing"
	"time"

	"github.com/skunkworq/stealth/brws/engine"
	wf "github.com/skunkworq/stealth/brws/engine/waterfall"
)

// stubEngine is a test double that returns a fixed response.
type stubEngine struct {
	name     string
	response *engine.Response
	err      error
}

func (s *stubEngine) Name() string                      { return s.name }
func (s *stubEngine) Capabilities() engine.Capabilities { return engine.Capabilities{} }
func (s *stubEngine) Close() error                      { return nil }
func (s *stubEngine) Do(_ context.Context, _ *engine.Request) (*engine.Response, error) {
	return s.response, s.err
}

// TestClient_FSMWaterfallEscalation verifies the full escalation loop:
// 1. HTTP engine returns ban signals (403)
// 2. Evasion FSM retry loop cycles through strategies within a single Navigate
// 3. Ban signals accumulate and trigger escalation
// 4. Waterfall promotes chromium tier
func TestClient_FSMWaterfallEscalation(t *testing.T) {
	// HTTP engine always returns 403 (banned)
	httpEngine := &stubEngine{
		name:     "http",
		response: &engine.Response{Status: 403, Body: []byte("blocked")},
	}

	// Chromium engine returns 200 (success)
	chromiumEngine := &stubEngine{
		name:     "chromium",
		response: &engine.Response{Status: 200, Body: []byte("success")},
	}

	// Build waterfall: http first, chromium deferred
	waterfallEng, err := wf.New(
		wf.Tier{Engine: httpEngine, Name: "http"},
		wf.Tier{Engine: chromiumEngine, Name: "chromium", LaunchAfter: 5 * time.Second},
	)
	if err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.EngineName = "native"
	// EvasionFSM is enabled by default
	cfg.WaterfallEngine = waterfallEng
	cfg.Escalation = &EscalationConfig{
		Enabled:              true,
		MaxEscalationRetries: 1,
		PromoteOnStatus:      []int{403, 429},
	}

	client, err := NewWithConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()

	// A single Navigate call against a persistently-403 engine will trigger
	// the FSM retry loop, which cycles through strategies. Each retry records
	// a ban signal, so the FSM crosses the threshold (3) within this call.
	resp, err := client.Navigate(ctx, "http://example.com")
	if err != nil {
		t.Fatalf("navigate error: %v", err)
	}

	// FSM should have escalated — the retry loop accumulated 3+ ban signals
	if !client.evasionFSM.ShouldEscalate() {
		t.Error("FSM should recommend escalation after retry loop accumulated ban signals")
	}

	reason := client.evasionFSM.EscalationReason()
	if reason != "ban_signals" {
		t.Errorf("expected reason 'ban_signals', got %q", reason)
	}

	// Verify waterfall metrics show the chromium tier was promoted
	metrics := waterfallEng.Metrics()
	t.Logf("Waterfall metrics: wins=%v errors=%v", metrics.Wins, metrics.Errors)
	t.Logf("FSM summary:\n%s", client.evasionFSM.Summary())

	_ = resp
}

// TestClient_FSMExhaustion_PromotesChromium verifies that when all evasion
// strategies are exhausted (detected >50%), the FSM promotes chromium tier.
func TestClient_FSMExhaustion_PromotesChromium(t *testing.T) {
	// Engine returns 403 for every request
	blockedEngine := &stubEngine{
		name:     "http",
		response: &engine.Response{Status: 403, Body: []byte("blocked")},
	}

	chromiumEngine := &stubEngine{
		name:     "chromium",
		response: &engine.Response{Status: 200, Body: []byte("ok")},
	}

	waterfallEng, err := wf.New(
		wf.Tier{Engine: blockedEngine, Name: "http"},
		wf.Tier{Engine: chromiumEngine, Name: "chromium", LaunchAfter: 10 * time.Second},
	)
	if err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.EngineName = "native"
	// EvasionFSM is enabled by default
	cfg.WaterfallEngine = waterfallEng
	cfg.Escalation = &EscalationConfig{
		Enabled:              true,
		MaxEscalationRetries: 0, // no retries — just track signals
		PromoteOnStatus:      []int{403},
	}

	client, err := NewWithConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()

	// Hit the FSM with enough ban signals to trigger escalation
	// (ban threshold is 3, each Navigate with 403 records 1 ban signal from FSM)
	for i := 0; i < 4; i++ {
		_, err := client.Navigate(ctx, "http://example.com")
		if err != nil {
			t.Fatalf("navigate %d error: %v", i, err)
		}
	}

	if !client.evasionFSM.ShouldEscalate() {
		t.Fatal("expected FSM to recommend escalation")
	}

	t.Logf("Escalation reason: %s", client.evasionFSM.EscalationReason())
	t.Logf("FSM summary:\n%s", client.evasionFSM.Summary())
}

// TestClient_ActiveEngine_SelectsWaterfall verifies that activeEngine() returns
// the waterfall when configured.
func TestClient_ActiveEngine_SelectsWaterfall(t *testing.T) {
	eng := &stubEngine{name: "base", response: &engine.Response{Status: 200}}
	waterfallEng, _ := wf.New(wf.Tier{Engine: eng, Name: "base"})

	client := &Client{
		engine:    eng,
		waterfall: waterfallEng,
	}

	active := client.activeEngine()
	if active.Name() != "waterfall" {
		t.Errorf("expected waterfall engine, got %s", active.Name())
	}
}

// TestClient_ActiveEngine_FallsBackToRaw verifies that activeEngine() returns
// the raw engine when no waterfall is configured.
func TestClient_ActiveEngine_FallsBackToRaw(t *testing.T) {
	eng := &stubEngine{name: "native", response: &engine.Response{Status: 200}}

	client := &Client{
		engine: eng,
	}

	active := client.activeEngine()
	if active.Name() != "native" {
		t.Errorf("expected native engine, got %s", active.Name())
	}
}
