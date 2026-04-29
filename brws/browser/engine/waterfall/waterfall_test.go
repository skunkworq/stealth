package waterfall

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/skunkworq/stealth/brws/browser/engine"
)

// stubEngine is a test double that returns after a delay.
type stubEngine struct {
	name     string
	delay    time.Duration
	response *engine.Response
	err      error
}

func (s *stubEngine) Name() string                      { return s.name }
func (s *stubEngine) Capabilities() engine.Capabilities { return engine.Capabilities{} }
func (s *stubEngine) Close() error                      { return nil }
func (s *stubEngine) Do(ctx context.Context, req *engine.Request) (*engine.Response, error) {
	select {
	case <-time.After(s.delay):
		return s.response, s.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestWaterfall_SingleTier(t *testing.T) {
	w, err := New(Tier{
		Engine: &stubEngine{
			name:     "fast",
			delay:    10 * time.Millisecond,
			response: &engine.Response{Status: 200},
		},
		Name: "fast",
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := w.Do(context.Background(), &engine.Request{URL: "http://test"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Errorf("status = %d, want 200", resp.Status)
	}

	m := w.Metrics()
	if m.Wins["fast"] != 1 {
		t.Errorf("fast wins = %d, want 1", m.Wins["fast"])
	}
}

func TestWaterfall_FastWins(t *testing.T) {
	w, err := New(
		Tier{
			Engine: &stubEngine{
				name:     "fast",
				delay:    10 * time.Millisecond,
				response: &engine.Response{Status: 200, StatusText: "fast"},
			},
			Name: "fast",
		},
		Tier{
			Engine: &stubEngine{
				name:     "slow",
				delay:    500 * time.Millisecond,
				response: &engine.Response{Status: 200, StatusText: "slow"},
			},
			Name:        "slow",
			LaunchAfter: 100 * time.Millisecond,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	resp, err := w.Do(context.Background(), &engine.Request{URL: "http://test"})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusText != "fast" {
		t.Errorf("expected fast engine to win, got %s", resp.StatusText)
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("should complete quickly, took %v", elapsed)
	}
}

func TestWaterfall_SlowWinsWhenFastFails(t *testing.T) {
	w, err := New(
		Tier{
			Engine: &stubEngine{
				name:  "fast",
				delay: 10 * time.Millisecond,
				err:   fmt.Errorf("connection refused"),
			},
			Name: "fast",
		},
		Tier{
			Engine: &stubEngine{
				name:     "slow",
				delay:    50 * time.Millisecond,
				response: &engine.Response{Status: 200, StatusText: "slow"},
			},
			Name:        "slow",
			LaunchAfter: 20 * time.Millisecond,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := w.Do(context.Background(), &engine.Request{URL: "http://test"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusText != "slow" {
		t.Errorf("expected slow engine to win after fast fails, got %s", resp.StatusText)
	}

	m := w.Metrics()
	if m.Errors["fast"] != 1 {
		t.Errorf("fast errors = %d, want 1", m.Errors["fast"])
	}
	if m.Wins["slow"] != 1 {
		t.Errorf("slow wins = %d, want 1", m.Wins["slow"])
	}
}

func TestWaterfall_AllFail(t *testing.T) {
	w, err := New(
		Tier{
			Engine: &stubEngine{name: "a", delay: 10 * time.Millisecond, err: fmt.Errorf("fail-a")},
			Name:   "a",
		},
		Tier{
			Engine:      &stubEngine{name: "b", delay: 10 * time.Millisecond, err: fmt.Errorf("fail-b")},
			Name:        "b",
			LaunchAfter: 20 * time.Millisecond,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = w.Do(context.Background(), &engine.Request{URL: "http://test"})
	if err == nil {
		t.Fatal("expected error when all tiers fail")
	}
}

func TestWaterfall_PromoteTier(t *testing.T) {
	w, err := New(
		Tier{
			Engine: &stubEngine{name: "cheap", delay: 10 * time.Millisecond, err: fmt.Errorf("blocked")},
			Name:   "cheap",
		},
		Tier{
			Engine:      &stubEngine{name: "premium", delay: 10 * time.Millisecond, response: &engine.Response{Status: 200}},
			Name:        "premium",
			LaunchAfter: 2 * time.Second,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	// Promote premium to position 0
	w.PromoteTier("premium")

	resp, err := w.Do(context.Background(), &engine.Request{URL: "http://test"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 {
		t.Errorf("promoted tier should respond, got status %d", resp.Status)
	}
}

func TestWaterfall_ContextCancellation(t *testing.T) {
	w, err := New(Tier{
		Engine: &stubEngine{name: "slow", delay: 5 * time.Second, response: &engine.Response{Status: 200}},
		Name:   "slow",
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = w.Do(ctx, &engine.Request{URL: "http://test"})
	if err == nil {
		t.Fatal("expected error on context cancellation")
	}
}

func TestWaterfall_RequiresAtLeastOneTier(t *testing.T) {
	_, err := New()
	if err == nil {
		t.Fatal("expected error with no tiers")
	}
}
