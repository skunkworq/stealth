package chromium

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/skunkworq/stealth/brws/instrumentation"
)

// newSettleTestEngine builds a StealthEngine carrying only what challengeSettle
// touches (the logger). challengeSettle does no browser I/O, so this is enough
// to exercise the network-idle / redirect-settle logic hermetically.
func newSettleTestEngine() *StealthEngine {
	return &StealthEngine{logger: instrumentation.Named("settle-test")}
}

// TestChallengeSettle_CleanPage: a page that loads, has no in-flight requests and
// never re-navigates should settle as soon as the idle window elapses — well
// before the budget. (Mirrors example.com: one navigation, no challenge.)
func TestChallengeSettle_CleanPage(t *testing.T) {
	s := newSettleTestEngine()
	var mu sync.Mutex
	inFlight := 0
	navCount := 1 // the initial navigation already committed
	last := time.Now()

	start := time.Now()
	s.challengeSettle(context.Background(), &mu, &inFlight, &last, &navCount, 5*time.Second, 200*time.Millisecond)
	elapsed := time.Since(start)

	if elapsed >= 1*time.Second {
		t.Errorf("clean page should settle quickly (~idle window), took %v", elapsed)
	}
}

// TestChallengeSettle_ChallengeRedirect: a challenge keeps the network busy, then
// redirects (a new top-level navigation) and finally goes quiet. Settle must wait
// past the busy period and return only once the post-redirect network is idle —
// not on the pre-challenge stub.
func TestChallengeSettle_ChallengeRedirect(t *testing.T) {
	s := newSettleTestEngine()
	var mu sync.Mutex
	inFlight := 2 // challenge script + telemetry POST in flight
	navCount := 1
	last := time.Now()

	// Simulate the Kasada-style flow: stay busy ~400ms, fire a redirect
	// (navCount++), keep loading the real page ~400ms more, then go idle.
	go func() {
		time.Sleep(400 * time.Millisecond)
		mu.Lock()
		navCount++ // challenge redirected into the real document
		inFlight = 3
		last = time.Now()
		mu.Unlock()

		time.Sleep(400 * time.Millisecond)
		mu.Lock()
		inFlight = 0 // real page finished loading
		last = time.Now()
		mu.Unlock()
	}()

	start := time.Now()
	s.challengeSettle(context.Background(), &mu, &inFlight, &last, &navCount, 5*time.Second, 200*time.Millisecond)
	elapsed := time.Since(start)

	// Must have waited through the busy period + redirect + idle window
	// (~800ms+200ms), and must not have hit the 5s budget.
	if elapsed < 700*time.Millisecond {
		t.Errorf("settled too early (captured stub?), took only %v", elapsed)
	}
	if elapsed >= 5*time.Second {
		t.Errorf("settle hit budget instead of detecting idle, took %v", elapsed)
	}
	mu.Lock()
	gotNav := navCount
	mu.Unlock()
	if gotNav <= 1 {
		t.Errorf("expected a post-load redirect navigation, navCount=%d", gotNav)
	}
}

// TestChallengeSettle_BudgetBound: a challenge that never goes idle (network
// stays busy forever) must still return when the budget expires — it can't hang.
func TestChallengeSettle_BudgetBound(t *testing.T) {
	s := newSettleTestEngine()
	var mu sync.Mutex
	inFlight := 1 // perpetually busy
	navCount := 1
	last := time.Now()

	// Keep nudging activity so it never goes idle.
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				mu.Lock()
				last = time.Now()
				mu.Unlock()
			}
		}
	}()
	defer close(stop)

	budget := 600 * time.Millisecond
	start := time.Now()
	s.challengeSettle(context.Background(), &mu, &inFlight, &last, &navCount, budget, 200*time.Millisecond)
	elapsed := time.Since(start)

	if elapsed < budget {
		t.Errorf("returned before budget (%v < %v)", elapsed, budget)
	}
	if elapsed > budget+500*time.Millisecond {
		t.Errorf("overshot budget significantly: %v", elapsed)
	}
}

// TestChallengeSettle_ContextCancel: a cancelled context unblocks the wait
// immediately rather than burning the full budget.
func TestChallengeSettle_ContextCancel(t *testing.T) {
	s := newSettleTestEngine()
	var mu sync.Mutex
	inFlight := 1 // busy, would otherwise wait the whole budget
	navCount := 1
	last := time.Now()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	s.challengeSettle(ctx, &mu, &inFlight, &last, &navCount, 10*time.Second, 200*time.Millisecond)
	elapsed := time.Since(start)

	if elapsed >= 1*time.Second {
		t.Errorf("context cancel should unblock quickly, took %v", elapsed)
	}
}
