// Quick Start 2: Heuristic Agent — Autonomous browsing without an LLM
//
// Usage:
//   go run 02_agent_heuristic.go https://news.ycombinator.com
//
// This demonstrates the full Agent loop using built-in decision heuristics.
// No external API calls — the agent makes its own choices based on simple rules.
//
// Heuristics available:
//   - Decisions.ClickFirstLink    → click the first <a> on the page
//   - Decisions.ScrollToBottom    → scroll until the bottom is reached
//   - Decisions.ScrollThenClick   → scroll once, then click first link
//   - Decisions.SubmitFirstForm   → fill and submit the first form
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/chromedp/chromedp"
	interact "github.com/skunkworq/stealth/brws/content/agent"
)

func main() {
	url := "https://news.ycombinator.com"
	if len(os.Args) > 1 {
		url = os.Args[1]
	}

	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	// Navigate
	if err := chromedp.Run(ctx, chromedp.Navigate(url)); err != nil {
		log.Fatalf("navigate failed: %v", err)
	}

	// Create agent with default config
	cfg := interact.DefaultConfig()
	cfg.SettleDelay = 1 * time.Second // wait 1s after each action
	agent := interact.NewAgent(cfg, nil, nil, nil)

	// ── Strategy 1: Scroll to bottom ──
	fmt.Println("=== Strategy: ScrollToBottom ===")
	for i := 0; i < 20; i++ {
		step, err := agent.Step(ctx, interact.Decisions.ScrollToBottom)
		if err != nil {
			log.Printf("step error: %v", err)
			break
		}

		noChange := step.Result != nil && step.Result.NoChange
		fmt.Printf("Step %d: %s → success=%v noChange=%v\n",
			i+1, step.Decision.ID, step.Result.Success, noChange)

		if noChange {
			fmt.Println("Reached bottom.\n")
			break
		}
	}

	// ── Strategy 2: Click the first link ──
	fmt.Println("=== Strategy: ClickFirstLink ===")
	step, err := agent.Step(ctx, interact.Decisions.ClickFirstLink)
	if err != nil {
		log.Printf("click error: %v", err)
	} else {
		fmt.Printf("Clicked %s → success=%v new_url=%s\n",
			step.Decision.ID, step.Result.Success, step.Result.NewURL)
	}

	// ── History summary ──
	fmt.Println("\n=== Agent History ===")
	for i, s := range agent.History() {
		noChange := ""
		if s.Result != nil && s.Result.NoChange {
			noChange = " [no-change]"
		}
		fmt.Printf("%d. %s → %s%s\n", i+1, s.Decision.Type, s.Decision.ID, noChange)
	}
	fmt.Printf("\n%s\n", agent.Summary())
}
