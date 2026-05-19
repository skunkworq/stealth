//go:build ignore

// Quick Start 3: LLM-Driven Agent — Observe → Prompt → Decide → Execute
//
// Usage:
//   go run 03_agent_llm.go https://example.com
//
// This demonstrates the reactive agent loop. The agent observes and formats
// the page, then calls a decideFn callback where you plug in your LLM.
//
// The included decideFn is a DUMMY that picks random actions.
// Replace it with a real OpenAI/Anthropic/Local LLM call.
package main

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"

	"github.com/chromedp/chromedp"
	interact "github.com/skunkworq/stealth/brws/content/agent"
)

// ── Mock LLM ────────────────────────────────────────────────────────────────
// Replace this with your real LLM API call.
//
// The function receives:
//   - formatted: the compact page context (send this to the LLM)
//   - actions:   all available actions with IDs and descriptions
//
// It must return the Action.ID string of the chosen action, e.g. "click_E1".
func mockLLM(formatted string, actions []interact.Action) string {
	// In reality you would do something like:
	//
	//   prompt := fmt.Sprintf(
	//     "You are a web browsing agent. Choose ONE action by ID.\n\n%s",
	//     formatted)
	//   response := openaiChatCompletion(prompt)
	//   return strings.TrimSpace(response)
	//
	// For demo purposes, we pick a random action that isn't "done".
	eligible := make([]interact.Action, 0, len(actions))
	for _, a := range actions {
		if a.ID != "done" {
			eligible = append(eligible, a)
		}
	}
	if len(eligible) == 0 {
		return "done"
	}
	return eligible[rand.Intn(len(eligible))].ID
}

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

	// Create agent
	cfg := interact.DefaultConfig()
	cfg.SettleDelay = 2 * time.Second
	agent := interact.NewAgent(cfg, nil, nil, nil)

	// ── Agent Loop ───────────────────────────────────────────────────────────
	fmt.Println("=== Starting LLM-Driven Agent Loop ===\n")
	maxSteps := 5

	for i := 0; i < maxSteps; i++ {
		// 1. Observe + format
		pageCtx, actions, formatted, err := agent.Observe(ctx)
		if err != nil {
			log.Fatalf("observe failed: %v", err)
		}

		fmt.Printf("--- Step %d | %s | %d actions ---\n",
			i+1, pageCtx.Snapshot.URL, len(actions))

		// 2. Decide (call LLM)
		actionID := mockLLM(formatted, actions)
		fmt.Printf("LLM chose: %s\n", actionID)

		// 3. Find action
		act := pageCtx.ActionSpace.Find(actionID)
		if act == nil {
			fmt.Printf("Unknown action '%s' — stopping.\n", actionID)
			break
		}

		// 4. Execute
		res, err := agent.Execute(ctx, *act)
		if err != nil {
			log.Printf("execute error: %v", err)
		}
		fmt.Printf("Result: success=%v new_url=%s no_change=%v\n\n",
			res.Success, res.NewURL, res.NoChange)

		// 5. Termination
		if actionID == "done" {
			fmt.Println("Agent signaled completion.")
			break
		}
	}

	// ── Final Summary ────────────────────────────────────────────────────────
	fmt.Println("=== Agent History ===")
	for i, s := range agent.History() {
		url := ""
		if s.Result != nil && s.Result.NewURL != "" {
			url = " → " + s.Result.NewURL
		}
		fmt.Printf("%d. %s (%s)%s\n", i+1, s.Decision.ID, s.Decision.Type, url)
	}
	fmt.Printf("\n%s\n", agent.Summary())
}
