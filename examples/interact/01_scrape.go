//go:build ignore

// Quick Start 1: Scrape — Extract structured page state via CDP
//
// Usage:
//   go run 01_scrape.go https://news.ycombinator.com
//
// This demonstrates the Observer layer by itself. No agent loop, no LLM,
// no decisions — just navigate, observe, and dump the page snapshot.
package main

import (
	"context"
	"encoding/json"
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

	// Navigate with timeout
	navCtx, navCancel := context.WithTimeout(ctx, 30*time.Second)
	defer navCancel()
	if err := chromedp.Run(navCtx, chromedp.Navigate(url)); err != nil {
		log.Fatalf("navigate failed: %v", err)
	}

	// Observe full page state
	obs := interact.DefaultObserver()
	snap, err := obs.Observe(ctx)
	if err != nil {
		log.Fatalf("observe failed: %v", err)
	}

	// ── Summary ──
	fmt.Printf("URL:      %s\n", snap.URL)
	fmt.Printf("Title:    %s\n", snap.Title)
	fmt.Printf("Viewport: %.0f×%.0f\n", snap.Viewport.Width, snap.Viewport.Height)
	fmt.Printf("Scroll:   %.0f / %.0f px\n", snap.Scroll.Y, snap.Scroll.MaxY)
	fmt.Printf("Elements: %d interactive\n", len(snap.Elements))
	fmt.Printf("Links:    %d\n", len(snap.Links))
	fmt.Printf("Forms:    %d\n", len(snap.Forms))
	fmt.Printf("Tabs:     %d\n", len(snap.Tabs))
	fmt.Printf("History:  %d entries (back=%v forward=%v)\n",
		snap.History.Length, snap.History.CanGoBack, snap.History.CanGoForward)

	// ── First 5 elements ──
	fmt.Println("\n--- Top Interactive Elements ---")
	for i, el := range snap.Elements {
		if i >= 5 {
			break
		}
		fmt.Printf("[%s] <%s> %q @ (%.0f, %.0f)\n",
			el.ID, el.Tag, el.Text, el.Bounds.X, el.Bounds.Y)
	}

	// ── First 5 links ──
	fmt.Println("\n--- Top Links ---")
	for i, link := range snap.Links {
		if i >= 5 {
			break
		}
		fmt.Printf("- %s → %s\n", link.Text, link.Href)
	}

	// ── Full JSON export ──
	b, _ := json.MarshalIndent(snap, "", "  ")
	_ = os.WriteFile("snapshot.json", b, 0644)
	fmt.Println("\n✓ Full snapshot written to snapshot.json")
}
