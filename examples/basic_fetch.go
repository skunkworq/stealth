// This example demonstrates basic usage of the brws library
// to fetch a URL using different engines.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/skunkworq/stealth/brws/engine"
	// Import engines to register them
	_ "github.com/skunkworq/stealth/brws/engine/chromium"
	_ "github.com/skunkworq/stealth/brws/engine/native"
)

func main() {
	ctx := context.Background()

	// List available engines
	fmt.Println("Available engines:")
	for _, name := range engine.Available() {
		fmt.Printf("  - %s\n", name)
	}
	fmt.Println()

	// Example 1: Fetch with native Go engine
	fmt.Println("=== Native Engine ===")
	if err := fetchWithEngine(ctx, "native", "https://httpbin.org/get"); err != nil {
		log.Printf("Native fetch failed: %v", err)
	}

	// Example 2: Fetch with Chromium engine (requires Chrome installed)
	fmt.Println("\n=== Chromium Engine ===")
	if err := fetchWithEngine(ctx, "chromium", "https://httpbin.org/get"); err != nil {
		log.Printf("Chromium fetch failed: %v", err)
		log.Println("(Make sure Chrome/Chromium is installed)")
	}
}

func fetchWithEngine(ctx context.Context, engineName, url string) error {
	// Create engine
	eng, err := engine.New(engineName, engine.Options{
		Timeout:  30 * time.Second,
		Headless: true,
	})
	if err != nil {
		return fmt.Errorf("creating engine: %w", err)
	}
	defer func() { _ = eng.Close() }()

	// Print capabilities
	caps := eng.Capabilities()
	fmt.Printf("Engine: %s\n", eng.Name())
	fmt.Printf("  JavaScript: %v\n", caps.JavaScript)
	fmt.Printf("  HTTP/2: %v\n", caps.HTTP2)
	fmt.Printf("  HTTP/3: %v\n", caps.HTTP3)
	fmt.Printf("  Persistent Profile: %v\n", caps.PersistentProfile)

	// Create request
	req := &engine.Request{
		Method:  "GET",
		URL:     url,
		Headers: map[string][]string{
			"Accept": {"application/json"},
		},
		Timeout:         30 * time.Second,
		FollowRedirects: true,
	}

	// Execute request
	resp, err := eng.Do(ctx, req)
	if err != nil {
		return fmt.Errorf("fetching: %w", err)
	}

	// Print response
	fmt.Printf("Status: %d\n", resp.Status)
	fmt.Printf("Protocol: %s\n", resp.Protocol)
	fmt.Printf("Final URL: %s\n", resp.FinalURL)
	fmt.Printf("Body length: %d bytes\n", len(resp.Body))
	fmt.Printf("Timing: %v\n", resp.Timing.Total)

	return nil
}
