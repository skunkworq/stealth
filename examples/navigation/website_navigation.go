// This example demonstrates multi-step website navigation using the stealth
// framework with the chromium-stealth engine. It shows waiting for elements,
// executing JavaScript, extracting structured data, and following links.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/skunkworq/stealth/brws/browser/engine"
	_ "github.com/skunkworq/stealth/brws/browser/engine/browser/chromium"
	_ "github.com/skunkworq/stealth/brws/stealth/chromium"
	_ "github.com/skunkworq/stealth/brws/browser/engine/http/native"
)

func main() {
	ctx := context.Background()

	fmt.Println("=== Stealth Website Navigation Demo ===")
	fmt.Println()

	// -------------------------------------------------------------------------
	// Step 1: Create a stealth-enabled Chromium engine.
	// -------------------------------------------------------------------------
	// The "chromium-stealth" engine launches a real Chrome process with
	// anti-detection patches, human-like mouse movements, and stealth scripts.
	fmt.Println("Launching chromium-stealth engine...")
	eng, err := engine.New("chromium-stealth", engine.Options{
		Headless:       true,              // Set to false to watch the browser
		Timeout:        30 * time.Second,
		Stealth:        true,              // Enable header/TLS spoofing
		StealthTLS:     true,              // Enable TLS fingerprint spoofing
		ProfileName:    "chrome-120-macos",
	})
	if err != nil {
		log.Fatalf("Failed to create engine: %v", err)
	}
	defer func() { _ = eng.Close() }()

	fmt.Printf("Engine: %s\n", eng.Name())
	fmt.Printf("Capabilities: JS=%v HTTP2=%v HTTP3=%v\n",
		eng.Capabilities().JavaScript,
		eng.Capabilities().HTTP2,
		eng.Capabilities().HTTP3)
	fmt.Println()

	// -------------------------------------------------------------------------
	// Step 2: Navigate to a page and wait for a specific element.
	// -------------------------------------------------------------------------
	// We use httpbin.org as a stable demo target. In production you would
	// target real sites — the same code works unchanged.
	landingURL := "https://httpbin.org/html"
	fmt.Printf("Navigating to: %s\n", landingURL)

	resp, err := eng.Do(ctx, &engine.Request{
		URL:               landingURL,
		Method:            "GET",
		LoadStrategy: engine.LoadLoad,
		WaitForSelector:   "body",          // Wait until <body> is visible
		Timeout:           30 * time.Second,
	})
	if err != nil {
		log.Fatalf("Navigation failed: %v", err)
	}

	printResponse("Landing page", resp)

	// -------------------------------------------------------------------------
	// Step 3: Extract structured data from the page.
	// -------------------------------------------------------------------------
	htmlResp := engine.NewHtmlResponse(resp)

	fmt.Printf("Title: %s\n", htmlResp.GetTitle())
	fmt.Printf("Links found: %d\n", len(htmlResp.GetLinks()))
	fmt.Printf("Images found: %d\n", len(htmlResp.GetImages()))

	// Show first few links
	for i, link := range htmlResp.GetLinks() {
		if i >= 5 {
			break
		}
		fmt.Printf("  - %s\n", link)
	}
	fmt.Println()

	// -------------------------------------------------------------------------
	// Step 4: Execute JavaScript on the page.
	// -------------------------------------------------------------------------
	// We navigate back to the same page but this time inject a script that
	// returns the viewport size and user-agent — useful for verifying that
	// stealth spoofing is actually active.
	fmt.Println("Executing JavaScript to verify stealth context...")

	jsScript := `
		(() => {
			return JSON.stringify({
				userAgent: navigator.userAgent,
				platform: navigator.platform,
				language: navigator.language,
				viewport: {
					width: window.innerWidth,
					height: window.innerHeight
				},
				webdriver: navigator.webdriver,
				chrome: typeof window.chrome !== 'undefined'
			});
		})()
	`

	resp2, err := eng.Do(ctx, &engine.Request{
		URL:             landingURL,
		WaitForSelector: "body",
		ScriptToExecute: jsScript,
		Timeout:         30 * time.Second,
	})
	if err != nil {
		log.Fatalf("Script execution failed: %v", err)
	}

	// The script result isn't directly in the body for chromedp, but the
	// page HTML is. For a real JS-return-value workflow you'd use the
	// chromium package directly. Here we show the navigation succeeded.
	fmt.Printf("Page loaded after JS execution: %d bytes\n", len(resp2.Body))
	fmt.Println()

	// -------------------------------------------------------------------------
	// Step 5: Navigate to a form page and submit data.
	// -------------------------------------------------------------------------
	formURL := "https://httpbin.org/forms/post"
	fmt.Printf("Navigating to form page: %s\n", formURL)

	resp3, err := eng.Do(ctx, &engine.Request{
		URL:             formURL,
		WaitForSelector: "form",
		Timeout:         30 * time.Second,
	})
	if err != nil {
		log.Fatalf("Form page navigation failed: %v", err)
	}

	htmlResp3 := engine.NewHtmlResponse(resp3)
	forms := htmlResp3.GetForms()
	fmt.Printf("Forms detected: %d\n", len(forms))
	for i, form := range forms {
		fmt.Printf("  Form %d: action=%s method=%s fields=%d\n",
			i+1, form.Action, form.Method, len(form.Fields))
		for _, field := range form.Fields {
			fmt.Printf("    - %s (type=%s, required=%v)\n",
				field.Name, field.Type, field.Required)
		}
	}
	fmt.Println()

	// -------------------------------------------------------------------------
	// Step 6: POST form data.
	// -------------------------------------------------------------------------
	fmt.Println("Submitting form data via POST...")
	formReq := engine.NewFormRequest("https://httpbin.org/post", engine.FormData{
		"custname": "Stealth User",
		"custtel":  "+1-555-0199",
		"custemail": "stealth@example.com",
		"size":     "large",
		"topping":  "bacon",
		"delivery": "20:00",
		"comments": "Generated by stealth framework demo",
	})
	postResp, err := eng.Do(ctx, formReq.Request)
	if err != nil {
		log.Fatalf("POST failed: %v", err)
	}

	printResponse("Form submission", postResp)
	fmt.Println()

	// -------------------------------------------------------------------------
	// Step 7: Show network trace summary.
	// -------------------------------------------------------------------------
	fmt.Println("=== Network Trace Summary ===")
	fmt.Printf("Trace ID: %s\n", resp.Trace.RequestID)
	fmt.Printf("Trace entries: %d\n", len(resp.Trace.Entries))
	for _, entry := range resp.Trace.Entries {
		fmt.Printf("  %s %s -> %d (%s)\n",
			entry.Method, truncate(entry.URL, 50), entry.Status, entry.Protocol)
	}
	fmt.Println()

	fmt.Println("=== Demo complete ===")
}

func printResponse(label string, resp *engine.Response) {
	fmt.Printf("[%s] Status: %d %s\n", label, resp.Status, resp.StatusText)
	fmt.Printf("[%s] Protocol: %s\n", label, resp.Protocol)
	fmt.Printf("[%s] Final URL: %s\n", label, resp.FinalURL)
	fmt.Printf("[%s] Body size: %d bytes\n", label, len(resp.Body))
	fmt.Printf("[%s] Total time: %v\n", label, resp.Timing.Total)

	// Print a few response headers
	interesting := []string{"Content-Type", "Server", "Date"}
	for _, key := range interesting {
		if vals, ok := resp.Headers[key]; ok && len(vals) > 0 {
			fmt.Printf("[%s] Header %s: %s\n", label, key, vals[0])
		}
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
