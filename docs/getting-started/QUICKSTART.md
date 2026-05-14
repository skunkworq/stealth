# Stealth — Comprehensive Quickstart Guide

> Get from zero to scraping with anti-detection in 15 minutes.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Installation](#2-installation)
3. [Project Overview](#3-project-overview)
4. [Quickstart: Fingerprint a Real Browser](#4-quickstart-fingerprint-a-real-browser)
5. [Quickstart: Launch a Stealth Browser](#5-quickstart-launch-a-stealth-browser)
6. [Quickstart: Scrape with Proxy Rotation](#6-quickstart-scrape-with-proxy-rotation)
7. [Quickstart: Solve a Cloudflare Challenge](#7-quickstart-solve-a-cloudflare-challenge)
8. [Quickstart: Agentic Graph Scraping](#8-quickstart-agentic-graph-scraping)
9. [Quickstart: CDP Browser Agent](#9-quickstart-cdp-browser-agent)
10. [Configuration Reference](#10-configuration-reference)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Go | 1.26+ | `go version` |
| Chrome/Chromium | 120+ | For CDP-based automation |
| Python | 3.10+ | For ML training scripts (optional) |
| Rust | 1.75+ | For packet sniffer FFI (optional) |
| OpenRouter API Key | — | For LLM features (semantic, agentic) |

### Install Chrome

```bash
# macOS
brew install --cask google-chrome

# Ubuntu/Debian
wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
sudo sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list'
sudo apt update && sudo apt install google-chrome-stable

# Verify
google-chrome --version
```

### Set Environment Variables

```bash
export OPENROUTER_API_KEY="sk-or-v1-..."
export CHROME_BIN="/usr/bin/google-chrome"  # or /Applications/Google\ Chrome.app/... on macOS
```

---

## 2. Installation

```bash
git clone https://github.com/skunkworq/stealth.git
cd stealth
go mod download

# Optional: build all commands
go build ./cmd/...

# Verify
go test ./brws/content/agentic/... -v
```

---

## 3. Project Overview

Stealth is a multi-layer anti-detection scraping framework. You can use it at different levels of abstraction:

| Level | Use Case | Entry Point |
|---|---|---|
| **Level 0** | Simple HTTP with TLS spoofing | `brws/browser/engine` native engine |
| **Level 1** | Browser automation | `brws/browser/engine/browser/chromium` |
| **Level 2** | Stealth browser (anti-detection) | `brws/browser/engine/browser/chromium-stealth` |
| **Level 3** | Full evasion stack (CAPTCHA, behavior, proxy) | `brws/stealth/client.go` |
| **Level 4** | LLM-driven scraping | `brws/content/agentic` |
| **Level 5** | Autonomous browser agent | `brws/content/agent` |

---

## 4. Quickstart: Fingerprint a Real Browser

Capture the TLS fingerprint of your local Chrome to understand what a real browser looks like.

### 4.1 Start the Capture Lab

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/skunkworq/stealth/brws/network/proxy"
)

func main() {
    // Create MITM proxy
    p, err := proxy.NewProxy(&proxy.ProxyConfig{
        ListenAddr:      ":8081",
        EnableMITM:      true,
        EnableHTTPTrace: true,
    }, nil)
    if err != nil {
        log.Fatal(err)
    }

    // Set up capture callback
    p.SetCaptureCallbacks(
        func(ch *tlsparser.ClientHello, fp *types.CompleteFingerprint) {
            fmt.Printf("Captured JA3: %s\n", fp.TLS.JA3Hash)
            fmt.Printf("Captured JA4: %s\n", fp.TLS.JA4)
            fmt.Printf("Cipher suites: %d\n", len(ch.CipherSuites))
            fmt.Printf("Extensions: %d\n", len(ch.Extensions))
        },
        nil, nil,
    )

    if err := p.Start(); err != nil {
        log.Fatal(err)
    }
    defer p.Stop()

    fmt.Println("Proxy running on :8081")
    fmt.Println("Configure Chrome to use localhost:8081 and visit https://example.com")

    // Serve PAC file for easy browser configuration
    go http.ListenAndServe(":8080", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
        w.Write([]byte(p.GetPACFile()))
    }))

    time.Sleep(5 * time.Minute)
}
```

### 4.2 Configure Chrome to Use the Proxy

```bash
# Launch Chrome with proxy
google-chrome --proxy-pac-url=http://localhost:8080

# Or manually set proxy to localhost:8081
```

### 4.3 View Results

Visit any HTTPS site. The proxy prints:

```
Captured JA3: 769,47-53-5-10,0-10-11,23-24-25,0
Captured JA4: t13d1516h2_8daaf6152771_02713d6af862
Cipher suites: 17
Extensions: 21
```

---

## 5. Quickstart: Launch a Stealth Browser

Open a page using the stealth-hardened Chromium engine with automatic anti-detection patches.

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/skunkworq/stealth/brws/browser/engine"
)

func main() {
    ctx := context.Background()

    // Create stealth engine
    eng, err := engine.New("chromium-stealth", engine.Options{
        Headless:    false,  // set true for headless
        Proxy:       "",     // e.g. "http://proxy:8080"
        Timeout:     30 * time.Second,
        StealthPlus: false,  // set true for advanced features
    })
    if err != nil {
        log.Fatal(err)
    }
    defer eng.Close()

    // Navigate and fetch
    resp, err := eng.Do(ctx, &engine.Request{
        Method: "GET",
        URL:    "https://bot.sannysoft.com",  // anti-bot test page
    })
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Status: %d\n", resp.Status)
    fmt.Printf("Title: %s\n", resp.Title)
    fmt.Printf("Body length: %d\n", len(resp.Body))

    // Check if we passed detection
    if !resp.Detected {
        fmt.Println("✅ Stealth successful — not detected as bot")
    } else {
        fmt.Println("⚠️  Detection signals found")
        for _, sig := range resp.DetectionSignals {
            fmt.Printf("  - %s\n", sig)
        }
    }
}
```

### Run

```bash
go run main.go
```

You should see Chrome open, navigate to the test page, and report stealth success.

---

## 6. Quickstart: Scrape with Proxy Rotation

Rotate through multiple proxies with automatic health tracking and tier escalation.

```go
package main

import (
    "context"
    "fmt"
    "log"
    "net/http"
    "time"

    "github.com/skunkworq/stealth/brws/network/proxy/pool"
)

func main() {
    // Create proxy pool
    p := pool.NewPool([]string{
        "http://user:pass@proxy1.example.com:8080",
        "http://user:pass@proxy2.example.com:8080",
        "http://user:pass@proxy3.example.com:8080",
    }, pool.StrategyRoundRobin)

    // Create HTTP client with rotation
    client := &http.Client{
        Timeout: 30 * time.Second,
        Transport: &http.Transport{
            Proxy: func(r *http.Request) (*url.URL, error) {
                proxy := p.Get()
                if proxy == nil {
                    return nil, nil
                }
                return url.Parse(proxy.URL)
            },
        },
    }

    // Make requests
    for i := 0; i < 10; i++ {
        req, _ := http.NewRequestWithContext(context.Background(), "GET", "https://httpbin.org/ip", nil)
        resp, err := client.Do(req)
        if err != nil {
            log.Printf("Request %d failed: %v", i, err)
            continue
        }
        body, _ := io.ReadAll(resp.Body)
        resp.Body.Close()
        fmt.Printf("Request %d: %s\n", i, string(body))
        time.Sleep(2 * time.Second)
    }

    // Print pool stats
    stats := p.Stats()
    fmt.Printf("Total requests: %d, Successes: %d, Failures: %d\n",
        stats.TotalRequests, stats.Successes, stats.Failures)
}
```

### Tiered Escalation (Advanced)

```go
// Escalate from datacenter → residential → mobile per domain
tracker := pool.NewTierTracker([]pool.TieredProxy{
    {Level: 0, Pool: dcPool, Label: "datacenter"},
    {Level: 1, Pool: resPool, Label: "residential"},
    {Level: 2, Pool: mobPool, Label: "mobile"},
})

req, _ := http.NewRequest("GET", "https://example.com", nil)
proxy := tracker.Get(req.URL.String())
// ... execute request ...
if err != nil {
    tracker.RecordError(req.URL.String())
} else {
    tracker.RecordSuccess(req.URL.String(), latency)
}
```

---

## 7. Quickstart: Solve a Cloudflare Challenge

Automatically detect and solve Cloudflare Turnstile or JS challenges.

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/skunkworq/stealth/brws/browser/engine"
    "github.com/skunkworq/stealth/brws/stealth"
)

func main() {
    ctx := context.Background()

    // Create stealth client with challenge solving
    client, err := stealth.NewAdaptiveFromConfig(stealth.Config{
        EngineName: "chromium-stealth",
        Headless:   true,
        Challenge: &stealth.ChallengeConfig{
            AutoSolve: true,
            AutoDetect: true,
        },
        Escalation: &stealth.EscalationConfig{
            Enabled:              true,
            MaxEscalationRetries: 3,
        },
    })
    if err != nil {
        log.Fatal(err)
    }

    // The client automatically handles challenges
    resp, err := client.Scrape(ctx, "https://cloudflare-challenge-site.com")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Status: %d\n", resp.Status)
    fmt.Printf("Challenge solved: %v\n", resp.ChallengeSolved)
    fmt.Printf("Body length: %d\n", len(resp.Body))

    // Extract data
    doc, err := resp.AsHTML()
    if err != nil {
        log.Fatal(err)
    }

    titles := doc.QuerySelectorAll("h1")
    for _, t := range titles {
        fmt.Printf("Title: %s\n", t.Text())
    }

    // Query by class or ID
    if el := doc.QuerySelector(".content"); el != nil {
        fmt.Printf("Content: %s\n", el.Text())
    }
}
```

### Challenge Detection Only

```go
// Just detect if a page has a challenge
classifier := challenge.NewClassifier()
result := classifier.Classify(resp.Body)
fmt.Printf("Challenge type: %s\n", result.Type)
fmt.Printf("Confidence: %.2f\n", result.Confidence)

switch result.Type {
case challenge.CloudflareTurnstile:
    fmt.Println("Cloudflare Turnstile detected")
case challenge.CloudflareJS:
    fmt.Println("Cloudflare JS challenge detected")
case challenge.ReCAPTCHAv2:
    fmt.Println("reCAPTCHA v2 detected")
case challenge.None:
    fmt.Println("No challenge detected")
}
```

---

## 8. Quickstart: Agentic Graph Scraping

Use the ScrapeGraphAI-style LLM-driven pipeline for structured extraction.

### 8.1 Single Page Extraction

```go
package main

import (
    "context"
    "fmt"
    "log"
    "os"

    "github.com/skunkworq/stealth/brws/content/agentic"
    "github.com/skunkworq/stealth/brws/content/semantic"
)

func main() {
    ctx := context.Background()

    // Initialize LLM
    llm := agentic.NewSemanticLLM(semantic.NewLLMClient(os.Getenv("OPENROUTER_API_KEY")))

    // Create graph
    graph, err := agentic.NewSmartScraperGraph(
        "Extract all product names and prices as JSON with keys 'products' (array of {name, price})",
        "https://example.com/products",
        map[string]interface{}{
            "reasoning": true,   // adds pre-processing reasoning node
            "reattempt": true,   // retries on empty/NA answers
        },
        nil, // schema (optional)
        llm,
    )
    if err != nil {
        log.Fatal(err)
    }

    // Execute
    state, info, err := graph.Run(ctx)
    if err != nil {
        log.Fatal(err)
    }

    // Results
    fmt.Printf("Answer: %+v\n", state["answer"])
    fmt.Printf("Nodes executed: %d\n", len(info))
    for _, i := range info {
        fmt.Printf("  %s: %v\n", i.NodeName, i.ExecTime)
    }
}
```

### 8.2 Search then Scrape

```go
// Search the web, then scrape top results
searchGraph, err := agentic.NewSearchGraph(
    "What are the latest features in Go 1.24?",
    map[string]interface{}{
        "max_results": 3,
    },
    nil,
    llm,
)
if err != nil {
    log.Fatal(err)
}

state, _, err := searchGraph.Run(ctx)
fmt.Printf("Synthesized answer: %+v\n", state["answer"])
```

### 8.3 With Custom Schema

```go
type Product struct {
    Name  string `json:"name"`
    Price string `json:"price"`
    URL   string `json:"url"`
}

graph, err := agentic.NewSmartScraperGraph(
    "Extract all products from this page",
    "https://example.com/shop",
    map[string]interface{}{},
    Product{}, // schema for structured output
    llm,
)
```

---

## 9. Quickstart: CDP Browser Agent

Use the observe-decide-execute agent for autonomous browser navigation.

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/chromedp/chromedp"
    "github.com/skunkworq/stealth/brws/content/agent"
)

func main() {
    ctx := context.Background()

    // Create chromedp context
    allocCtx, cancel := chromedp.NewExecAllocator(ctx, chromedp.DefaultExecAllocatorOptions[:]...)
    defer cancel()
    browserCtx, cancel := chromedp.NewContext(allocCtx)
    defer cancel()

    // Create agent components
    observer := agent.NewObserver(browserCtx)
    formatter := agent.DefaultFormatter()
    executor := &agent.Executor{}

    // Create agent
    cfg := agent.Config{
        MaxRetries:    3,
        SettleDelay:   500 * time.Millisecond,
        ActionTimeout: 30 * time.Second,
        StealthMode:   true,
    }
    ag := agent.NewAgent(cfg, observer, formatter, executor)

    // Navigate to starting page
    chromedp.Run(browserCtx, chromedp.Navigate("https://example.com"))

    // Define a simple decision function
    decideFn := func(ctx *agent.Context, actions []agent.Action, formatted string, hist []agent.Step) (agent.Action, error) {
        // Click the first link we haven't visited yet
        for _, a := range actions {
            if a.Type == agent.ActionClick && a.IsLink {
                return a, nil
            }
        }
        return agent.Action{Type: agent.ActionNone}, fmt.Errorf("no actions")
    }

    // Run 5 steps
    for i := 0; i < 5; i++ {
        step, err := ag.Step(ctx, decideFn)
        if err != nil {
            log.Printf("Step %d error: %v", i, err)
            break
        }
        fmt.Printf("Step %d: %s -> %s\n", i, step.Decision.Type, step.Result.NewURL)
    }

    fmt.Println(ag.Summary())
}
```

### Built-in Decision Helpers

```go
// Scroll to bottom then stop
for {
    step, err := ag.Step(ctx, agent.Decisions.ScrollToBottom)
    if err != nil {
        break  // "at bottom of page"
    }
    _ = step
}

// Click first link
step, err := ag.Step(ctx, agent.Decisions.ClickFirstLink)

// Fill and submit first form
step, err = ag.Step(ctx, agent.Decisions.SubmitFirstForm)
```

---

## 10. Configuration Reference

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `OPENROUTER_API_KEY` | For LLM features | API key for semantic/agentic pipelines |
| `CHROME_BIN` | No | Path to Chrome/Chromium binary |
| `PROXY_SCRAPE_DO_URL` | No | Scrape.do proxy endpoint |
| `BROWSERBASE_API_KEY` | No | BrowserBase API key |

### Stealth Config (`brws/core/config/stealth.go`)

```go
type StealthConfig struct {
    // Browser
    Headless        bool
    StealthLevel    int     // 0-5
    StealthPlus     bool
    ProfileDir      string

    // TLS
    SpoofTLS        bool
    BrowserType     string  // "chrome", "firefox", "safari"
    BrowserVersion  string
    RotateJA3       bool

    // Proxy
    ProxyURL        string
    ProxyStrategy   string  // "round_robin", "random", "fastest"
    ProxyTier       int     // 0=datacenter, 1=residential, 2=mobile

    // Timing
    MinDelay        time.Duration
    MaxDelay        time.Duration
    RequestTimeout  time.Duration

    // Challenges
    SolveCaptcha    bool
    SolveCloudflare bool
    MaxChallengeTime time.Duration

    // Crawl
    RespectRobots   bool
    MaxConcurrent   int
    RequestsPerSecond float64
}
```

### Default Config

```go
cfg := config.DefaultStealthConfig()
cfg.Engine.Headless = true
cfg.Engine.StealthTLS = true
cfg.Engine.Stealth = true
cfg.Engine.Profile = "chrome-120-macos"
cfg.Cloudflare.Detect = true
cfg.Cloudflare.Solve = true
```

---

## 11. Troubleshooting

### Chrome not found

```bash
# Set explicitly
export CHROME_BIN="/usr/bin/google-chrome"

# Or use chromedp's auto-discovery (usually works on standard installs)
```

### OpenRouter errors

```bash
# Verify key is set
echo $OPENROUTER_API_KEY

# Check balance at https://openrouter.ai/settings/keys
# Common errors: 402 (insufficient credits), 429 (rate limit)
```

### TLS spoofing not working

```bash
# Verify uTLS is working
go test ./brws/fingerprint/tls/... -v -run TestSpoofer

# Check if target uses TLS fingerprinting
# Some sites check JA3 but not HTTP/2 fingerprints — try toggling H2
```

### Proxy connection refused

```bash
# Test proxy manually
curl -x http://proxy:port https://httpbin.org/ip

# Check proxy health in pool
pool.Get().IsWorking
```

### Detection on bot.sannysoft.com

If stealth test pages still show detection:
1. Increase `StealthLevel` to 4 or 5
2. Enable `StealthPlus`
3. Bind a real captured fingerprint via `engine.Options.Fingerprint`
4. Use a residential proxy (tier 1+)
5. Enable behavioral mimicry with realistic timing

### Build errors

```bash
# Clean and rebuild
go clean -cache
go mod tidy
go build ./...

# If Rust FFI fails, skip it:
go build -tags norust ./...
```

---

## Next Steps

| Goal | Read |
|---|---|
| Understand architecture | [`MODELS_INDEX.md`](../modules/MODELS_INDEX.md) |
| Deep dive into fingerprinting | [`MODEL_FINGERPRINT.md`](../modules/MODEL_FINGERPRINT.md) |
| Deep dive into browser engine | [`MODEL_BROWSER.md`](../modules/MODEL_BROWSER.md) |
| Deep dive into stealth/evasion | [`MODEL_STEALTH.md`](../modules/MODEL_STEALTH.md) |
| Deep dive into content extraction | [`MODEL_CONTENT.md`](../modules/MODEL_CONTENT.md) |
| Train ML models | `brws/ml/train_rl_agent.py`, `brws/ml/train_shield_sword.py` |
| Run benchmarks | `go test ./brws/fingerprint/bench/... -bench=. -benchmem` |

---

*Happy scraping.*
