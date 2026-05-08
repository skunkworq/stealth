# Stealth Browser Evasion System — Historical Design Document

> **Note:** This document was written early in the project lifecycle and reflects the original design vision. The actual implementation has evolved significantly. For the current system, see [`README.md`](../README.md), [`docs/ARCHITECTURE.md`](./ARCHITECTURE.md), and the [`MODEL_*.md`](../modules/MODELS_INDEX.md) module docs.

# Stealth Browser Evasion System - Design Document

## Overview

This document outlines the design and implementation plan for a production-grade browser evasion system capable of scraping protected websites with >80% success rates. The system is inspired by nodriver, ZenRows, and Scrapefly architectures.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Stealth CLI                                    │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │   Session   │  │  Challenge  │  │  Behavior  │  │   TLS/HTTP  │ │
│  │  Manager    │  │   Solver    │  │  Simulator │  │   Spoofing  │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘ │
│         │                 │                 │                 │          │
│         └────────────────┴────────┬────────┴─────────────────┘          │
│                                    │                                      │
│                          ┌─────────▼─────────┐                           │
│                          │  Browser Engine   │                           │
│                          │    (chromedp)     │                           │
│                          └─────────┬─────────┘                           │
│                                    │                                      │
│                          ┌─────────▼─────────┐                           │
│                          │  Chrome Browser   │                           │
│                          │   (Stealth Mode)  │                           │
│                          └───────────────────┘                           │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Component Design

### 1. Browser Engine

**Package**: `brws/engine`

The core browser control component using CDP (Chrome DevTools Protocol).

#### 1.1 Stealth Configuration

```go
// brws/engine/stealth/config.go
package stealth

type Config struct {
    // Browser launch options
    Headless        bool
    DisableGPU      bool
    NoSandbox       bool
    UserDataDir     string
    Lang            string
    WindowSize      Size
    BrowserExe      string
    
    // Stealth features
    RemoveWebDriver bool   // Remove navigator.webdriver
    CanvasNoise     bool   // Add canvas fingerprint noise
    WebGLSpoof     bool   // Spoof WebGL vendor/renderer
    ClientHints    bool   // Spoof sec-ch-ua headers
    FakeScreen     bool   // Override screen properties
    FakeTimezone   bool   // Override timezone
}

type Size struct {
    Width  int
    Height int
}

// Default stealth config
func DefaultConfig() *Config {
    return &Config{
        Headless:         false,
        DisableGPU:       false,
        NoSandbox:        false,
        Lang:             "en-US",
        WindowSize:       Size{Width: 1920, Height: 1080},
        RemoveWebDriver:  true,
        CanvasNoise:      true,
        WebGLSpoof:      true,
        ClientHints:     true,
        FakeScreen:       true,
        FakeTimezone:     false,
    }
}
```

#### 1.2 Chrome Launch Arguments

```go
// brws/engine/stealth/args.go
package stealth

// Critical stealth arguments that nodriver uses
var DefaultArgs = []string{
    // Allow remote connections
    "--remote-allow-origins=*",
    
    // Disable first-run wizard
    "--no-first-run",
    "--no-default-browser-check",
    
    // Disable auto-updates
    "--no-service-autorun",
    
    // Disable unwanted features
    "--no-pings",
    "--password-store=basic",
    "--disable-infobars",
    "--disable-breakpad",
    "--disable-dev-shm-usage",
    "--disable-session-crashed-bubble",
    "--disable-search-engine-choice-screen",
    
    // CRITICAL: Disable automation detection
    "--disable-blink-features=AutomationControlled",
}

// Args returns full argument list based on config
func (c *Config) Args() []string {
    args := make([]string, len(DefaultArgs))
    copy(args, DefaultArgs)
    
    // Add language
    args = append(args, "--lang="+c.Lang)
    
    // Add window size
    args = append(args, fmt.Sprintf("--window-size=%d,%d", 
        c.WindowSize.Width, c.WindowSize.Height))
    
    // Conditional args
    if c.Headless {
        args = append(args, "--headless=new")
    }
    if c.NoSandbox {
        args = append(args, "--no-sandbox")
    }
    if c.DisableGPU {
        args = append(args, "--disable-gpu")
    }
    if c.UserDataDir != "" {
        args = append(args, "--user-data-dir="+c.UserDataDir)
    }
    
    return args
}
```

#### 1.3 Browser Pool

```go
// brws/engine/pool.go
package engine

type BrowserPool struct {
    config     *stealth.Config
    browsers   chan *Browser
    maxSize    int
    factory    *BrowserFactory
}

type Browser struct {
    Context     context.Context
    Cancel      context.CancelFunc
    Profile     *BrowserProfile
    cookies     []*http.Cookie
    localStorage map[string]string
    created     time.Time
}

type BrowserProfile struct {
    UserAgent      string
    Platform       string
    CanvasNoise    bool
    WebGLVendor    string
    WebGLRenderer  string
    Timezone       string
    ScreenSize    Size
}

func NewPool(cfg *stealth.Config, maxSize int) *BrowserPool {
    return &BrowserPool{
        config:   cfg,
        browsers: make(chan *Browser, maxSize),
        maxSize:  maxSize,
    }
}

func (p *BrowserPool) Get(ctx context.Context) (*Browser, error) {
    select {
    case b := <-p.browsers:
        if b.IsHealthy() {
            return b, nil
        }
        b.Close()
        // Fall through to create new
    default:
        // Pool empty, create new
    }
    
    return p.factory.Create(ctx)
}

func (p *BrowserPool) Put(b *Browser) {
    if !b.IsHealthy() {
        b.Close()
        return
    }
    
    select {
    case p.browsers <- b:
    default:
        b.Close()  // Pool full
    }
}

func (b *Browser) IsHealthy() bool {
    return time.Since(b.created) < 30*time.Minute
}
```

---

### 2. Stealth Script Injection

**Package**: `brws/engine/stealth`

JavaScript patches to remove automation indicators.

```go
// brws/engine/stealth/scripts.go
package stealth

// Remove automation properties
const RemoveAutomationScript = `
(function() {
    // Remove navigator.webdriver
    Object.defineProperty(navigator, 'webdriver', {
        get: () => false,
        configurable: false,
        writable: false
    });
    
    // Remove CDP detection properties
    delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;
    delete window.$cdc_asdjflasutopfhvcZLmcfl_;
    delete window.__webdriver_evaluate;
    delete window.__selenium_evaluate;
    delete window.__fxdriver_evaluate;
    delete window.__driver_evaluate;
    
    // Remove Chrome runtime detection
    if (window.chrome) {
        window.chrome.runtime = undefined;
    }
    
    // Override permissions query for automation
    const originalQuery = window.navigator.permissions.query;
    window.navigator.permissions.query = (parameters) => (
        parameters.name === 'notifications' ?
            Promise.resolve({ state: Notification.permission }) :
            originalQuery(parameters)
    );
    
    // Override plugins
    Object.defineProperty(navigator, 'plugins', {
        get: () => [1, 2, 3, 4, 5],
        configurable: false
    });
    
    // Override languages
    Object.defineProperty(navigator, 'languages', {
        get: () => ['en-US', 'en'],
        configurable: false
    });
})();
`

// Canvas noise injection
const CanvasNoiseScript = `
(function() {
    const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function() {
        const data = originalGetImageData.apply(this, arguments);
        
        // Add noise to 2% of pixels
        for (let i = 0; i < data.data.length; i += 4) {
            if (Math.random() < 0.02) {
                data.data[i] = (data.data[i] + Math.floor(Math.random() * 3)) % 256;
                data.data[i+1] = (data.data[i+1] + Math.floor(Math.random() * 3)) % 256;
                data.data[i+2] = (data.data[i+2] + Math.floor(Math.random() * 3)) % 256;
            }
        }
        
        return data;
    };
})();
`

// WebGL spoofing
const WebGLSpoofScript = `
(function() {
    const originalGetParameter = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function(param) {
        // UNMASKED_VENDOR_WEBGL = 37445
        if (param === 37445) {
            return 'NVIDIA Corporation';
        }
        // UNMASKED_RENDERER_WEBGL = 37446
        if (param === 37446) {
            return 'NVIDIA GeForce RTX 3060/PCIe/SSE2';
        }
        return originalGetParameter.apply(this, arguments);
    };
})();
`

// Screen spoofing
const ScreenSpoofScript = `
(function() {
    Object.defineProperty(screen, 'width', { get: () => 1920 });
    Object.defineProperty(screen, 'height', { get: () => 1080 });
    Object.defineProperty(screen, 'availWidth', { get: () => 1920 });
    Object.defineProperty(screen, 'availHeight', { get: () => 1040 });
    Object.defineProperty(screen, 'colorDepth', { get: () => 24 });
    Object.defineProperty(screen, 'pixelDepth', { get: () => 24 });
    
    Object.defineProperty(window, 'innerWidth', { get: () => 1920 });
    Object.defineProperty(window, 'innerHeight', { get: () => 1080 });
    Object.defineProperty(window, 'outerWidth', { get: () => 1920 });
    Object.defineProperty(window, 'outerHeight', { get: () => 1120 });
    Object.defineProperty(window, 'devicePixelRatio', { get: () => 1 });
})();
`

// Client hints spoofing
const ClientHintsSpoofScript = `
(function() {
    Object.defineProperty(navigator, 'userAgentData', {
        get: () => ({
            brands: [
                { brand: 'Not(A:Brand', version: '8' },
                { brand: 'Chromium', version: '120' },
                { brand: 'Google Chrome', version: '120' }
            ],
            mobile: false,
            platform: 'Windows',
            getHighEntropyValues: (hints) => Promise.resolve({
                platform: 'Windows',
                platformVersion: '10.0.0',
                architecture: 'x86',
                bitness: '64',
                model: '',
                uaFullVersion: '120.0.6099.109'
            })
        })
    });
})();
`

// All scripts combined
func (c *Config) StealthScripts() []string {
    scripts := []string{RemoveAutomationScript}
    
    if c.CanvasNoise {
        scripts = append(scripts, CanvasNoiseScript)
    }
    if c.WebGLSpoof {
        scripts = append(scripts, WebGLSpoofScript)
    }
    if c.FakeScreen {
        scripts = append(scripts, ScreenSpoofScript)
    }
    if c.ClientHints {
        scripts = append(scripts, ClientHintsSpoofScript)
    }
    
    return scripts
}
```

---

### 3. TLS/HTTP Fingerprinting

**Package**: `brws/engine/spoof`

```go
// brws/engine/spoof/tls.go
package spoof

import "github.com/refraction-networking/utls"

// Browser signatures
var BrowserSpecs = map[string]*utls.ClientHelloSpec{
    "chrome120": {
        CipherSuites: []uint16{
            0x1301, 0x1302, 0x1303, // TLS 1.3
            0xc02b, 0xc02f, 0xc02c, 0xc030, // ECDHE
            0xcca9, 0xcca8, // CHACHA20
            0xc013, 0xc014, // RSA
            0x009c, 0x009d, 0x002f, 0x0035, // AES
        },
        Extensions: []utls.TLSExtension{
            &utls.SNIExtension{},
            &utls.UtlsSupportedVersionsExtension{
                Versions: []uint16{0x0304, 0x0303}, // TLS 1.3, 1.2
            },
            &utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
            &utls.SupportedGroupsExtension{SupportedGroups: []utls.CurveID{
                utls.X25519, utls.CurveP256, utls.CurveP384,
            }},
            // ... more extensions
        },
    },
}

// HTTP/2 pseudo-header order
var PseudoHeaderOrder = map[string][]string{
    "chrome":  {":method", ":authority", ":scheme", ":path"},
    "firefox": {":method", ":path", ":authority", ":scheme"},
    "safari":  {":method", ":scheme", ":path", ":authority"},
}

// HTTP headers by browser
var DefaultHeaders = map[string]map[string]string{
    "chrome": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Ch-Ua": `"Chromium";v="120", "Not(A:Brand";v="8", "Google Chrome";v="120"`,
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": `"Windows"`,
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    },
}
```

---

### 4. Behavioral Simulation

**Package**: `brws/engine/behavior`

```go
// brws/engine/behavior/typer.go
package behavior

type TyperConfig struct {
    MinDelay    time.Duration  // 30ms
    MaxDelay    time.Duration  // 150ms
    ErrorRate   float64       // 2%
    FixErrors   bool          // Correct mistakes
}

type Typer struct {
    cfg TyperConfig
}

func (t *Typer) Type(page interface {
    Type(selector, text string) error
    Press(key string) error
    Wait(d time.Duration) error
}, selector, text string) error {
    for i, char := range text {
        // Random error introduction
        if t.cfg.FixErrors && t.cfg.ErrorRate > 0 && rand.Float64() < t.cfg.ErrorRate {
            wrong := adjacentKeys[char][rand.Intn(len(adjacentKeys[char]))]
            page.Type(selector, string(wrong))
            page.Wait(200 * time.Millisecond)
            page.Press("Backspace")
        }
        
        // Type correct character
        page.Type(selector, string(char))
        
        // Variable delay
        delay := t.cfg.MinDelay + 
            time.Duration(rand.Int63n(int64(t.cfg.MaxDelay - t.cfg.MinDelay)))
        page.Wait(delay)
    }
    
    return nil
}

// Keyboard layout for typo simulation
var adjacentKeys = map[rune][]rune{
    'a': {'q', 'w', 's', 'z'},
    'e': {'r', 'w', 's', 'd'},
    'i': {'o', 'u', 'j', 'k'},
    // ... complete mapping
}
```

```go
// brws/engine/behavior/mouse.go
package behavior

type MouseConfig struct {
    MinSpeed    int  // 200 px/s
    MaxSpeed    int  // 1500 px/s
    AddJitter   bool // Add random noise
    PauseProb   float64 // Probability of pause
}

type Mouse struct {
    cfg MouseConfig
    x, y int
}

type Point struct {
    X, Y int
}

// Bezier curve mouse movement
func (m *Mouse) MoveTo(page interface {
    MouseMove(x, y int) error
    Wait(d time.Duration) error
}, targetX, targetY int) error {
    // Generate bezier path
    path := m.generateBezierPath(m.x, m.y, targetX, targetY)
    
    for _, p := range path {
        page.MouseMove(p.X, p.Y)
        page.Wait(16 * time.Millisecond) // ~60fps
        
        // Random pause
        if rand.Float64() < m.cfg.PauseProb {
            page.Wait(time.Duration(100+rand.Intn(400)) * time.Millisecond)
        }
    }
    
    m.x, m.y = targetX, targetY
    return nil
}

func (m *Mouse) generateBezierPath(x1, y1, x2, y2 int) []Point {
    // Generate smooth bezier curve with control points
    // ... implementation
}
```

```go
// brws/engine/behavior/scroll.go
package behavior

type ScrollConfig struct {
    MinAmount    int     // 100px
    MaxAmount    int     // 500px
    MinPause    int     // seconds
    MaxPause    int     // seconds
    BackscrollProb float64
}

func (s *Scroll) ScrollPage(page interface {
    Evaluate(js string) error
    Wait(d time.Duration) error
}) error {
    for {
        // Random scroll amount
        amount := s.cfg.MinAmount + rand.Intn(s.cfg.MaxAmount-s.cfg.MinAmount)
        
        // Execute scroll
        page.Evaluate(fmt.Sprintf("window.scrollBy(0, %d)", amount))
        
        // Random pause to "read"
        pause := time.Duration(s.cfg.MinPause+rand.Intn(s.cfg.MaxPause-s.cfg.MinPause)) * time.Second
        page.Wait(pause)
        
        // Occasional backscroll
        if rand.Float64() < s.cfg.BackscrollProb {
            page.Evaluate(fmt.Sprintf("window.scrollBy(0, -%d)", 50+rand.Intn(150)))
        }
        
        // Check if at bottom
        atBottom, _ := page.Evaluate("window.scrollY + window.innerHeight >= document.body.scrollHeight")
        if atBottom == true {
            break
        }
    }
    return nil
}
```

---

### 5. Challenge Detection & Solving

**Package**: `brws/challenge`

```go
// brws/challenge/detector.go
package challenge

type ChallengeType string

const (
    ChallengeRecaptchaV2 ChallengeType = "recaptcha-v2"
    ChallengeRecaptchaV3 ChallengeType = "recaptcha-v3"
    ChallengeHCaptcha   ChallengeType = "hcaptcha"
    ChallengeCloudflare ChallengeType = "cloudflare"
    ChallengeTurnstile  ChallengeType = "turnstile"
    ChallengeGeneric    ChallengeType = "generic"
)

type Detector struct{}

func (d *Detector) Detect(resp *http.Response, body []byte) ChallengeType {
    bodyStr := string(body)
    
    // reCAPTCHA v2
    if strings.Contains(bodyStr, "g-recaptcha") || 
       strings.Contains(bodyStr, "data-sitekey") {
        if strings.Contains(bodyStr, "g-recaptcha-response") {
            return ChallengeRecaptchaV2
        }
        return ChallengeRecaptchaV3
    }
    
    // hCaptcha
    if strings.Contains(bodyStr, "h-captcha") ||
       strings.Contains(bodyStr, "data-hcaptcha-sitekey") {
        return ChallengeHCaptcha
    }
    
    // Cloudflare
    if strings.Contains(resp.Header.Get("Server"), "cloudflare") {
        if strings.Contains(bodyStr, "challenge-platform") ||
           strings.Contains(bodyStr, "cf-challenge") {
            return ChallengeCloudflare
        }
        if strings.Contains(bodyStr, "cf-turnstile") {
            return ChallengeTurnstile
        }
    }
    
    return ""
}

// brws/challenge/solver.go
type Solver struct {
    capsolverAPIKey string
    twocaptchaAPIKey string
}

type SolverOption func(*Solver)

func WithCapSolver(apiKey string) SolverOption {
    return func(s *Solver) {
        s.capsolverAPIKey = apiKey
    }
}

func With2Captcha(apiKey string) SolverOption {
    return func(s *Solver) {
        s.twocaptchaAPIKey = apiKey
    }
}

func (s *Solver) Solve(ctx context.Context, page interface {
    Evaluate(js string) (interface{}, error)
    Wait(d time.Duration) error
}, challenge ChallengeType, siteKey, url string) (string, error) {
    switch challenge {
    case ChallengeRecaptchaV2, ChallengeRecaptchaV3:
        return s.solveRecaptcha(ctx, siteKey, url)
    case ChallengeHCaptcha:
        return s.solveHCaptcha(ctx, siteKey, url)
    case ChallengeTurnstile:
        return s.solveTurnstile(ctx, siteKey, url)
    }
    
    return "", fmt.Errorf("unsupported challenge type: %s", challenge)
}

func (s *Solver) solveRecaptcha(ctx context.Context, siteKey, url string) (string, error) {
    if s.capsolverAPIKey != "" {
        return s.solveWithCapSolver(ctx, "RecaptchaV2TaskProxyless", siteKey, url)
    }
    return "", fmt.Errorf("no CAPTCHA solver configured")
}

func (s *Solver) solveHCaptcha(ctx context.Context, siteKey, url string) (string, error) {
    // Similar implementation
    return "", nil
}

func (s *Solver) solveTurnstile(ctx context.Context, siteKey, url string) (string, error) {
    // Cloudflare Turnstile solving
    return "", nil
}
```

---

### 6. Session Management

**Package**: `brws/session`

```go
// brws/session/manager.go
package session

type Manager struct {
    dir  string
    mu   sync.RWMutex
    sessions map[string]*Session
}

type Session struct {
    ID          string
    Domain      string
    Created     time.Time
    LastUsed    time.Time
    RequestCount int
    
    // Browser state
    Cookies       []*http.Cookie
    LocalStorage  map[string]string
    UserAgent     string
    
    // Trust score (0-100)
    TrustScore float64
    
    // Metadata
    Fingerprint *spoof.Fingerprint
}

func NewManager(sessionDir string) *Manager {
    os.MkdirAll(sessionDir, 0755)
    return &Manager{
        dir:      sessionDir,
        sessions: make(map[string]*Session),
    }
}

func (m *Manager) Get(domain string) (*Session, error) {
    m.mu.RLock()
    if s, ok := m.sessions[domain]; ok && s.IsHealthy() {
        s.LastUsed = time.Now()
        s.RequestCount++
        m.mu.RUnlock()
        return s, nil
    }
    m.mu.RUnlock()
    
    // Try load from disk
    return m.loadFromDisk(domain)
}

func (m *Manager) Save(s *Session) error {
    m.mu.Lock()
    m.sessions[s.Domain] = s
    m.mu.Unlock()
    
    return m.saveToDisk(s)
}

func (s *Session) IsHealthy() bool {
    if time.Since(s.LastUsed) > 30*time.Minute {
        return false
    }
    if s.TrustScore < 20 {
        return false
    }
    return true
}

func (s *Session) DecreaseTrust(reason string) {
    penalties := map[string]float64{
        "blocked":    50,
        "captcha":    30,
        "challenge":  20,
        "timeout":    10,
    }
    
    if penalty, ok := penalties[reason]; ok {
        s.TrustScore = math.Max(0, s.TrustScore-penalty)
    }
}

func (s *Session) IncreaseTrust() {
    s.TrustScore = math.Min(100, s.TrustScore+5)
}
```

---

### 7. CLI Design

**Package**: `cmd/stealth`

```go
// cmd/stealth/main.go
package main

import (
    "github.com/skunkworq/stealth/cmd/stealth"
)

func main() {
    cli.Run()
}
```

```go
// internal/cli/cmd.go
package cli

import (
    "github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
    Use:   "stealth",
    Short: "Stealth browser for anti-bot evasion",
    Long:  `A browser automation tool with built-in evasion techniques.`,
}

func Run() error {
    return rootCmd.Execute()
}

func init() {
    rootCmd.AddCommand(browseCmd)
    rootCmd.AddCommand(sessionsCmd)
    rootCmd.AddCommand(versionCmd)
}
```

```go
// cmd/browse.go
var browseCmd = &cobra.Command{
    Use:   "browse <url>",
    Short: "Browse a URL with stealth",
    Args:  cobra.ExactArgs(1),
    RunE: func(cmd *cobra.Command, args []string) error {
        url := args[0]
        
        cfg := stealth.DefaultConfig()
        cfg.Headless = headless
        cfg.CanvasNoise = true
        cfg.WebGLSpoof = true
        
        engine, err := evasion.NewEngine(cfg)
        if err != nil {
            return err
        }
        
        resp, err := engine.Fetch(cmd.Context(), url)
        if err != nil {
            return err
        }
        
        fmt.Println(resp.Body)
        return nil
    },
}

var (
    headless     bool
    browser      string
    solveCaptcha bool
    sessionName  string
)

func init() {
    browseCmd.Flags().BoolVarP(&headless, "headless", "", false, "Run in headless mode")
    browseCmd.Flags().StringVarP(&browser, "browser", "b", "chrome120", "Browser fingerprint (chrome120, firefox121, safari16)")
    browseCmd.Flags().BoolVarP(&solveCaptcha, "solve-captcha", "c", false, "Automatically solve CAPTCHAs")
    browseCmd.Flags().StringVarP(&sessionName, "session", "s", "", "Session name to save/reuse")
}
```

```bash
# CLI Usage Examples

# Basic stealth browsing
stealth browse https://example.com

# Headless mode
stealth browse --headless https://example.com

# With specific browser fingerprint
stealth browse --browser chrome120 https://example.com

# With CAPTCHA solving
stealth browse --solve-captcha https://example.com

# Save session
stealth browse --session mysite https://example.com

# Reuse session
stealth browse --session mysite https://other-page.com

# Interactive REPL
stealth repl
```

---

## Data Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Request Flow                                    │
└─────────────────────────────────────────────────────────────────────────┘

  1. CLI Parse
     └─> Extract URL, flags, session name

  2. Session Manager
     ├─> Load existing session if specified
     └─> Create new session with trust score

  3. Browser Pool
     ├─> Get browser from pool (or create new)
     └─> Inject stealth scripts

  4. TLS/HTTP Spoofing
     ├─> Apply browser fingerprint
     ├─> Set headers
     └─> Configure HTTP/2 settings

  5. Behavioral Setup
     ├─> Apply mouse/typing config
     └─> Set timing patterns

  6. Navigate
     └─> page.Navigate(url)

  7. Challenge Detection
     ├─> Check response for challenges
     └─> If detected → Solve → Retry

  8. Response
     ├─> Extract content
     ├─> Update session (cookies, storage)
     └─> Return to caller

  9. Session Update
     ├─> Increase trust if successful
     ├─> Decrease trust if blocked
     └─> Save to disk
```

---

## Configuration

### Default Configuration

```yaml
# config.yaml
browser:
  headless: false
  window_size:
    width: 1920
    height: 1080
  language: en-US

stealth:
  remove_webdriver: true
  canvas_noise: true
  webgl_spoof: true
  client_hints: true
  fake_screen: true
  fake_timezone: false

behavior:
  typing:
    min_delay_ms: 30
    max_delay_ms: 150
    error_rate: 0.02
    fix_errors: true
  mouse:
    min_speed: 200
    max_speed: 1500
    add_jitter: true
    pause_probability: 0.15
  scroll:
    min_amount: 100
    max_amount: 500
    pause_seconds: [1, 5]
    backscroll_probability: 0.1

fingerprint:
  browser: chrome120
  platform: windows
  headers: default

challenge:
  auto_solve: false
  solver: capsolver  # or twocaptcha
  # api_key: provided via environment

session:
  dir: ./sessions
  ttl_minutes: 30
  trust_threshold: 20

proxy:
  enabled: false
  # Residential proxy configuration (Phase 2)
```

---

## File Structure

```
stealth/
├── cmd/
│   └── stealth/
│       └── main.go
├── internal/
│   ├── cli/
│   │   ├── cmd.go
│   │   ├── browse.go
│   │   ├── repl.go
│   │   └── sessions.go
│   └── config/
│       └── config.go
├── brws/
│   ├── engine/
│   │   ├── browser.go
│   │   ├── pool.go
│   │   └── chromedp.go
│   ├── stealth/
│   │   ├── config.go
│   │   ├── args.go
│   │   ├── scripts.go
│   │   └── pool.go
│   ├── spoof/
│   │   ├── tls.go
│   │   ├── http2.go
│   │   └── headers.go
│   ├── behavior/
│   │   ├── typer.go
│   │   ├── mouse.go
│   │   └── scroll.go
│   └── session/
│       └── manager.go
├── challenge/
│   ├── detector.go
│   ├── solver.go
│   └── captcha.go
└── pkg/
    ├── types/
    │   └── types.go
    └── utils/
        └── utils.go
```

---

## Implementation Phases

### Phase 1: Browser Stealth (Week 1-2)
- [x] Chrome launch arguments
- [x] CDP-based control
- [x] Automation property removal
- [x] Canvas noise injection
- [x] WebGL spoofing

### Phase 2: TLS/HTTP Fingerprinting (Week 2-3)
- [x] uTLS integration
- [x] HTTP/2 pseudo-header ordering
- [x] Client Hints spoofing
- [x] Header order matching

### Phase 3: Behavioral Simulation (Week 3-4)
- [x] Bezier curve mouse movement
- [x] Human typing with errors
- [x] Realistic scrolling
- [ ] Session warming patterns

### Phase 4: Challenge Handling (Week 4-5)
- [x] Challenge detection
- [x] CapSolver integration
- [ ] Session cookie extraction
- [ ] Turnstile solving

### Phase 5: Session Management (Week 5-6)
- [x] Cookie persistence
- [x] Trust scoring
- [x] Automatic retry logic

### Phase 6: CLI (Week 6-7)
- [x] Basic browse command
- [x] Session management
- [x] Interactive REPL

---

## Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Basic site success | >90% | Unprotected sites |
| Protected site success | >70% | Cloudflare, simple anti-bot |
| Challenge success | >80% | With auto-solve enabled |
| Session reuse | >50% | Cookies valid after 30min |
| Response time | <5s | Page load + extraction |

---

## Dependencies

```go
require (
    github.com/chromedp/chromedp v0.9.5
    github.com/chromedp/cdproto v0.0.0-20231109015234-5c3d0f20c1a7
    github.com/refraction-networking/utls v1.3.2
    github.com/spf13/cobra v1.8.0
    github.com/spf13/viper v1.18.2
    github.com/cenkalti/hputils v0.0.0-20230819084404-7e2d5a6
)
```

---

## References

- [nodriver](https://github.com/UltrafunkAmsterdam/nodriver)
- [ZenRows](https://www.zenrows.com)
- [chromedp](https://github.com/chromedp/chromedp)
- [uTLS](https://github.com/refraction-networking/utls)
- [puppeteer-extra-plugin-stealth](https://github.com/berstend/puppeteer-extra/tree/master/packages/puppeteer-extra-plugin-stealth)
