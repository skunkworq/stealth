# `brws` — Browser Automation Stack (Deep Dive)

> Complete architectural reference for the `brws/` Go library. Covers every layer, every public interface, the data flow between components, and the full agent action reference.

---

## Table of Contents

1. [Philosophy & Layer Architecture](#1-philosophy--layer-architecture)
2. [Layer 1 — Engine](#2-layer-1--engine)
3. [Layer 2 — Stealth](#3-layer-2--stealth)
4. [Layer 3 — Content / Agent (Agent Loop)](#4-layer-3--content--agent-agent-loop)
5. [Layer 3 — Content / Scrapegraph (Graph Execution)](#5-layer-3--content--scrapegraph-graph-execution)
6. [Layer 4 — Crawl](#6-layer-4--crawl)
7. [Data Flow Diagrams](#7-data-flow-diagrams)
8. [Complete Agent Action Reference](#8-complete-agent-action-reference)
9. [Configuration & Wiring](#9-configuration--wiring)

---

## 1. Philosophy & Layer Architecture

`brws` is a layered Go library for **stealth browser automation**, **AI-driven web agents**, and **large-scale crawling**. Packages are organized into four dependency layers; nothing in a lower layer imports from a higher one.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Layer 4 — Scale          crawl/         ml/           fingerprint/         │
├─────────────────────────────────────────────────────────────────────────────┤
│  Layer 3 — Content        content/agent   content/scrapegraph               │
│                           content/understand   content/extract              │
├─────────────────────────────────────────────────────────────────────────────┤
│  Layer 2 — Stealth        stealth/                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│  Layer 1 — Engine         browser/engine/   network/                        │
├─────────────────────────────────────────────────────────────────────────────┤
│  Cross-cutting            core/                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Design principles:**
- **Interface-first:** Every layer depends on interfaces, not concrete types.
- **Swappable backends:** The same agent code runs against Chromium, Firefox, WebKit, or raw HTTP.
- **No double-navigation:** The stealth client and agent share the same browser tab. Challenge solving happens *on* the agent's tab, not in a throwaway tab that gets discarded.
- **Token-aware:** The formatter compresses page state so LLM prompts stay within token budgets.

---

## 2. Layer 1 — Engine

The engine layer is the lowest abstraction over a browser or HTTP client. It knows nothing about stealth, agents, or LLMs.

### 2.1 Core Interface (`brws/browser/engine/engine.go`)

```go
type Engine interface {
    Name() string
    Capabilities() Capabilities
    Do(ctx context.Context, req *Request) (*Response, error)
    Close() error
}
```

**`Request`** — Unified HTTP request with browser knobs:
- `Method`, `URL`, `Headers`, `Body`
- `WaitForNavigation`, `WaitForSelector`, `ScriptToExecute`
- `Viewport`, `UserAgent`, `ExtraHeaders`, `Referrer`
- `SessionID`, `FingerprintID` — links to a cached identity profile

**`Response`** — Unified response:
- `Status`, `Headers`, `Body`, `FinalURL`, `Protocol`
- `Trace` — HAR-like network trace entries
- `Timing` — DNS, connect, SSL, send, wait, receive durations

**Optional extensions:**
- `InteractiveEngine` — adds `Mouse(x, y)`, `Click(x, y)`, `Type(text)`, `Scroll(pixels)`, `ScrollTo(y)` for human-like interaction.
- `TabEngine` — adds `DoOnTab(ctx, tabCtx, req)` for executing a request on an *existing* browser tab instead of creating a fresh one per request.

**Registry pattern:**
Engines register themselves in `init()` via `engine.Register(name, constructor)`. Callers create engines by name:
```go
eng, _ := engine.New("chromium-stealth", engine.Options{Headless: false})
```

Registered engines: `"native"`, `"chromium"`, `"chromium-stealth"`, `"firefox"`, `"webkit"`.

### 2.2 Chromium Stealth Engine (`brws/stealth/chromium/engine.go`)

This is the primary production engine. It implements `Engine`, `InteractiveEngine`, and `TabEngine`. It is registered under the name `"chromium-stealth"`.

**`NewStealth(opts engine.Options) (engine.Engine, error)`**
Creates a `StealthEngine` from generic `engine.Options`. It launches a Chrome process via `chromedp.ExecAllocator` configured with anti-detection flags (disabling `AutomationControlled`, using ANGLE GPU instead of SwiftShader, random viewport jitter, disabling default apps/extensions). The returned engine can be used immediately.

**`NewStealthWithFingerprint(opts engine.Options, fp *types.CompleteFingerprint) (engine.Engine, error)`**
Same as `NewStealth`, but locks the engine to a specific captured browser identity.

A `CompleteFingerprint` is a multi-layer snapshot of a real browser's signature, collected by the `fingerprint/` tooling. It contains:
- **TLS layer** — exact ClientHello: cipher suite order, extension order, GREASE positions, JA3/JA4 hashes, ALPN, key share groups
- **HTTP layer** — header order, header values, accept patterns, accept-language, accept-encoding
- **HTTP/2 layer** — settings frame order, window update timing, pseudo-header order, frame sequence
- **Behavior layer** — mouse velocity distributions, scroll momentum curves, typing inter-keystroke timing

When you create an engine with `NewStealthWithFingerprint`, all of these signals are frozen for the lifetime of the engine:
- The TLS stack is configured to replay the exact same ClientHello (same JA3 hash on every connection)
- The HTTP header order is locked to the fingerprint's sequence
- The viewport size and User-Agent are locked
- Behavior simulators use the fingerprint's timing distributions instead of generic defaults

**Why this matters:** Bot detectors correlate signals across layers. If one request presents a TLS fingerprint that says "Chrome 120" but sends HTTP headers in an order typical of Firefox, or if the JA3 hash changes between requests, that mismatch is a ban signal. Fingerprint-bound construction eliminates these mismatches by ensuring every layer of every request presents the *same* consistent identity.

**`Do(ctx context.Context, req *engine.Request) (*engine.Response, error)`**
Implements `engine.Engine`. Creates a fresh chromedp tab, calls `DoOnTab()` on it, then closes the tab. This is the "one-shot" path: each request gets a clean tab.

**`DoOnTab(ctx context.Context, tabCtx context.Context, req *engine.Request) (*engine.Response, error)`**
Implements `engine.TabEngine`. This is the workhorse. It operates on an existing tab (provided by `tabCtx`) rather than creating a new one:
1. Enables CDP network and page domains on the tab.
2. Injects the stealth script via `page.AddScriptToEvaluateOnNewDocument`.
3. Sets extra HTTP headers from the fingerprint profile.
4. Starts a network event listener to populate `engine.Trace` entries.
5. Navigates to `req.URL` (with `Referrer` injection when `StealthPlus` is enabled).
6. Waits for body, optionally executes `req.ScriptToExecute`.
7. Captures `outerHTML` and returns an `engine.Response`.

This method is what makes the "no double-navigation" pattern possible: the stealth layer and the agent layer share the same tab.

**`Mouse(x, y float64) error` / `Click(x, y float64) error` / `Type(text string) error` / `Scroll(pixels float64) error` / `ScrollTo(y float64) error`**
Implement `engine.InteractiveEngine`. These dispatch CDP mouse/keyboard/scroll events directly. When `SimulateBehavior` is enabled, the engine first runs JS simulators (`MouseSimulator`, `TypingSimulator`, `ScrollSimulator`) that dispatch human-like event sequences in the page, then follows up with the reliable CDP action.

**`Close() error`**
Shuts down the Chrome process and cancels the allocator context.

**`SetStealthConfig(cfg *StealthConfig)` / `SetStealthOptions(opts StealthOptions)`**
Runtime mutators for stealth behavior. `StealthConfig` controls script injection (canvas noise, WebGL spoof, client hints, IP spoofing). `StealthOptions` controls runtime pacing (pre/post-navigation delays, gesture injection).

**`Allocator() context.Context`**
Returns the root `chromedp` allocator context. Callers can spawn their own tab contexts from it.

**`NewTab() (context.Context, context.CancelFunc)`**
Convenience wrapper that spawns a new tab context from the allocator. The caller is responsible for calling the cancel func.

### 2.3 Waterfall Engine (`brws/browser/engine/meta/waterfall/`)

Races multiple engines in tiers. Implements `engine.Engine`.

- Tier 0 fires immediately; deferred tiers launch after a `LaunchAfter` delay.
- First successful response wins; remaining tiers are cancelled.
- `PromoteTier(name)` moves a tier to index 0 at runtime (used by anti-bot escalation when a ban signal forces a heavier engine).

---

## 3. Layer 2 — Stealth

The stealth layer wraps an engine (or waterfall) and adds all anti-bot, challenge-solving, and escalation logic. Most callers only need to import this package.

### 3.1 `stealth.Adaptive` (`brws/stealth/client.go`)

The primary API surface:

```go
client, _ := stealth.NewAdaptive(
    stealth.WithHeadless(false),
    stealth.WithProxy("http://proxy:8080"),
    stealth.WithChallengeSolver("capsolver", "KEY"),
    stealth.WithEscalation(stealth.DefaultEscalationConfig()),
)
resp, _ := client.Navigate(ctx, "https://example.com")
```

**`Config` fields:**
- `EngineName`, `Headless`, `Proxy`, `PolicyModelPath`
- `Stealth *chromium.StealthConfig` — canvas noise, WebGL spoof, client hints, etc.
- `Challenge *ChallengeConfig` — auto-detect, auto-solve, solver API key, max retries
- `Session *SessionConfig` — profile dir, session name, lifetime
- `Escalation *EscalationConfig` — anti-bot escalation rules
- `WaterfallEngine`, `TieredProxies`, `EvasionFSMDisabled`

**Construction flow (`NewAdaptiveWithConfig`):**
1. Creates instrumentation (logger, tracer, hooks, FSM).
2. Instantiates the engine via `engine.New()`.
3. Initializes session manager, RL policy loader (if path given), captcha solver, Cloudflare solver.
4. Creates the `ChallengeOrchestrator` with registered FSM solvers.
5. Sets up waterfall, tier tracker, escalation config, and evasion FSM (lazy).

### 3.2 `navigate()` — The Hot Path

This is the core request lifecycle, shared by `Navigate()` and `NavigateOnTab()`:

```
1. Lazy FSM init
   → behavior.NewAdaptiveEvasionFSMForURL(url) on first request

2. Hook/FSM start
   → OnRequestStart hook, FSM Idle → Start transition

3. Engine selection
   → activeEngine() returns waterfall if configured, else raw engine

4. Request dispatch
   → If tabCtx != nil: engine.TabEngine.DoOnTab()
   → Else: engine.Engine.Do()

5. WAF retry loop (max 3)
   → isWAFResponse() uses instrumentation.DetectChallenge()
   → On WAF hit: RL policy selects action OR hardcoded stealth tweaks
   → Increasing backoff sleep between retries

6. Evasion FSM ban-signal handling
   → isBanSignal() detects 401/403/429 + challenge markers
   → Records result, FSM rotates strategy
   → If FSM.ShouldEscalate() and waterfall exists: promotes "chromium" tier

7. Anti-bot escalation
   → escalate() records ban, rotates proxy tier, promotes waterfall tier

8. Captcha solving
   → attemptCaptchaSolve() uses trace-replay when available
   → Falls back to orchestrator

9. Challenge orchestrator (catch-all)
   → orchestrator.HandleResponse() delegates to FSM solvers
   → Cloudflare → Captcha → DataDome → Dynamic (priority order)

10. Return
   → Wraps engine.Response into stealth.Response with ChallengeSolved flag
```

**Key design win — no double-navigation:**
- `Agent.NewStealthTab()` creates a tab from the stealth browser and calls `NavigateOnTab()`.
- `Executor.execNavigate()` also calls `NavigateOnTab()` when a `StealthClient` is wired in.
- `navigate()` sees `tabCtx != nil` and uses `DoOnTab()` instead of `Do()`.
- The stealth engine applies scripts, headers, and permissions directly on the provided tab.
- This eliminates the old pattern: temp-tab solve → agent tab re-navigate.

### 3.3 Escalation (`brws/stealth/escalation.go`)

- **`EscalationConfig`** — `Enabled`, `MaxEscalationRetries`, `PromoteOnStatus` (default `[401, 403, 429]`).
- **`escalate()`** — Records ban signal on session health, escalates proxy tier via `TierTracker`, promotes waterfall tier, checks if session is blocked.

### 3.4 Challenge Solving

**`CloudflareSolverClient`** (`brws/stealth/cloudflare_solver.go`):
- Solves JS challenges, managed challenges, and Turnstile flows.
- Uses a pinned fingerprint/profile for session consistency.
- Generates human-like pointer traces with jitter, arc paths, and easing.

**`ChallengeOrchestrator`** (`brws/stealth/challenge/fsm/`):
- Routes detected challenges to registered solvers.
- Priority-ordered solvers: CloudflareFSMSolver → CaptchaFSMSolver → DataDomeFSMSolver → DynamicFSMSolver.
- Each solver implements a state-machine approach with retry logic.

---

## 4. Layer 3 — Content / Interact (Agent Loop)

This is the **AI-driven agent framework**. It implements an observe → decide → execute loop over a live browser tab.

### 4.1 Core Types (`brws/content/agent/types.go`)

**`PageSnapshot`** — Everything observable about a page:
```go
type PageSnapshot struct {
    URL          string
    Title        string
    Viewport     Viewport
    Scroll       ScrollState
    DocumentSize DocumentSize
    Elements     []VisibleElement
    Forms        []understand.FormSchema
    Links        []Link
    History      HistoryState
    Tabs         []TabState
    ChallengeDetected bool
    ChallengeType     string
    Meta         *understand.PageMeta
    Images       []understand.ImageRef
    SemanticTree *understand.SemanticTree
}
```

**`VisibleElement`** — One interactive element:
```go
type VisibleElement struct {
    ID            string
    Selector      string
    Tag           string
    Text          string
    Bounds        BoundingBox
    IsVisible     bool
    IsInteractive bool
    ActionTypes   []ActionType
    Attrs         map[string]string
}
```

**`ActionType`** — 21 action types:
```
click, type, select, toggle,
scroll_down, scroll_up, scroll_bottom, scroll_top, scroll_to,
navigate, back, forward, reload,
wait, screenshot,
hover, focus, key_press, clear_input,
wait_for_selector, wait_for_navigation,
new_tab, switch_tab, close_tab,
solve_challenge, done
```

**`Action`** — One possible action the LLM can choose:
```go
type Action struct {
    ID           string
    Type         ActionType
    Description  string
    TargetID     string
    Parameters   map[string]interface{}
    IsLink       bool
    IsFormSubmit bool
}
```

**`ActionSpace`** — Complete set of available actions, grouped by category:
- `ElementActions` — click, type, select, toggle, hover, focus, clear_input
- `ScrollActions` — scroll_down, scroll_up, scroll_bottom, scroll_top, scroll_to
- `NavActions` — back, forward, reload, navigate
- `TabActions` — new_tab, switch_tab, close_tab
- `OtherActions` — wait, screenshot, key_press, wait_for_selector, wait_for_navigation, done

**`Context`** — Bundles snapshot + action space:
```go
type Context struct {
    Snapshot            *PageSnapshot
    ActionSpace         *ActionSpace
    SemanticActionSpace *ActionSpace
    Representation      Representation // "dom" or "semantic"
}
```

### 4.2 Observer (`brws/content/agent/observer.go`)

**`Observer.Observe(ctx)`** captures a `PageSnapshot` via CDP in 10 steps:

1. `chromedp.Location` + `chromedp.Title`
2. `page.GetLayoutMetrics()` → viewport and document size
3. JS evaluation → scroll position, document height
4. `page.GetNavigationHistory()` → back/forward state with actual URLs
5. `target.GetTargets()` → all open tabs
6. **`queryInteractiveElements()`** — multi-pass JS query:
   - Pass 1: semantic tags (`a`, `button`, `input`, `textarea`, `select`, `[role="button"]`, `[onclick]`)
   - Pass 2: focusable elements (`[tabindex]`, `[contenteditable]`)
   - Pass 3: elements with `cursor: pointer` (catches clickable divs/spans)
   - Pass 4: framework attributes (`jsaction*="click"`, `ng-click`, `data-click`)
   - Computes bounding boxes, builds CSS selectors, infers `ActionTypes`
7. `queryLinks()` — all `a[href]`, deduplicated
8. `OuterHTML("html")` → form extraction via `understand.ExtractFormSchemas()`
9. `detectPageChallenge()` — scans HTML for WAF markers (Cloudflare, DataDome, Imperva, reCAPTCHA, hCaptcha, PerimeterX, Akamai)
10. Optional semantic enrichment via `SemanticEnhancer`

### 4.3 Action Space Builder (`brws/content/agent/actionspace.go`)

**`BuildActionSpace(snap)`** enumerates all possible actions from a snapshot:

- **Element actions** — For each `VisibleElement` + `ActionType` combo:
  - `click` → "Click 'text' (tag)"
  - `type` → "Type into 'placeholder' (tag)" with `field_type` and `name` parameters
  - `select` → "Select option in 'text' (tag)"
  - `toggle` → "Toggle 'text' (tag)"
  - `hover` → "Hover over 'text' (tag)"
  - `focus` → "Focus 'text' (tag)"
  - `clear_input` → "Clear input 'text' (tag)"
- **Scroll actions** — Offered based on current scroll position:
  - `scroll_down` (50% viewport) and `scroll_down_large` (100% viewport) if not at bottom
  - `scroll_up` (50% viewport) if not at top
  - `scroll_bottom` and `scroll_top`
  - `scroll_to_<id>` for each off-screen element
- **Nav actions** — `nav_back` (with actual previous URL), `nav_forward`, `nav_reload`, `navigate`
- **Tab actions** — `switch_tab_<idx>`, `close_tab_<idx>`, `new_tab`
- **Other actions** — `wait`, `screenshot`, `key_press`, `wait_for_selector`, `wait_for_navigation`, `done`
- **Challenge action** — `solve_challenge` only when `snap.ChallengeDetected` is true

**`BuildSemanticActionSpace(snap)`** derives actions from a `SemanticTree` instead of raw DOM. Produces a smaller action space (~40% fewer tokens) suitable for LLM navigation.

### 4.4 Formatter (`brws/content/agent/formatter.go`)

Converts `Context` into an LLM-friendly prompt string.

**`FormatCompact(ctx)`** (default for agent loops):
```
PAGE https://example.com | "Example Domain" | vp=1920x1080 | scroll=0/5000(0%)
HISTORY: back=https://prev.com | forward=
TABS: [1] Example Domain (active)
[E1] <a> → click,hover,focus | "Click here"
[E2] <input> → type,focus,clear_input | "Search"
SCROLL: scroll_down scroll_down_large scroll_bottom
NAV: nav_back nav_reload navigate
TABS: switch_tab_2 close_tab_2 new_tab
OTHER: wait screenshot key_press wait_for_selector wait_for_navigation done
```

**`Format(ctx)`** — Full markdown-like structured prompt with sections for elements, scroll, nav, tabs, forms, links, meta, images, and semantic tree.

**`FormatSemanticCompact(ctx)`** — Uses the semantic tree representation instead of raw DOM elements. Typically 30–40% fewer tokens.

### 4.5 Executor (`brws/content/agent/executor.go`)

Runs agent-chosen actions against a live chromedp tab.

```go
type Executor struct {
    EngineCtx        context.Context      // chromedp allocator context
    StealthClient    *stealth.Adaptive      // challenge-aware navigation
    SimulateBehavior bool                 // human-like mouse/typing/scroll
    BehaviorDelay    time.Duration        // base delay for simulators
}
```

**`Execute(ctx, action) (*ExecuteResult, error)`** — Big switch on `action.Type`:

| Action | Implementation |
|---|---|
| `click` | `chromedp.Click(selector, NodeVisible)` or `chromedp.MouseClickXY(x, y)`. With `SimulateBehavior`: resolves element center, runs JS Bézier mousemove, then CDP click. |
| `type` | `chromedp.SendKeys(selector, text, NodeVisible)`. With `SimulateBehavior`: focus, then char-by-char typing with random `CharDelay()` and 5% typo-correction rate. |
| `select` | JS: `el.value = ...; el.dispatchEvent(new Event('change', {bubbles: true}))` |
| `toggle` | `chromedp.Click(selector, NodeVisible)` |
| `scroll_down/up` | `window.scrollBy(0, ±amount)`. With `SimulateBehavior`: JS scroll simulator with easing. |
| `scroll_bottom/top` | `window.scrollTo(0, document.body.scrollHeight)` / `window.scrollTo(0, 0)` |
| `scroll_to` | `el.scrollIntoView({behavior: 'smooth', block: 'center'})` or `window.scrollTo(0, y)` |
| `navigate` | If `StealthClient` set: `stealthClient.NavigateOnTab(ctx, ctx, url)` — no double-navigation. Otherwise: `chromedp.Navigate(url)`. |
| `back` / `forward` | `chromedp.NavigateBack()` / `chromedp.NavigateForward()` |
| `reload` | `chromedp.Reload()` |
| `wait` | `chromedp.Sleep(ms)` (default 1000ms, configurable via `ms` or `duration` param) |
| `screenshot` | `chromedp.CaptureScreenshot(&buf)` — currently captures to buffer; path param parsed but not persisted yet. |
| `hover` | JS resolves element center via `getBoundingClientRect()`, then `chromedp.MouseEvent(MouseMoved, x, y)` to trigger CSS `:hover`. |
| `focus` | `chromedp.Focus(selector, NodeVisible)` |
| `key_press` | If `selector` given: focus + `chromedp.SendKeys`. If global: `input.DispatchKeyEvent(KeyDown)`. Friendly names mapped: `Enter`→`\r`, `Escape`→`\u001b`, `Tab`→`\t`, `Backspace`→`\b`, `Space`→` `. |
| `clear_input` | JS: `el.value = ''` + dispatches `input` and `change` events. |
| `wait_for_selector` | `chromedp.WaitVisible(selector)` with `context.WithTimeout` (default 5000ms). Returns clear timeout error if element never appears. |
| `wait_for_navigation` | Polls `chromedp.Location` every 100ms with `context.WithTimeout` until URL changes from pre-action URL. |
| `new_tab` | `target.CreateTarget(url)` |
| `switch_tab` | `target.ActivateTarget(target_id)` |
| `close_tab` | `target.CloseTarget(target_id)` |
| `solve_challenge` | Calls `StealthClient.NavigateOnTab()` to re-navigate current URL with challenge solving enabled. Returns `ChallengeSolved`. |
| `done` | No-op. Signals task completion. |

**`ExecuteResult`** — What happened:
```go
type ExecuteResult struct {
    ActionID        string
    Success         bool
    Error           string
    NewURL          string
    ScrollDelta     float64
    ChallengeSolved bool
    NoChange        bool // true if scroll moved 0px or nav landed on same URL
}
```

**`ExecutePlan(ctx, actions)`** — Runs a sequence of actions with 200ms settle between each.

### 4.6 Agent Orchestrator (`brws/content/agent/agent.go`)

Ties together Observer, Formatter, and Executor into the observe-decide-execute loop.

```go
type Agent struct {
    cfg       Config
    observer  *Observer
    formatter *Formatter
    executor  *Executor
    history   []Step
    lastCtx   *Context
    lastSpace []Action
}
```

**`Config`**:
- `MaxRetries`, `SettleDelay` (500ms), `ActionTimeout` (30s), `HistorySize` (50)
- `StealthClient *stealth.Adaptive` — when set, agent creates tabs from stealth browser
- `Representation` — `RepresentationDOM` (default) or `RepresentationSemantic`
- `SimulateBehavior`, `BehaviorDelay`

**`Observe(ctx)`**:
1. `observer.Observe()` → `*PageSnapshot`
2. `NewContext(snap)` → builds DOM action space
3. If semantic mode, also builds `SemanticActionSpace`
4. Selects active space based on `cfg.Representation`
5. Formats via `FormatCompact()` or `FormatSemanticCompact()`
6. Returns `(Context, []Action, formattedString, error)`

**`Execute(ctx, action)`**:
1. Creates timeout context (`ActionTimeout`)
2. `executor.Execute()`
3. Records `Step` in history (capped at `HistorySize`)
4. Sleep `SettleDelay`

**`Step(ctx, decideFn)`** — One full cycle:
1. `Observe()` → page context, action space, formatted prompt
2. Log challenge detection if stealth client present
3. Call `decideFn(pageCtx, actionSpace, formatted, history)` → `Action`
4. `Execute()` → `ExecuteResult`
5. Log challenge solved if applicable
6. Return `Step` record

**`NewStealthTab(ctx, url)`**:
1. Creates persistent tab from stealth browser
2. Navigates with `NavigateOnTab()`
3. Wires stealth client into executor

**Built-in decision functions (`Decisions`):**
- `ClickFirstLink` — finds first `click` action where `IsLink` is true
- `ScrollThenClick` — scrolls down, then clicks first link
- `ScrollToBottom` — scrolls to bottom
- `SubmitFirstForm` — fills first input/select, then clicks submit

### 4.7 LLM Bridge (`brws/content/agent/llm.go`)

**`LLMDecideFn(ctx, llm, systemPrompt)`** — Returns a `decideFn` for `Agent.Step()`:
- Builds prompt with current page, available actions, and last 3 steps
- Calls `llm.Complete()` and parses reply
- **`parseActionReply()`** handles formats: `click_E1`, `[click_E1]`, `type_E3: hello world`, `navigate: https://...`, `done`

---

## 5. Layer 3 — Content / Pipeline (Graph Execution)

A **ScrapeGraphAI-inspired** directed-graph execution engine for LLM-centric scraping. Operates independently from the agent loop.

### 5.1 Core Graph Engine (`brws/content/scrapegraph/engine.go`)

```go
type Node interface {
    Name() string
    NodeType() string // "node" or "conditional_node"
    InputExpr() string
    Outputs() []string
    MinInputs() int
    Execute(ctx, state) (State, string, error)
}
```

- **`State`** — `map[string]interface{}` shared mutable dictionary flowing through the graph.
- **`BaseGraph`** — Drives nodes in a loop, routes via edges, handles conditional branching.
- **`ParseInputKeys(state, expression)`** — Evaluates boolean expressions against state keys (`&`, `|`, parentheses).

### 5.2 Core Nodes

**`FetchNode`** — Ingests from URLs or local files:
- If `StealthClient` set, uses it for challenge-aware fetching.
- Returns `[]Document`.
- Promotes challenge metadata to graph state.

**`ParseNode`** — HTML → text cleanup:
- Token-aware chunking (`splitText` with sentence/word boundary preference).
- Optionally extracts URLs.

**`ExtractorNode`** — Drop-in replacement for `ParseNode + GenerateAnswerNode`:
- Delegates to `content/extract.Extract()` — handles chunking, schema validation, and multi-provider extraction internally.
- No LLM parameter required at the graph level; configure via `extract.Option` values.
- Best when fidelity or schema conformance matters more than latency.

**`GenerateAnswerNode`** — Extracts structured answers from content:
- Single chunk: direct extraction
- Multi-chunk: MapReduce with 4 concurrent goroutines → merge step
- Prompts: `promptSingleChunk`, `promptChunk`, `promptMerge`

**`ReasoningNode`** — Pre-processes user prompt against schema to produce extraction strategy.

**`MergeAnswersNode`** — Synthesizes multiple partial answers into one coherent result.

**`SearchInternetNode`** — Generates search query via LLM, scrapes DuckDuckGo HTML for URLs.

**`ConditionalNode`** — Branches execution based on runtime condition evaluated against state map.

### 5.3 Pre-built Graphs

**`SmartScraperGraph`** — Flagship scraper:
```
Fetch → Parse → GenerateAnswer
```
- Optional: `reasoning` node, `reattempt` conditional + regen node
- 8 strategy combinations based on `html_mode`, `reasoning`, `reattempt` flags
- `NewSmartScraperGraphWithStealth()` injects stealth client into `FetchNode`
- `NewSmartScraperGraphWithExtractor(prompt, source, config, opts...)` — uses `Fetch → ExtractorNode` instead; no LLM param, configured via `extract.Option` values

**`SearchGraph`** — Autonomous web search:
```
SearchInternet → GraphIterator → MergeAnswers
```
- `GraphIteratorNode` runs `SmartScraperGraph` for each URL
- Semaphore-controlled concurrency (default batch 4)

### 5.4 Search Coordinator (`brws/content/scrapegraph/search.go`)

**`SearchCoordinator`** — Goal-directed observe-decide-execute loop for search tasks:

```go
type SearchCoordinator struct {
    cfg SearchConfig
    llm LLM
    ag  *agent.Agent
}
```

**`Run()` lifecycle:**
1. Creates stealth tab via `Agent.NewStealthTab()`
2. Builds `decideFn` that calls LLM with search-specific system prompt
3. Runs `Agent.Step()` in a loop up to `MaxSteps` (default 20)
4. LLM returns JSON `decideResponse` with `action_id`, `text`, `url`, `reason`
5. `resolveAction()` injects `selector` from snapshot into action parameters
6. After loop, `extractResults()` sends final page state to LLM for structured extraction
7. Returns `*SearchResult` with `[]ResultItem` (Title, URL, Snippet, Price)

---

## 6. Layer 4 — Crawl

### 6.1 Spider Framework (`brws/crawl/spider/`)

Scrapy-inspired high-throughput crawler.

```
Scheduler → Downloader → Spider → ItemPipeline
                ↑              ↓
           Middleware       ItemMiddleware
```

**`Spider` interface:**
```go
type Spider interface {
    Name() string
    Start() []*Request
    Parse(Response) []*Request
}
```

**`Crawler`**:
- Worker pool (default 16 concurrent requests)
- Scheduler queue + result pipeline
- `executeRequest()`:
  1. Converts `spider.Request` → `engine.Request`
  2. `engine.Do()` → `spider.Response`
  3. Middleware processing → `spider.Parse()` → enqueue new requests (respects `maxDepth`)
  4. Pipeline processing

### 6.2 Adaptive Crawler (`brws/crawl/integration/adaptive_crawler.go`)

Self-improving crawler with strategy selection.

**`AdaptiveCrawler.Crawl(url)`**:
1. Looks up `PageHistory` for URL
2. `selectStrategy()` → returns `"explore"`, `"cautious_explore"`, `"optimized_fast"`, `"learned"`, or `"standard"` based on success rate and visit count
3. `navigator.NavigateWithIntent()` → builds semantic tree
4. Records success/failure, updates strategy stats

**`AdaptiveCrawler.CrawlWithIntent(url, intent)`**:
1. Checks for successful `ActionPattern` for this intent
2. If no pattern, uses `SmartNavigator.NavigateByIntent()`

**`AdaptivePolicy`** — Tracks strategy scores (success rate × efficiency), failure patterns with exponential backoff recommendations.

### 6.3 Semantic Navigator (`brws/crawl/integration/navigator.go`)

**`SemanticNavigator.NavigateWithIntent(url, intent)`**:
1. Stealth-navigates to URL
2. Runs `pipeline.ProcessURL()` → extracts semantic tree + compression stats
3. Caches tree by URL and `FinalURL`
4. If `intent` provided, walks tree to find actions matching intent description

**`SmartNavigator.NavigateByIntent(url, intent)`**:
1. Calls `navigator.NavigateWithIntent()` to get semantic tree
2. `findBestIntentMatch()` — scores all actions by word overlap between intent and action description/selector
3. Returns top match + up to 4 alternatives

**`AgentOrchestrator`** — Multi-agent parallel crawler:
- Pool of `SemanticAgent`s (load-balanced: least `PagesProcessed`)
- `ParallelCrawl(urls)`:
  1. Deduplicates via `Coordinator.ShouldProcess()`
  2. Semaphore-limited goroutines (`maxConcurrent`)
  3. Rate-limited via token bucket
  4. `executeWithRetry()` with exponential backoff

---

## 7. Data Flow Diagrams

### Path A: Pipeline / Graph Flow (Non-interactive)

```
User Prompt + URL
    │
    ▼
Pipeline (SmartScraperGraph or SearchGraph)
    │
    ├── FetchNode ──────────────────────┐
    │   │                               │
    │   ├── If StealthClient set:       │
    │   │   stealth.Adaptive.Scrape()     │
    │   │   → stealth.Adaptive.Navigate() │
    │   │       → engine.Do() or        │
    │   │         engine.DoOnTab()      │
    │   │           → chromium-stealth  │
    │   │               → chromedp      │
    │   │               → Chrome        │
    │   └── Else: raw HTTP GET          │
    │                                   │
    ├── ParseNode ──→ htmlToText ──→ chunks
    │                                   │
    └── GenerateAnswerNode ──→ LLM.CompleteJSON()
        → structured answer
```

### Path B: Agent Loop Flow (Interactive)

```
User Goal
    │
    ▼
SearchCoordinator or custom code
    │
    ▼
Agent.NewStealthTab(url)
    │
    ├── Agent.cfg.StealthClient.NewTab()
    │   → chromium.StealthEngine.NewTab()
    │       → chromedp.NewContext(allocCtx)
    │
    └── Agent.cfg.StealthClient.NavigateOnTab(tabCtx, url)
        → stealth.Adaptive.navigate(tabCtx=tabCtx)
            → engine.TabEngine.DoOnTab(ctx, tabCtx, req)
                → chromium.StealthEngine.DoOnTab()
                    → apply stealth script, headers, permissions
                    → chromedp.Navigate(url)
                    → capture network trace
                    → return Response
        → challenge detection/solving
        → return stealth.Response
    │
    ▼
Agent.Step(decideFn) loop
    │
    ├── Observe()
    │   → chromedp.Location/Title/LayoutMetrics
    │   → JS eval for scroll, elements, links
    │   → BuildActionSpace()
    │   → FormatCompact() or FormatSemanticCompact()
    │
    ├── decideFn (LLM or policy)
    │   → LLM sees formatted page + actions + history
    │   → returns Action{ID, Type, Parameters}
    │
    └── Execute(action)
        → Executor.Execute()
            → chromedp.Click/Type/Scroll/Navigate/etc.
            → If ActionNavigate + StealthClient:
                StealthClient.NavigateOnTab(ctx, ctx, url)
        → Record Step in history
        → Settle delay
    │
    ▼
Repeat until ActionNone or max steps
    │
    ▼
Extract results via LLM
```

---

## 8. Complete Agent Action Reference

| Action | Element-Bound? | Key Parameters | CDP / Chrome Call |
|---|---|---|---|
| `click` | Yes | `selector`, `x`, `y` | `chromedp.Click` or `chromedp.MouseClickXY` |
| `type` | Yes | `selector`, `text` | `chromedp.SendKeys` (char-by-char with jitter if `SimulateBehavior`) |
| `select` | Yes | `selector`, `value` | JS `el.value = ...; dispatchEvent('change')` |
| `toggle` | Yes | `selector` | `chromedp.Click` |
| `scroll_down` | No | `amount` (default 50% viewport) | `window.scrollBy(0, amount)` |
| `scroll_up` | No | `amount` (default 50% viewport) | `window.scrollBy(0, -amount)` |
| `scroll_bottom` | No | — | `window.scrollTo(0, document.body.scrollHeight)` |
| `scroll_top` | No | — | `window.scrollTo(0, 0)` |
| `scroll_to` | Yes | `selector`, `y` | `el.scrollIntoView({block: 'center'})` or `window.scrollTo(0, y)` |
| `navigate` | No | `url` | `StealthClient.NavigateOnTab()` or `chromedp.Navigate()` |
| `back` | No | — | `chromedp.NavigateBack()` |
| `forward` | No | — | `chromedp.NavigateForward()` |
| `reload` | No | — | `chromedp.Reload()` |
| `wait` | No | `ms` / `duration` (default 1000ms) | `chromedp.Sleep` |
| `screenshot` | No | `path` | `chromedp.CaptureScreenshot` |
| `hover` | Yes | `selector` | JS `getBoundingClientRect` → `chromedp.MouseEvent(MouseMoved, cx, cy)` |
| `focus` | Yes | `selector` | `chromedp.Focus` |
| `key_press` | Optional | `key`, `selector` (optional) | `chromedp.SendKeys` (targeted) or `input.DispatchKeyEvent` (global) |
| `clear_input` | Yes | `selector` | JS `el.value = ''` + `input`/`change` events |
| `wait_for_selector` | No | `selector`, `timeout_ms` (default 5000) | `chromedp.WaitVisible` with timeout context |
| `wait_for_navigation` | No | `timeout_ms` (default 5000) | Poll `Location` every 100ms with timeout context |
| `new_tab` | No | `url` (default about:blank) | `target.CreateTarget` |
| `switch_tab` | No | `target_id` | `target.ActivateTarget` |
| `close_tab` | No | `target_id` | `target.CloseTarget` |
| `solve_challenge` | No | — | `StealthClient.NavigateOnTab` on current URL |
| `done` | No | — | No-op |

---

## 9. Configuration & Wiring

### Top-Level Stealth Config (`brws/core/config/stealth.go`)

```go
type Config struct {
    EngineConfig
    RequestConfig
    RetryConfig
    SessionConfig
    RateLimitConfig
    CloudflareConfig
    SemanticConfig
    MonitoringConfig
}
```

### How Layers Call Each Other

| Caller | Callee | Method / Entry Point |
|--------|--------|---------------------|
| `pipeline.FetchNode` | `stealth.Adaptive` | `.Scrape()` |
| `stealth.Adaptive` | `engine.Engine` | `.Do()` / `.DoOnTab()` |
| `stealth.Adaptive` | `waterfall.Waterfall` | `.Do()` (if waterfall set) |
| `waterfall.Waterfall` | `engine.Engine` (tiers) | `.Do()` |
| `agent.Executor` | `stealth.Adaptive` | `.NavigateOnTab()` |
| `agent.Agent` | `agent.Observer` | `.Observe()` |
| `agent.Agent` | `agent.Executor` | `.Execute()` |
| `SearchCoordinator` | `agent.Agent` | `.Step()` |
| `crawl.Crawler` | `engine.Engine` | `.Do()` |
| `AdaptiveCrawler` | `SemanticNavigator` | `.NavigateWithIntent()` |
| `AgentOrchestrator` | `SemanticAgent` | `.crawlSingle()` |
| `challenge.ChallengeOrchestrator` | `challengefsm.SolverRegistry` | Solver-specific handlers |

### Quick-Start Examples

#### Navigate with stealth
```go
client, _ := stealth.NewAdaptive(stealth.WithChallengeSolver("capsolver", key))
defer client.Close()
resp, _ := client.Navigate(ctx, "https://target.com")
fmt.Println(string(resp.Body))
```

#### AI search agent
```go
coord, _ := pipeline.NewSearchCoordinator(pipeline.SearchConfig{
    Domain:        "amazon.com",
    Query:         "laptop under $500",
    StealthClient: client,
})
result, _ := coord.Run(ctx)
for _, item := range result.Items {
    fmt.Println(item.Title, item.Price)
}
```

#### Goal-directed agent with custom decideFn
```go
ag := agent.NewAgent(agent.DefaultConfig(), nil, nil, nil)
tabCtx, cancel, _ := ag.NewStealthTab(ctx, "https://example.com")
defer cancel()

for i := 0; i < 20; i++ {
    step, _ := ag.Step(tabCtx, func(pageCtx *agent.Context, actions []agent.Action, formatted string, history []agent.Step) (agent.Action, error) {
        // call your LLM here
        return chosenAction, nil
    })
    if step.Decision.Type == agent.ActionNone {
        break
    }
}
```

#### Semantic extraction
```go
pipe := semantic.NewPipeline(semantic.DefaultConfig())
tree, _ := pipe.Process(ctx, rawHTML, pageURL)
fmt.Println(tree.Compress().String())
```

#### Adaptive crawl
```go
crawler := integration.NewAdaptiveCrawler(client, pipe)
crawler.Crawl(ctx, []string{"https://shop.com"}, "find product listings")
```
