# `brws/content/agent` — Browser Automation Agent Framework

A compartmentalized, observation-action loop for browser automation. Designed for two primary use cases:

1. **Web scraping** — Programmatically extract structured page state (elements, links, forms, scroll position, tabs, history) via Chrome DevTools Protocol (CDP).
2. **Agent-driven browsing** — Give an LLM or RL policy full visibility into a live page and let it decide what to do next.

Every layer is separate and swappable. You can use the Observer by itself as a scraper, the Formatter by itself for prompt engineering, or the full Agent orchestrator for autonomous task completion.

---

## Table of Contents

- [Architecture](#architecture)
- [Page Representation: DOM vs Semantic](#page-representation-dom-vs-semantic)
- [Layer 1: Types (`types.go`)](#layer-1-types)
- [Layer 2: Observer (`observer.go`)](#layer-2-observer)
- [Layer 3: Action Space (`actionspace.go`)](#layer-3-action-space)
- [Layer 4: Formatter (`formatter.go`)](#layer-4-formatter)
- [Layer 5: Executor (`executor.go`)](#layer-5-executor)
- [Layer 6: Agent Orchestrator (`agent.go`)](#layer-6-agent-orchestrator)
- [Using as a Scraper](#using-as-a-scraper)
- [Using as an Agent Loop](#using-as-an-agent-loop)
- [CLI Bridge (`cmd/scrape/agent/agent`)](#cli-bridge)
- [Advanced: Custom Layers](#advanced-custom-layers)
- [Action Reference](#action-reference)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AGENT ORCHESTRATOR                                  │
│           observe → format → decide → execute → repeat                      │
│              ↑________________________________________↓                     │
└─────────────────────────────────────────────────────────────────────────────┘
        │           │            │          │
        ▼           ▼            ▼          ▼
   ┌─────────┐  ┌─────────┐  ┌──────┐  ┌─────────┐
   │ Observer│  │Formatter│  │Decide│  │Executor │
   │(percep- │  │(LLM     │  │(LLM /│  │(CDP /   │
   │ tion)   │  │ context)│  │policy)│  │remote)  │
   └─────────┘  └─────────┘  └──────┘  └─────────┘
        │                                    │
        ▼                                    ▼
   ┌─────────┐                        ┌─────────────┐
   │Action-  │                        │ Browser Tab │
   │ Space   │                        │ (chromedp)  │
   └─────────┘                        └─────────────┘
```

Each layer is intentionally independent:

| Layer | File | Responsibility | Can Swap? |
|-------|------|---------------|-----------|
| 1 | `types.go` | Data structures (`PageSnapshot`, `Action`, `Element`, etc.) | No (core) |
| 2 | `observer.go` | Extract live page state via CDP | Yes (Playwright, Puppeteer, HTTP) |
| 3 | `actionspace.go` | Build all possible actions from a snapshot | Yes (custom heuristics) |
| 4 | `formatter.go` | Render snapshot + actions as text/JSON | Yes (custom prompts) |
| 5 | `executor.go` | Execute chosen `Action` on the browser | Yes (remote grid, HTTP) |
| 6 | `agent.go` | Orchestrate the loop; history; convenience decisions | Yes (custom policies) |

---

## Page Representation: DOM vs Semantic

The agent has two representation modes, selected once at construction via `Config.Representation`. The mode controls what the observer sends to the formatter and which action space is built. It does not change at runtime.

| | `RepresentationDOM` (default) | `RepresentationSemantic` |
|---|---|---|
| **Source** | Raw CDP elements (bounding boxes, selectors) | Compressed semantic tree from `content/semantic` |
| **Action space** | `BuildActionSpace` — one action per `(element, type)` pair | `BuildSemanticActionSpace` — one action per semantic tree node |
| **Formatter** | `FormatCompact` — element list with coordinates | `FormatSemanticCompact` — hierarchical node summaries |
| **Token cost** | Higher | ~40% lower |
| **Best for** | Form filling, precise clicks, scraping with exact selectors | Navigation, Q&A, search, reading-heavy tasks |
| **Requires** | Nothing extra | `SemanticMode: true` in Config (builds the tree during observe) |

### Choosing a mode

```go
// DOM mode — default, always works
cfg := agent.DefaultConfig()
// cfg.Representation is RepresentationDOM

// Semantic mode — lower token cost, needs semantic tree
cfg := agent.Config{
    Representation: agent.RepresentationSemantic,
    SemanticMode:   true, // tells the observer to build the tree
    StealthClient:  client,
}
ag := agent.NewAgent(cfg, nil, nil, nil)
```

Both modes expose the same `Step` / `Observe` / `Execute` API. The only difference is the content passed to `decideFn` and the action IDs the LLM can choose from.

---

## Layer 1: Types

The type system is designed to be **fully JSON-serializable** so it can cross language boundaries (Go → Python → LLM → back).

### PageSnapshot

The root observation. Captures everything visible about the current page:

```go
type PageSnapshot struct {
    URL          string                // Current URL
    Title        string                // Page title
    Viewport     Viewport              // Width/Height in CSS pixels
    Scroll       ScrollState           // Current Y, max Y (scrollable depth)
    DocumentSize DocumentSize          // Full document width/height
    Elements     []VisibleElement      // Interactive elements (buttons, inputs, links)
    Forms        []semantic.FormSchema // Form structures with fields
    Links        []Link                // All anchor tags with hrefs
    History      HistoryState          // Browser history stack with entries
    Tabs         []TabState            // All open browser tabs
    Timestamp    time.Time
}
```

### HistoryState

Unlike basic `window.history.length`, this uses CDP `Page.getNavigationHistory` to give the agent **actual URLs and titles** it can go back/forward to:

```go
type HistoryState struct {
    Length       int            // Total history entries
    CurrentIndex int            // Where we are in the stack
    CanGoBack    bool           // Is there a previous page?
    CanGoForward bool           // Is there a next page?
    Entries      []HistoryEntry // [{URL, Title}, ...]
}
```

### TabState

The agent sees all tabs, not just the current one:

```go
type TabState struct {
    TargetID string // CDP target ID (for switching)
    URL      string
    Title    string
    IsActive bool   // Currently focused?
    Index    int    // Tab index
}
```

### Action

Every possible agent move is typed:

```go
type Action struct {
    ID           string                 // Short code: "click_E1", "scroll_down"
    Type         ActionType             // "click", "type", "scroll_down", ...
    Description  string                 // Human-readable
    TargetID     string                 // References VisibleElement.ID
    Parameters   map[string]interface{} // Action-specific data
    IsLink       bool                   // Click navigates to a link?
    IsFormSubmit bool                   // Click submits a form?
}
```

### ActionSpace

The complete menu of available actions, grouped by category:

```go
type ActionSpace struct {
    ElementActions []Action // click, type, select, toggle
    ScrollActions  []Action // scroll_down, scroll_up, scroll_to, ...
    NavActions     []Action // back, forward, reload, navigate
    TabActions     []Action // new_tab, switch_tab, close_tab
    OtherActions   []Action // wait, screenshot, done
}
```

---

## Layer 2: Observer

The Observer extracts a `PageSnapshot` from a live browser tab via CDP. It is the **scraper layer** — you can use it by itself without any agent machinery.

### What it captures

| Data | CDP Method / JS | Purpose |
|------|-----------------|---------|
| URL, Title | `chromedp.Location`, `chromedp.Title` | Basic page identity |
| Viewport | `page.GetLayoutMetrics()` | Visible area dimensions |
| Scroll state | JS `window.scrollY`, `document.documentElement.scrollHeight` | How far down the page we are |
| Interactive elements | JS querySelectorAll on `a, button, input, textarea, select, [role="button"], [onclick]` | Everything clickable/fillable |
| Element bounds | `getBoundingClientRect()` | Screen coordinates for clicking |
| Links | JS querySelectorAll on `a[href]` | Navigation graph |
| Forms | `semantic.ExtractFormSchemas(outerHTML)` | Form fields and structure |
| History | `page.GetNavigationHistory()` | Actual back/forward stack |
| Tabs | `target.GetTargets()` | All open tabs |

### Usage as a scraper

```go
import (
    "context"
    "encoding/json"
    "fmt"

    "github.com/chromedp/chromedp"
    "github.com/skunkworq/stealth/brws/content/agent"
)

func main() {
    ctx, cancel := chromedp.NewContext(context.Background())
    defer cancel()

    // Navigate
    chromedp.Run(ctx, chromedp.Navigate("https://news.ycombinator.com"))

    // Scrape full page state
    obs := agent.DefaultObserver()
    snap, err := obs.Observe(ctx)
    if err != nil {
        panic(err)
    }

    // Use the data
    fmt.Printf("URL: %s\nTitle: %s\n", snap.URL, snap.Title)
    fmt.Printf("Scroll: %.0f / %.0f px\n", snap.Scroll.Y, snap.Scroll.MaxY)
    fmt.Printf("Elements: %d\n", len(snap.Elements))
    fmt.Printf("Links: %d\n", len(snap.Links))
    fmt.Printf("Tabs: %d\n", len(snap.Tabs))
    fmt.Printf("History entries: %d (can go back: %v)\n",
        snap.History.Length, snap.History.CanGoBack)

    // Serialize for storage/processing
    b, _ := json.MarshalIndent(snap, "", "  ")
    fmt.Println(string(b))
}
```

### Tuning observation limits

```go
obs := agent.DefaultObserver()
obs.MaxElements = 100   // Capture more elements (default: 50)
obs.MaxTextLen = 200    // Longer text per element (default: 120)
```

---

## Layer 3: Action Space

Given a `PageSnapshot`, `BuildActionSpace()` enumerates **every possible action** the agent could take.

### How actions are generated

**Element actions** — one per `(element, action_type)` pair:
- An `<a>` tag → `click` action (with `IsLink=true`)
- An `<input type="text">` → `type` action
- An `<input type="checkbox">` → `toggle` action
- A `<select>` → `select` action

**Scroll actions** — context-aware based on scroll position:
- `scroll_down` — offered if not at bottom
- `scroll_up` — offered if not at top
- `scroll_bottom` — jump to end
- `scroll_top` — jump to start
- `scroll_to_<element>` — scroll until off-screen element is visible

**Navigation actions** — based on history state:
- `nav_back` — includes destination URL in description
- `nav_forward` — includes destination URL in description
- `nav_reload`
- `navigate` — go to arbitrary URL

**Tab actions** — based on open tabs:
- `switch_tab_<N>` — switch to inactive tab
- `close_tab_<N>` — close any tab
- `new_tab` — open blank tab

### Action IDs

Every action gets a deterministic short ID so LLMs can respond compactly:

| Pattern | Example | Meaning |
|---------|---------|---------|
| `click_E1` | `click_E1` | Click element E1 |
| `type_E3` | `type_E3` | Type into element E3 |
| `scroll_down` | `scroll_down` | Scroll down half viewport |
| `scroll_down_large` | `scroll_down_large` | Scroll down full viewport |
| `scroll_to_E5` | `scroll_to_E5` | Scroll until E5 is visible |
| `nav_back` | `nav_back` | Go back in history |
| `switch_tab_1` | `switch_tab_1` | Switch to tab index 1 |
| `wait` | `wait` | Wait for page to settle |
| `done` | `done` | Signal task completion |

### Usage

```go
snap, _ := obs.Observe(ctx)
actionSpace := agent.BuildActionSpace(snap)

// Flat list of all actions
for _, a := range actionSpace.All() {
    fmt.Printf("[%s] %s\n", a.ID, a.Description)
}

// Find a specific action
act := actionSpace.Find("click_E1")
if act != nil {
    fmt.Println("Found:", act.Description)
}
```

---

## Layer 4: Formatter

Converts `Context` (snapshot + action space) into a string representation for LLM consumption. Three modes:

### Compact (default) — token-efficient

```
PAGE https://news.ycombinator.com | "Hacker News" | vp=1280x800 | scroll=0/4500(0%)
TABS: 1 open | [0]*Hacker News
BACK: https://www.google.com/search?q=hn
[ E1] a "Hacker News" @ 12,15 → click [is_link]
[ E2] a "new" @ 45,15 → click [is_link]
[ E3] a "past" @ 78,15 → click [is_link]
[ E4] input "" @ 450,15 → type [placeholder=search]
[ E5] a "comments" @ 12,120 → click [is_link]
SCROLL: scroll_down scroll_down_large scroll_bottom
NAV: nav_back nav_reload navigate
TABS: new_tab
META: wait screenshot done
```

### Markdown — human-readable

```
=== PAGE CONTEXT ===
URL:     https://news.ycombinator.com
Title:   Hacker News
Viewport: 1280 x 800
Scroll:   0 / 4500 px (0% — top third)
History:  2 entries | back=true | forward=false
  ← back to: https://www.google.com/search?q=hn

=== INTERACTIVE ELEMENTS ===
  [E1] <a> → click | "Hacker News"
  [E2] <a> → click | "new"
  [E3] <input> → type | [placeholder="search"]

=== SCROLL ACTIONS ===
  [scroll_down] Scroll down (~50% of viewport)
  [scroll_bottom] Scroll to the bottom of the page
...
```

### JSON — structured parsing

Full `json.MarshalIndent` of the `Context` struct. Useful for logging, storage, or structured downstream processing.

### Usage

```go
ctx := agent.NewContext(snap)
fmttr := agent.DefaultFormatter()

compact  := fmttr.FormatCompact(ctx)
markdown := fmttr.Format(ctx)
jsonStr  := fmttr.FormatJSON(ctx)
```

---

## Layer 5: Executor

Executes agent-chosen actions against a live browser tab via CDP.

### Supported actions

| Action | CDP Implementation |
|--------|-------------------|
| `click` | `chromedp.Click(selector)` — or Bézier mouse path → CDP click when SimulateBehavior=true |
| `type` | `chromedp.SendKeys(selector, text)` — or focus → char-by-char SendKeys + delays when SimulateBehavior=true |
| `select` | JS `el.value = ...; el.dispatchEvent(new Event('change'))` |
| `toggle` | `chromedp.Click(selector)` |
| `scroll_down` | JS `window.scrollBy(0, amount)` — or ScrollSimulator JS when SimulateBehavior=true |
| `scroll_up` | JS `window.scrollBy(0, -amount)` — or ScrollSimulator JS when SimulateBehavior=true |
| `scroll_bottom` | JS `window.scrollTo(0, document.body.scrollHeight)` |
| `scroll_top` | JS `window.scrollTo(0, 0)` |
| `scroll_to` | JS `el.scrollIntoView()` or `window.scrollTo(0, y)` |
| `navigate` | `chromedp.Navigate(url)` |
| `back` | `chromedp.NavigateBack()` |
| `forward` | `chromedp.NavigateForward()` |
| `reload` | `chromedp.Reload()` |
| `wait` | `chromedp.Sleep(duration)` |
| `screenshot` | `chromedp.CaptureScreenshot(&buf)` |
| `new_tab` | `target.CreateTarget(url)` |
| `switch_tab` | `target.ActivateTarget(targetID)` |
| `close_tab` | `target.CloseTarget(targetID)` |

### ExecuteResult

```go
type ExecuteResult struct {
    ActionID        string  // matches Action.ID
    Success         bool
    Error           string  // non-empty on failure
    NewURL          string  // set after navigate/back/forward/reload
    ScrollDelta     float64 // pixels moved for scroll_down/scroll_up
    ChallengeSolved bool    // true if an anti-bot challenge was solved
    // NoChange is true when the action succeeded but produced no measurable
    // page change: scroll actions that moved zero pixels (already at boundary),
    // or nav actions that resolved to the same URL. Useful in decideFn to
    // detect when the agent is making no progress.
    NoChange bool
}
```

### Usage

```go
exec := &agent.Executor{}

// Execute a single action
res, err := exec.Execute(ctx, agent.Action{
    Type:   agent.ActionClick,
    ID:     "click_E1",
    Parameters: map[string]interface{}{
        "selector": "a#submit",
    },
})

fmt.Printf("Success: %v, New URL: %s, NoChange: %v\n", res.Success, res.NewURL, res.NoChange)
```

### Execute a plan (sequence)

```go
actions := []agent.Action{
    {Type: agent.ActionTypeText, ID: "type_E3", Parameters: map[string]interface{}{
        "selector": "input[name='q']", "text": "golang",
    }},
    {Type: agent.ActionClick, ID: "click_E5", Parameters: map[string]interface{}{
        "selector": "button[type='submit']",
    }},
}
results, err := exec.ExecutePlan(ctx, actions)
```

---

## Layer 6: Agent Orchestrator

The `Agent` struct ties all layers together into a loop:

```
observe → format → decide → execute → repeat
```

### Reactive loop (external decision maker)

The agent observes and formats, but the **decision is external** (e.g., an LLM API call):

```go
a := agent.NewAgent(agent.DefaultConfig(), nil, nil, nil)

for {
    // 1. Observe
    pageCtx, actions, formatted, err := a.Observe(chromeCtx)
    if err != nil {
        log.Fatal(err)
    }

    // 2. Send to LLM (external)
    actionID := callLLM(formatted) // e.g. "click_E1"

    // 3. Find and execute
    act := pageCtx.ActionSpace.Find(actionID)
    if act == nil {
        log.Fatalf("unknown action: %s", actionID)
    }
    res, err := a.Execute(chromeCtx, *act)
    fmt.Printf("Result: %+v\n", res)

    // 4. Check termination
    if actionID == "done" {
        break
    }
}
```

### Autonomous loop (callback-based)

Use `Agent.Step()` with a decision callback:

```go
a := agent.NewAgent(agent.DefaultConfig(), nil, nil, nil)

for i := 0; i < 20; i++ {
    step, err := a.Step(chromeCtx, func(ctx *agent.Context, actions []agent.Action, formatted string, hist []agent.Step) (agent.Action, error) {
        // Your LLM / policy logic here
        // Return the chosen action
        return actions[0], nil // naive: always pick first
    })
    if err != nil {
        log.Println("Step error:", err)
    }
    if step.Decision.Type == agent.ActionNone {
        break
    }
}
```

### Built-in decision heuristics

For non-LLM use cases, convenience decision functions are provided:

```go
// Click the first available link
step, _ := a.Step(chromeCtx, agent.Decisions.ClickFirstLink)

// Scroll down once, then click first link
step, _ := a.Step(chromeCtx, agent.Decisions.ScrollThenClick)

// Keep scrolling until bottom
step, _ := a.Step(chromeCtx, agent.Decisions.ScrollToBottom)

// Fill and submit first form
step, _ := a.Step(chromeCtx, agent.Decisions.SubmitFirstForm)
```

### Configuration

```go
cfg := agent.Config{
    // --- Page representation (choose one) ---
    Representation: agent.RepresentationDOM,      // or RepresentationSemantic
    SemanticMode:   false,                        // set true when using RepresentationSemantic

    // --- Timing ---
    SettleDelay:   500 * time.Millisecond, // Wait after each action before re-observing
    ActionTimeout: 30 * time.Second,       // Per-action deadline

    // --- Memory ---
    HistorySize: 50, // Max steps kept in memory; older steps are dropped

    // --- Context shaping ---
    IncludeMedia: false, // Include <img>/<video> in snapshot (token-heavy)
    IncludeForms: true,  // Include form field details
    CompactLinks: true,  // One-line link format vs full struct
    ScrollFirst:  true,  // Prioritise scroll actions in the action space

    // --- Stealth ---
    StealthMode:   true,   // Human-like delays and behaviour
    StealthClient: client, // Required for challenge solving and persistent tabs

    // --- Behavior simulation ---
    SimulateBehavior: false, // true = Bézier mouse paths, per-keystroke delays, incremental scroll
    BehaviorDelay:    0,     // 0 = use simulator defaults (50–200 ms typing, 100–300 ms scroll)
}
```

### History access

```go
// Full step history — each Step has Observation, Decision, Result, and Formatted
for _, s := range a.History() {
    noChange := s.Result != nil && s.Result.NoChange
    fmt.Printf("%s: %s → success=%v noChange=%v\n",
        s.Timestamp.Format(time.RFC3339), s.Decision.ID, s.Result.Success, noChange)
}

// Last observed state
ctx := a.LastContext()
fmt.Println(ctx.Snapshot.URL)

// Summary
fmt.Println(a.Summary()) // "Agent[12 steps] @ https://... | 23 actions available"
```

### Using NoChange in a decideFn

`ExecuteResult.NoChange` is set when a scroll action moved zero pixels (page boundary) or a nav action resolved to the same URL. It is available on the previous step's result via history:

```go
a.Step(tabCtx, func(pageCtx *agent.Context, actions []agent.Action, formatted string, hist []agent.Step) (agent.Action, error) {
    // Detect if the last action had no effect
    if len(hist) > 0 {
        last := hist[len(hist)-1]
        if last.Result != nil && last.Result.NoChange {
            // Last action was a no-op — try something different
        }
    }
    // ... decide
})
```

---

## Using as a Scraper

The agent framework is also a powerful structured scraper. Here's a complete example that extracts all interactive elements, links, and forms from a page:

```go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log"

    "github.com/chromedp/chromedp"
    "github.com/skunkworq/stealth/brws/content/agent"
)

func scrapePage(url string) (*agent.PageSnapshot, error) {
    ctx, cancel := chromedp.NewContext(context.Background())
    defer cancel()

    if err := chromedp.Run(ctx, chromedp.Navigate(url)); err != nil {
        return nil, err
    }

    obs := agent.DefaultObserver()
    return obs.Observe(ctx)
}

func main() {
    snap, err := scrapePage("https://news.ycombinator.com")
    if err != nil {
        log.Fatal(err)
    }

    // Extract links
    fmt.Println("=== LINKS ===")
    for _, link := range snap.Links {
        fmt.Printf("- %s → %s\n", link.Text, link.Href)
    }

    // Extract interactive elements
    fmt.Println("\n=== INTERACTIVE ELEMENTS ===")
    for _, elem := range snap.Elements {
        fmt.Printf("[%s] <%s> %q @ (%.0f, %.0f)\n",
            elem.ID, elem.Tag, elem.Text, elem.Bounds.X, elem.Bounds.Y)
    }

    // Extract forms
    fmt.Println("\n=== FORMS ===")
    for i, form := range snap.Forms {
        fmt.Printf("Form %d: %s %s\n", i, form.Method, form.Action)
        for _, field := range form.Fields {
            fmt.Printf("  - %s (%s)\n", field.Label, field.Type)
        }
    }

    // Full JSON export
    b, _ := json.MarshalIndent(snap, "", "  ")
    fmt.Println("\n=== FULL JSON ===")
    fmt.Println(string(b))
}
```

### Scraping with scroll

To scrape content below the fold:

```go
func scrapeWithScroll(url string) ([]*agent.PageSnapshot, error) {
    ctx, cancel := chromedp.NewContext(context.Background())
    defer cancel()

    chromedp.Run(ctx, chromedp.Navigate(url))

    var snapshots []*agent.PageSnapshot
    obs := agent.DefaultObserver()

    for {
        snap, err := obs.Observe(ctx)
        if err != nil {
            return nil, err
        }
        snapshots = append(snapshots, snap)

        // Stop if at bottom
        if snap.Scroll.Y >= snap.Scroll.MaxY-1 {
            break
        }

        // Scroll down
        chromedp.Run(ctx, chromedp.Evaluate(
            fmt.Sprintf("window.scrollBy(0, %f)", snap.Viewport.Height*0.8), nil))
        chromedp.Sleep(500 * time.Millisecond)
    }

    return snapshots, nil
}
```

---

## Using as an Agent Loop

### Minimal LLM-driven agent

```go
package main

import (
    "context"
    "fmt"
    "strings"

    "github.com/chromedp/chromedp"
    "github.com/skunkworq/stealth/brws/content/agent"
)

// Mock LLM — replace with real API call
func mockLLM(prompt string) string {
    // In reality: call OpenAI/Claude/Local model
    if strings.Contains(prompt, "login") {
        return "type_E3: username"  // format: [action_id]: parameter
    }
    return "click_E1"
}

func main() {
    ctx, cancel := chromedp.NewContext(context.Background())
    defer cancel()

    a := agent.NewAgent(agent.DefaultConfig(), nil, nil, nil)

    // Initial navigation
    chromedp.Run(ctx, chromedp.Navigate("https://example.com/login"))

    for i := 0; i < 10; i++ {
        // Observe
        pageCtx, actions, formatted, err := a.Observe(ctx)
        if err != nil {
            panic(err)
        }

        // Decide
        response := mockLLM(formatted)
        parts := strings.SplitN(response, ":", 2)
        actionID := strings.TrimSpace(parts[0])
        param := ""
        if len(parts) > 1 {
            param = strings.TrimSpace(parts[1])
        }

        // Find action
        act := pageCtx.ActionSpace.Find(actionID)
        if act == nil {
            fmt.Println("Unknown action:", actionID)
            break
        }

        // Inject parameter for type actions
        if act.Type == agent.ActionTypeText && param != "" {
            act.Parameters["text"] = param
        }

        // Execute
        res, err := a.Execute(ctx, *act)
        fmt.Printf("Step %d: %s → success=%v err=%v\n",
            i, actionID, res.Success, err)

        if actionID == "done" {
            break
        }
    }
}
```

### Multi-tab workflow

```go
// Open a new tab
agent.Execute(ctx, agent.Action{
    Type: agent.ActionNewTab,
    Parameters: map[string]interface{}{"url": "https://google.com"},
})

// Observe — now sees 2 tabs
pageCtx, _, _, _ := a.Observe(ctx)
fmt.Println("Tabs:", len(pageCtx.Snapshot.Tabs))

// Switch to first tab
agent.Execute(ctx, agent.Action{
    Type: agent.ActionSwitchTab,
    Parameters: map[string]interface{}{"target_id": pageCtx.Snapshot.Tabs[0].TargetID},
})
```

---

## CLI Bridge

The `cmd/scrape/agent/agent` binary exposes the agent package as a subprocess-friendly CLI. This is how Python connects to it.

### Commands

```bash
# Observe a page (outputs JSON)
agent observe \
  --session-dir /tmp/agent-session \
  --url https://example.com \
  --format compact

# Execute an action
agent execute \
  --session-dir /tmp/agent-session \
  --action '{"type":"click","id":"E1_click","selector":"a#submit"}'

# Full step: observe + execute
agent step \
  --session-dir /tmp/agent-session \
  --url https://example.com \
  --decision click_E1 \
  --format compact

# Kill Chrome and clean up
agent session-stop --session-dir /tmp/agent-session
```

### Session persistence

The first call to any command with `--session-dir` starts Chrome with `--remote-debugging-port`. Subsequent calls reconnect to the same Chrome instance. Session data (cookies, localStorage, history) persists in the session directory's Chrome profile.

---

---

## Advanced: Custom Layers

### Custom Observer

```go
type CustomObserver struct {
    agent.Observer
}

func (o *CustomObserver) Observe(ctx context.Context) (*agent.PageSnapshot, error) {
    snap, err := o.Observer.Observe(ctx)
    if err != nil {
        return nil, err
    }
    // Add custom data
    snap.Links = filterLinks(snap.Links) // custom filtering
    return snap, nil
}
```

### Custom Formatter

```go
type XMLFormatter struct{}

func (f *XMLFormatter) Format(ctx *agent.Context) string {
    var b strings.Builder
    b.WriteString("<page>\n")
    b.WriteString(fmt.Sprintf("  <url>%s</url>\n", ctx.Snapshot.URL))
    for _, elem := range ctx.Snapshot.Elements {
        b.WriteString(fmt.Sprintf("  <element id=\"%s\" tag=\"%s\">%s</element>\n",
            elem.ID, elem.Tag, elem.Text))
    }
    b.WriteString("</page>")
    return b.String()
}
```

### Custom Decision Function

```go
// Always click the element closest to the word "submit"
func submitHunter(ctx *agent.Context, actions []agent.Action, formatted string, hist []agent.Step) (agent.Action, error) {
    for _, a := range actions {
        if a.Type == agent.ActionClick && strings.Contains(strings.ToLower(a.Description), "submit") {
            return a, nil
        }
    }
    return agent.Action{Type: agent.ActionNone}, fmt.Errorf("no submit button found")
}

step, _ := a.Step(chromeCtx, submitHunter)
```

---

## Action Reference

| Type | ID Pattern | Parameters | Description |
|------|-----------|------------|-------------|
| `click` | `click_<elem>` | `selector` | Click element |
| `type` | `type_<elem>` | `selector`, `text` | Type text into input |
| `select` | `select_<elem>` | `selector`, `value` | Choose option by value |
| `toggle` | `toggle_<elem>` | `selector` | Checkbox/radio toggle |
| `scroll_down` | `scroll_down` | `amount` (optional) | Scroll down |
| `scroll_up` | `scroll_up` | `amount` (optional) | Scroll up |
| `scroll_bottom` | `scroll_bottom` | — | Jump to bottom |
| `scroll_top` | `scroll_top` | — | Jump to top |
| `scroll_to` | `scroll_to_<elem>` | `selector` or `y` | Scroll to element |
| `navigate` | `navigate` | `url` | Go to URL |
| `back` | `nav_back` | — | Browser back |
| `forward` | `nav_forward` | — | Browser forward |
| `reload` | `nav_reload` | — | Reload page |
| `wait` | `wait` | `ms` or `duration` | Sleep |
| `screenshot` | `screenshot` | `path` (optional) | Capture screenshot |
| `new_tab` | `new_tab` | `url` (optional) | Open new tab |
| `switch_tab` | `switch_tab_<N>` | `target_id`, `index` | Switch tab |
| `close_tab` | `close_tab_<N>` | `target_id`, `index` | Close tab |
| `solve_challenge` | `solve_challenge` | `challenge_type` | Solve anti-bot challenge (requires StealthClient) |
| `done` | `done` | — | No-op / terminate |

---

## Design Principles

1. **Compartmentalization** — Every layer is independent. Swap the Observer for Playwright, the Formatter for XML, the Executor for a remote grid.
2. **Explicit mode selection** — `Config.Representation` is chosen once at construction. The agent never changes modes at runtime; the caller picks the right mode for the task.
3. **JSON-serializable** — All types serialize cleanly so they can cross process boundaries (Go CLI → Python → LLM).
4. **Scroll as first-class** — Scroll is not an afterthought. It carries intent, phase, and profile metadata.
5. **Tab awareness** — The agent sees the full browser, not just one tab.
6. **History awareness** — The agent knows exactly where back/forward will go, not just "can go back."
7. **Token efficiency** — The Compact formatter is designed for LLM context windows; Semantic mode cuts that further by ~40%.
8. **Deterministic IDs** — Short action IDs let LLMs respond compactly (`[click_E1]` instead of full JSON).
