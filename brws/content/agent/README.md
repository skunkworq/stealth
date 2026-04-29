# `brws/content/agent` — Browser Automation Agent Framework

A compartmentalized, observation-action loop for browser automation. Designed for two primary use cases:

1. **Web scraping** — Programmatically extract structured page state (elements, links, forms, scroll position, tabs, history) via Chrome DevTools Protocol (CDP).
2. **Agent-driven browsing** — Give an LLM or RL policy full visibility into a live page and let it decide what to do next.

Every layer is separate and swappable. You can use the Observer by itself as a scraper, the Formatter by itself for prompt engineering, or the full Agent orchestrator for autonomous task completion.

---

## Table of Contents

- [Architecture](#architecture)
- [Layer 1: Types (`types.go`)](#layer-1-types)
- [Layer 2: Observer (`observer.go`)](#layer-2-observer)
- [Layer 3: Action Space (`actionspace.go`)](#layer-3-action-space)
- [Layer 4: Formatter (`formatter.go`)](#layer-4-formatter)
- [Layer 5: Executor (`executor.go`)](#layer-5-executor)
- [Layer 6: Agent Orchestrator (`agent.go`)](#layer-6-agent-orchestrator)
- [Using as a Scraper](#using-as-a-scraper)
- [Using as an Agent Loop](#using-as-an-agent-loop)
- [CLI Bridge (`cmd/agent`)](#cli-bridge)
- [Python Integration (`pybrwslab.Agent`)](#python-integration)
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
| `click` | `chromedp.Click(selector)` or `chromedp.MouseClickXY(x, y)` |
| `type` | `chromedp.SendKeys(selector, text)` |
| `select` | JS `el.value = ...; el.dispatchEvent(new Event('change'))` |
| `toggle` | `chromedp.Click(selector)` |
| `scroll_down` | JS `window.scrollBy(0, amount)` |
| `scroll_up` | JS `window.scrollBy(0, -amount)` |
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

fmt.Printf("Success: %v, New URL: %s\n", res.Success, res.NewURL)
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
    MaxRetries:    3,               // Retry failed actions
    SettleDelay:   500 * time.Millisecond, // Wait after page changes
    ActionTimeout: 30 * time.Second,       // Per-action timeout
    HistorySize:   50,              // Max steps to remember
    IncludeMedia:  false,           // Include <img>/<video> (token-heavy)
    IncludeForms:  true,            // Include form details
    CompactLinks:  true,            // One-line link format
    ScrollFirst:   true,            // Prioritize scroll actions
    StealthMode:   true,            // Human-like delays
}
```

### History access

```go
// Full step history
for _, s := range a.History() {
    fmt.Printf("%s: %s → %v\n", s.Timestamp.Format(time.RFC3339),
        s.Decision.ID, s.Result.Success)
}

// Last observed state
ctx := a.LastContext()
fmt.Println(ctx.Snapshot.URL)

// Summary
fmt.Println(a.Summary()) // "Agent[12 steps] @ https://... | 23 actions available"
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

The `cmd/agent` binary exposes the agent package as a subprocess-friendly CLI. This is how Python connects to it.

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

## Python Integration

`pybrwslab.Agent` wraps the CLI binary:

```python
from pybrwslab import Agent

with Agent(session_dir="/tmp/agent-session") as agent:
    # Observe
    ctx = agent.observe("https://example.com", format="compact")
    print(ctx["formatted"])

    # Pick an action and execute
    action = ctx["action_space"]["element_actions"][0]
    result = agent.execute(action)
    print(result["success"])

    # Or do it in one call
    result = agent.step(
        "https://example.com",
        decision="click_E1",
        format="compact"
    )
    print(result["observation"]["formatted"])
```

### Connecting to an LLM

```python
from pybrwslab import Agent
import openai

agent = Agent(session_dir="/tmp/agent-session")

for _ in range(20):
    ctx = agent.observe("https://example.com", format="compact")

    # Send formatted context to LLM
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{
            "role": "user",
            "content": f"Choose ONE action by ID:\n\n{ctx['formatted']}"
        }]
    )
    action_id = response.choices[0].message.content.strip()

    # Execute
    result = agent.step("https://example.com", decision=action_id)
    if action_id == "done":
        break

agent.stop()
```

### Pydantic AI Research Agent

For a structured, tool-based agent framework, use [Pydantic AI](https://github.com/pydantic/pydantic-ai). The browser state becomes a set of tools the agent can call:

```python
"""
Pydantic AI Research Agent — Autonomous web research with structured output.
"""

from dataclasses import dataclass, field
from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext
from pybrwslab import Agent as BrowserAgent


class ResearchReport(BaseModel):
    query: str = Field(description="The original research question")
    findings: list[str] = Field(default_factory=list, description="Facts discovered")
    sources: list[str] = Field(default_factory=list, description="URLs visited")
    answer: str = Field(description="Concise answer to the question")
    confidence: str = Field(description="high | medium | low")


@dataclass
class ResearchDeps:
    browser: BrowserAgent
    visited_urls: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    max_steps: int = 20
    step_count: int = 0


agent = Agent(
    model="openai:gpt-4o",
    system_prompt="""\
You are an expert web researcher. Browse the web to find accurate answers.

Rules:
1. Start with search(query) or navigate(url).
2. After each page load, the formatted context shows available actions.
3. Use click(action_id), scroll(direction), type_text(action_id, text).
4. Record facts with add_finding(fact).
5. Track sources automatically.
6. Finish with finish_research(answer, confidence).
""",
    result_type=ResearchReport,
    deps_type=ResearchDeps,
)


@agent.tool
async def navigate(ctx: RunContext[ResearchDeps], url: str) -> str:
    """Navigate to a URL and observe the page."""
    ctx.deps.step_count += 1
    page = ctx.deps.browser.observe(url, format="compact")
    ctx.deps.visited_urls.append(page["snapshot"]["url"])
    return f"=== PAGE ===\n{page['formatted']}"


@agent.tool
async def search(ctx: RunContext[ResearchDeps], query: str) -> str:
    """Search DuckDuckGo for the query."""
    url = "https://html.duckduckgo.com/html/?q=" + query.replace(" ", "+")
    return await navigate(ctx, url)


@agent.tool
async def click(ctx: RunContext[ResearchDeps], action_id: str) -> str:
    """Click an element by its action ID."""
    ctx.deps.step_count += 1
    result = ctx.deps.browser.step("", decision=action_id, format="compact")
    if result["result"].get("new_url"):
        ctx.deps.visited_urls.append(result["result"]["new_url"])
    return (
        f"Clicked {action_id}: success={result['result']['success']}\n\n"
        f"{result['observation']['formatted']}"
    )


@agent.tool
async def scroll(ctx: RunContext[ResearchDeps], direction: str) -> str:
    """Scroll the page: down, up, bottom, or top."""
    mapping = {"down": "scroll_down", "up": "scroll_up",
               "bottom": "scroll_bottom", "top": "scroll_top"}
    result = ctx.deps.browser.step("", decision=mapping.get(direction, "scroll_down"))
    return result["observation"]["formatted"]


@agent.tool
async def type_text(ctx: RunContext[ResearchDeps], action_id: str, text: str) -> str:
    """Type text into an input field."""
    page = ctx.deps.browser.observe("", format="json")
    action = None
    for a in page.get("action_space", {}).get("element_actions", []):
        if a.get("id") == action_id:
            action = a
            break
    if action is None:
        return f"ERROR: {action_id} not found"
    action.setdefault("parameters", {})
    action["parameters"]["text"] = text
    result = ctx.deps.browser.execute(action)
    return f"Typed into {action_id}: success={result['success']}"


@agent.tool
async def go_back(ctx: RunContext[ResearchDeps]) -> str:
    """Go back to the previous page."""
    result = ctx.deps.browser.step("", decision="nav_back", format="compact")
    return result["observation"]["formatted"]


@agent.tool
async def add_finding(ctx: RunContext[ResearchDeps], fact: str) -> str:
    """Record a factual finding."""
    ctx.deps.findings.append(fact)
    return f"Recorded finding #{len(ctx.deps.findings)}: {fact}"


@agent.tool
async def finish_research(
    ctx: RunContext[ResearchDeps], answer: str, confidence: str
) -> ResearchReport:
    """Submit the final research report."""
    return ResearchReport(
        query="",  # filled by framework
        findings=ctx.deps.findings,
        sources=list(dict.fromkeys(ctx.deps.visited_urls)),
        answer=answer,
        confidence=confidence,
    )


# Run research
async def research(query: str) -> ResearchReport:
    browser = BrowserAgent(session_dir="/tmp/pydantic-ai-research")
    deps = ResearchDeps(browser=browser, max_steps=25)
    try:
        result = await agent.run(query, deps=deps)
        return result.data
    finally:
        browser.stop()


# Usage
# report = asyncio.run(research("Current NVIDIA stock price"))
# print(report.answer)
# print(report.sources)
```

**How it works:**

1. **Dependencies** (`ResearchDeps`) hold the `BrowserAgent` and accumulated state (visited URLs, findings, step counter).
2. **Tools** are decorated with `@agent.tool`. Each tool calls the browser via `pybrwslab.Agent` and returns a string description back to the LLM.
3. **Structured output** — `result_type=ResearchReport` means the agent returns a validated Pydantic model, not free text.
4. **State tracking** — `visited_urls` and `findings` persist across tool calls via `RunContext.deps`.
5. **Step limiting** — `max_steps` prevents infinite loops.

**Running the example:**

```bash
export OPENAI_API_KEY="sk-..."
python python/examples/pydantic_ai_researcher.py "What is the current price of NVIDIA stock?"
```

The full working example is at `python/examples/pydantic_ai_researcher.py`.

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
| `done` | `done` | — | No-op / terminate |

---

## Design Principles

1. **Compartmentalization** — Every layer is independent. Swap the Observer for Playwright, the Formatter for XML, the Executor for a remote grid.
2. **JSON-serializable** — All types serialize cleanly so they can cross process boundaries (Go CLI → Python → LLM).
3. **Scroll as first-class** — Scroll is not an afterthought. It carries intent, phase, and profile metadata.
4. **Tab awareness** — The agent sees the full browser, not just one tab.
5. **History awareness** — The agent knows exactly where back/forward will go, not just "can go back."
6. **Token efficiency** — The Compact formatter is designed for LLM context windows.
7. **Deterministic IDs** — Short action IDs let LLMs respond compactly (`[click_E1]` instead of full JSON).
