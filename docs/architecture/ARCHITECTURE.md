# Stealth Architecture — Complete System Overview

**Stealth** is a Go toolkit for browser-grade web scraping and autonomous agent-driven browsing. It solves three hard problems in modern web automation:

1. **Detection** — Sites detect and block headless browsers. Stealth uses TLS fingerprint spoofing, behavioral simulation, and adaptive evasion to appear human.
2. **Extraction** — Raw HTML is noisy and token-heavy for LLMs. Stealth compresses pages into structured semantic trees (~99% token reduction).
3. **Agency** — Bots can't "browse" like humans. Stealth models the page as an environment with observations, actions, and state.

---

## Table of Contents

- [Architecture at a Glance](#architecture-at-a-glance)
- [Layer 1: Engine — Making Requests](#layer-1-engine)
- [Layer 2: Stealth — Avoiding Detection](#layer-2-stealth)
- [Layer 3: Semantic — Understanding Content](#layer-3-semantic)
- [Layer 4: Agent — Acting Autonomously](#layer-4-agent)
- [End-to-End Data Flow](#end-to-end-data-flow)
- [Using as a Scraper](#using-as-a-scraper)
- [Using as an Agent](#using-as-an-agent)
- [Python Integration](#python-integration)
- [Lab & Training System](#lab--training-system)
- [CLI Tools Reference](#cli-tools-reference)

---

## Architecture at a Glance

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              AGENT LAYER                                    │
│         observe → decide → execute → repeat                                 │
│    (PageSnapshot → ActionSpace → BrowserAction → new PageSnapshot)         │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SEMANTIC + AGENTIC LAYER                            │
│  HTML → Clean → Chunk → Compress (LLM) → SemanticTree → Actions/Forms      │
│  URL → Fetch → Parse → [Reason] → GenerateAnswer → Merge (agentic graphs)  │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            STEALTH LAYER                                    │
│    Engine + Session + Challenge Solver + Behavioral Evasion + Escalation   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                             ENGINE LAYER                                    │
│         native (uTLS)    chromium (CDP)    firefox    webkit               │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Four layers, one goal:** Turn a URL into structured, actionable information while remaining indistinguishable from a real human browser.

---

## Layer 1: Engine

The Engine layer is the **transport**. It defines a unified `Engine` interface that abstracts over different HTTP/browser backends:

```go
type Engine interface {
    Name() string
    Capabilities() Capabilities
    Do(ctx context.Context, req *Request) (*Response, error)
    Close() error
}
```

### Engine implementations

| Engine | Underlying Tech | JavaScript | TLS Spoof | HTTP/2 | HTTP/3 | Use Case |
|--------|----------------|------------|-----------|--------|--------|----------|
| `native` | Go `net/http` + uTLS | No | uTLS ClientHello | Yes | No | Fast API scraping, no JS needed |
| `chromium` | Chrome via chromedp/CDP | Yes | Real Chrome | Yes | Yes | Full browser automation, JS-heavy sites |
| `firefox` | Firefox via Playwright | Yes | Real Firefox | Yes | Yes | Alternative browser fingerprint |
| `webkit` | Safari via Playwright | Yes | Real Safari | Yes | Yes | Mobile/Apple-specific testing |

### Engine selection strategy

The Stealth client uses a **waterfall** approach: start cheap (native), escalate to expensive (chromium) only when needed:

```
native (fast, no JS) ──► 403/429 detected ──► chromium-stealth (full browser)
                           │
                           └──► proxy rotation ──► behavioral evasion ──► challenge solving
```

### Engine profiles

Each engine can emulate a specific browser fingerprint:

```go
engine.New("chromium", engine.Options{
    Stealth:     true,
    StealthTLS:  true,
    ProfileName: "chrome-120-macos",  // or "firefox-120-windows", "safari-16-macos"
})
```

Profiles include: User-Agent, header order, TLS cipher suites, HTTP/2 settings, Sec-Fetch behavior, Client Hints, screen dimensions, timezone, and more.

---

## Layer 2: Stealth

The Stealth layer is the **anti-detection brain**. It sits between the user and the engine, intercepting requests and responses to maximize success rate.

### Core components

```
┌─────────────────────────────────────────────────────────────┐
│                      stealth.Client                         │
├─────────────────────────────────────────────────────────────┤
│  Session Manager  │  Reuses cookies, localStorage, profiles │
│  Challenge Solver │  Auto-detects & solves CAPTCHAs         │
│  Behavioral Sim   │  Human-like mouse, typing, scrolling    │
│  Escalation       │  Auto-retry with harder config on 403   │
│  Evasion FSM      │  Adaptive strategy selection            │
│  RL Policy        │  DQN model mutates stealth config       │
│  Waterfall        │  Tiered engine fallback                 │
└─────────────────────────────────────────────────────────────┘
```

### Anti-detection features

| Feature | What it does | Why it matters |
|---------|-------------|----------------|
| `RemoveWebDriver` | JS patch removes `navigator.webdriver` flag | Sites check this to detect Selenium/Playwright |
| `CanvasNoise` | Adds 2% random noise to canvas pixel data | Canvas fingerprinting expects human-like noise |
| `WebGLSpoof` | Fakes `UNMASKED_VENDOR_WEBGL` and renderer | WebGL fingerprints identify GPU/driver combos |
| `ClientHints` | Spoofs `Sec-Ch-Ua`, platform, mobile | Modern sites use Client Hints instead of UA |
| `FakeScreen` | Overrides `window.screen` dimensions | Headless browsers report 0x0 or unrealistic sizes |
| `FakeTimezone` | Sets `Intl.DateTimeFormat` timezone | IP-to-timezone mismatch is a detection signal |
| **StealthPlus** | Raw CDP escape hatch, user gestures, permissions | Nodriver-inspired advanced features |
| **Dynamic Sync** | Hardware, network, plugins, geometry sync | Ensures all fingerprint vectors are consistent |

### Challenge handling

When a challenge (CAPTCHA, Cloudflare, DataDome) is detected:

1. **Detect** — Scan status codes (503, 403), headers (`Cf-Ray`, `Server: cloudflare`), body markers (`cf-challenge`, Turnstile widgets)
2. **Classify** — ML-based challenge type classification (JS challenge, managed challenge, Turnstile, reCAPTCHA, hCaptcha)
3. **Solve** — Browser-based solving, external service integration (CapSolver, 2Captcha), or trace replay from captured human sessions
4. **Validate** — Verify `cf_clearance` cookie or challenge token before continuing

### Escalation system

On repeated failures (403, 429, challenge loops):

```
Attempt 1: native engine, basic stealth
    ↓ 403
Attempt 2: native + proxy rotation
    ↓ 403
Attempt 3: chromium engine, full stealth
    ↓ 403
Attempt 4: chromium + residential proxy + behavioral simulation
    ↓ 403
Attempt 5: Report failure (human review)
```

### RL-driven policy adaptation

The system loads DQN-trained PyTorch models (`fsm_rl_policy.pt`, `shield_sword_policy.pt`) that mutate the stealth configuration based on detection feedback:

```go
// 18-dimensional state vector
state := []float64{
    detection_anomaly_score,    // How "bot-like" do we appear?
    challenge_detected,          // Are we facing a challenge?
    captcha_solved,              // Did we solve the last CAPTCHA?
    request_success_rate,        // % of successful requests
    // ... 14 more dimensions
}

// Model outputs 18 actions (toggle stealth config fields)
action := policy.Predict(state)  // e.g., "enable CanvasNoise"
```

---

## Layer 3: Semantic

The Semantic layer transforms **raw HTML** into **structured, compressed, LLM-friendly representations**.

### Pipeline

```
Raw HTML
    │
    ▼
Clean & Parse ──► Remove scripts, styles, ads; parse into DOM tree
    │
    ▼
Chunk ──► Split DOM into fragments by structural boundaries
    │
    ▼
Hash ──► Compute structural hash per chunk (for caching)
    │
    ▼
Compress ──► LLM summarizes each chunk (parallel, cached)
    │
    ▼
Build Tree ──► Assemble SemanticNodes into hierarchy
    │
    ▼
Output ──► JSON tree, serialized text, or stats
```

### SemanticTree structure

```go
type SemanticTree struct {
    URL      string
    Title    string
    Domain   string
    RootNodes []SemanticNode
}

type SemanticNode struct {
    ID          string        // Unique node ID
    Summary     string        // LLM-compressed description
    Tag         string        // HTML tag
    TokenCount  int           // Estimated tokens
    IsDynamic   bool          // Contains interactive content?
    Children    []SemanticNode
    Actions     []Action      // Clickable/fillable actions
}
```

### Compression example

| Metric | Value |
|--------|-------|
| Raw HTML | ~500KB |
| Clean HTML | ~200KB |
| Full token count | ~140,000 tokens |
| Compressed tokens | ~18 tokens |
| **Reduction** | **~99.99%** |

### Caching

Semantic extraction uses a **SQLite-backed, content-addressed cache**:
- Each DOM chunk is hashed structurally
- Cache hits reuse previous LLM summaries
- Cache misses trigger API calls (OpenRouter)
- No-LLM fallback available for offline use

### Form extraction

Forms are extracted as structured schemas:

```go
type FormSchema struct {
    Action       string
    Method       string
    Fields       []FormField
    SubmitButton string
}

type FormField struct {
    Name     string
    Type     string  // text, email, password, select, etc.
    Label    string
    Required bool
    Options  []string  // For select/radio
}
```

---

## Layer 4: Agent

The Agent layer models the browser as an **environment** that an AI can interact with. It provides:

- **Observation** — What the agent currently sees (`PageSnapshot`)
- **Action Space** — Every possible move (`ActionSpace`)
- **Execution** — Running chosen actions (`Executor`)
- **Formatting** — Rendering state for LLM consumption (`Formatter`)

### Agent loop

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Observe   │────→│   Format    │────→│   Decide    │────→│   Execute   │
│             │     │             │     │  (LLM/RL)   │     │             │
│ PageSnapshot│     │ LLM prompt  │     │ Action ID   │     │ CDP action  │
└─────────────┘     └─────────────┘     └─────────────┘     └──────┬──────┘
      ↑_____________________________________________________________│
```

### What the agent sees

The `PageSnapshot` includes:
- **Viewport & scroll** — Where we are on the page
- **Interactive elements** — All clickable/fillable elements with IDs, selectors, text, bounds
- **Links** — Navigation graph
- **Forms** — Structured form schemas
- **History** — Actual back/forward URLs and titles
- **Tabs** — All open tabs with URLs and titles
- **Capabilities** — Page features (infinite scroll, lazy load, SPA, etc.)

### What the agent can do

| Category | Actions | Example IDs |
|----------|---------|-------------|
| Element | click, type, select, toggle | `click_E1`, `type_E3` |
| Scroll | down, up, bottom, top, to-element | `scroll_down`, `scroll_to_E5` |
| Navigation | back, forward, reload, navigate | `nav_back`, `navigate` |
| Tab | new, switch, close | `switch_tab_1`, `new_tab` |
| Other | wait, screenshot, done | `wait`, `done` |

### Decision formats

LLMs receive compact prompts:

```
PAGE https://news.ycombinator.com | "Hacker News" | vp=1280x800 | scroll=0/4500(0%)
TABS: 1 open | [0]*Hacker News
[ E1] a "Hacker News" @ 12,15 → click [is_link]
[ E2] a "new" @ 45,15 → click [is_link]
[ E3] input "" @ 450,15 → type [placeholder=search]
SCROLL: scroll_down scroll_down_large scroll_bottom
NAV: nav_back nav_reload navigate
META: wait screenshot done
```

And respond with short action IDs: `click_E1`, `scroll_down`, `done`.

---

## End-to-End Data Flow

Here's what happens when you ask Stealth to extract information from a URL:

### Scenario 1: Simple scrape (no JS, no protection)

```
User: "Extract headlines from https://example.com"

1. Engine: native (fast, no JS needed)
2. Request: GET https://example.com with Chrome-120 profile headers
3. Response: 200 OK, HTML body
4. Semantic: Extract text → SemanticTree → headlines
5. Output: ["Headline 1", "Headline 2", ...]
```

### Scenario 2: Protected site (Cloudflare, JS-rendered)

```
User: "Extract prices from https://protected-shop.com"

1. Engine: native
2. Request: GET https://protected-shop.com
3. Response: 503 "Just a moment..." (Cloudflare JS challenge)
4. Stealth: Detect challenge → Escalate to chromium engine
5. Engine: chromium with full stealth profile
6. Request: Navigate with Chrome-120-macos profile + canvas noise + WebGL spoof
7. Response: Cloudflare JS challenge rendered
8. Challenge Solver: Execute challenge JS → Obtain cf_clearance cookie
9. Request: Re-request with clearance cookie
10. Response: 200 OK, fully rendered HTML
11. Semantic: Extract product prices from DOM
12. Output: [{"name": "Product A", "price": "$99"}, ...]
```

### Scenario 3: Agent-driven research

```
User: "Research: What is NVIDIA's current stock price?"

1. Agent: Observe current page (blank)
2. LLM Decision: "navigate to google.com"
3. Execute: Navigate to Google
4. Agent: Observe Google homepage
5. LLM Decision: "type_E4: NVIDIA stock price" (E4 = search box)
6. Execute: Type query
7. LLM Decision: "click_E7" (E7 = search button)
8. Execute: Click search
9. Agent: Observe search results
10. LLM Decision: "click_E12" (E12 = first relevant link)
11. Execute: Click link
12. Agent: Observe stock page
13. LLM Decision: "add_finding: NVIDIA stock is $875.42"
14. LLM Decision: "done"
15. Output: ResearchReport with answer, sources, confidence
```

---

## Using as a Scraper

### Basic fetch

```go
import (
    "context"
    "github.com/skunkworq/stealth/brws/engine"
    _ "github.com/skunkworq/stealth/brws/browser/engine/http/native"
)

eng, _ := engine.New("native", engine.Options{Stealth: true})
resp, _ := eng.Do(ctx, &engine.Request{URL: "https://example.com"})
fmt.Println(string(resp.Body))
```

### Stealth fetch with challenge solving

```go
import "github.com/skunkworq/stealth/brws/stealth"

client, _ := stealth.NewWithConfig(&stealth.Config{
    EngineName: "chromium",
    Headless:   true,
    Stealth: &stealth.StealthConfig{
        Enabled:         true,
        RemoveWebDriver: true,
        CanvasNoise:     true,
        WebGLSpoof:      true,
    },
})

resp, _ := client.Fetch(ctx, "https://protected-site.com")
fmt.Println(string(resp.Body))
```

### Semantic extraction

```go
import "github.com/skunkworq/stealth/brws/semantic"

tree, stats, _ := semantic.HTMLToSemanticTreeCached(ctx, html, url, config)
fmt.Printf("Compressed from %d to %d tokens\n", stats.FullTokens, stats.CompressedTokens)
for _, node := range tree.RootNodes {
    fmt.Println(node.Summary)
}
```

### Structured scraping with the agent observer

```go
import "github.com/skunkworq/stealth/brws/agent"

ctx, cancel := chromedp.NewContext(context.Background())
defer cancel()
chromedp.Run(ctx, chromedp.Navigate("https://news.ycombinator.com"))

obs := agent.DefaultObserver()
snap, _ := obs.Observe(ctx)

// Extract all links
for _, link := range snap.Links {
    fmt.Printf("- %s → %s\n", link.Text, link.Href)
}

// Extract all forms
for _, form := range snap.Forms {
    fmt.Printf("Form: %s %s\n", form.Method, form.Action)
}

// Extract interactive elements
for _, elem := range snap.Elements {
    fmt.Printf("[%s] <%s> %q @ (%.0f, %.0f)\n",
        elem.ID, elem.Tag, elem.Text, elem.Bounds.X, elem.Bounds.Y)
}
```

---

## Using as an Agent

### Go: Direct agent loop

```go
import (
    "github.com/chromedp/chromedp"
    "github.com/skunkworq/stealth/brws/agent"
)

ctx, cancel := chromedp.NewContext(context.Background())
defer cancel()

a := agent.NewAgent(agent.DefaultConfig(), nil, nil, nil)

for i := 0; i < 20; i++ {
    // 1. Observe
    pageCtx, actions, formatted, _ := a.Observe(ctx)

    // 2. Send to LLM (replace with real API call)
    actionID := callLLM(formatted)

    // 3. Execute
    act := pageCtx.ActionSpace.Find(actionID)
    if act == nil { break }
    res, _ := a.Execute(ctx, *act)

    fmt.Printf("Step %d: %s → success=%v\n", i, actionID, res.Success)
    if actionID == "done" { break }
}
```

### Python: Pydantic AI research agent

```python
from dataclasses import dataclass, field
from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext
from pybrwslab import Agent as BrowserAgent

class ResearchReport(BaseModel):
    query: str
    findings: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    answer: str
    confidence: str

@dataclass
class Deps:
    browser: BrowserAgent
    visited: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)

agent = Agent(
    model="openai:gpt-4o",
    system_prompt="You are a web researcher...",
    result_type=ResearchReport,
    deps_type=Deps,
)

@agent.tool
async def search(ctx: RunContext[Deps], query: str) -> str:
    url = "https://html.duckduckgo.com/html/?q=" + query.replace(" ", "+")
    page = ctx.deps.browser.observe(url, format="compact")
    ctx.deps.visited.append(page["snapshot"]["url"])
    return page["formatted"]

@agent.tool
async def click(ctx: RunContext[Deps], action_id: str) -> str:
    result = ctx.deps.browser.step("", decision=action_id, format="compact")
    return result["observation"]["formatted"]

@agent.tool
async def add_finding(ctx: RunContext[Deps], fact: str) -> str:
    ctx.deps.findings.append(fact)
    return f"Recorded: {fact}"

@agent.tool
async def finish(ctx: RunContext[Deps], answer: str, confidence: str) -> ResearchReport:
    return ResearchReport(
        query="",
        findings=ctx.deps.findings,
        sources=list(dict.fromkeys(ctx.deps.visited)),
        answer=answer,
        confidence=confidence,
    )

# Run
browser = BrowserAgent(session_dir="/tmp/research")
result = await agent.run("NVIDIA stock price", deps=Deps(browser=browser))
print(result.data.answer)
browser.stop()
```

---

## Python Integration

All Go functionality is exposed to Python via CLI wrappers in `python/pybrwslab/`:

| Python Class | Go Binary | What it does |
|-------------|-----------|-------------|
| `Stealth` | `cmd/stealth` | Fetch, crawl, spider, lab, train |
| `Semantic` | `cmd/semantic` | Extract semantic trees from URLs |
| `Agent` | `cmd/agent` | Multi-step browser automation with persistent Chrome |
| `Brwslab` | `cmd/brwslab` | Network fingerprint testing, diff, trace |
| `Labd` | `cmd/labd` | Start/stop fingerprint capture lab |

All classes follow the same pattern:

```python
from pybrwslab import Stealth, Semantic, Agent

# Fetch with stealth
st = Stealth()
result = st.fetch("https://example.com", engine="chromium-stealth")

# Extract semantic tree
sem = Semantic()
tree = sem.extract("https://example.com", format="json")
print(tree.title)

# Agent-driven browsing
agent = Agent(session_dir="/tmp/session")
ctx = agent.observe("https://example.com")
print(ctx["formatted"])
agent.stop()
```

---

## Lab & Training System

The **Fingerprint Capture Lab** is a local testbed for researching browser fingerprints:

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Chrome    │────→│ MITM Proxy  │────→│ Lab Server  │
│  (CDP)      │     │ (TLS sniff) │     │ (capture)   │
└─────────────┘     └─────────────┘     └─────────────┘
```

**What it captures:**
- TLS ClientHello (cipher suites, extensions, GREASE)
- HTTP/2 frame sequences (settings, window updates, priority)
- HTTP header order and values
- CDP network events (exact request/response pairs)
- Behavioral timing patterns

**Uses:**
- Train ML models on real browser signatures
- Validate stealth configs against human baselines
- Build trace libraries for replay-based challenge solving
- Generate fingerprint diffs across engines

```bash
# Start lab server
stealth lab --chrome --port 8080

# Automated capture session
stealth train --urls https://google.com,https://github.com --output training-data/
```

---

## CLI Tools Reference

| Tool | File | Purpose |
|------|------|---------|
| `stealth` | `cmd/stealth` | Main CLI — fetch, crawl, spider, lab, train, shell |
| `brwslab` | `cmd/brwslab` | Network fidelity — fingerprint, diff, trace, session |
| `semantic` | `cmd/semantic` | Extract semantic trees from URLs |
| `semantic-server` | `cmd/semantic-server` | HTTP API for semantic extraction |
| `semantic-mcp` | `cmd/semantic-mcp` | MCP server for Claude Desktop |
| `semanticcrawl` | `cmd/semanticcrawl` | Semantic crawler with LLM extraction |
| `stealth-mcp` | `cmd/stealth-mcp` | MCP server for stealth operations |
| `labd` | `cmd/labd` | Fingerprint lab daemon |
| `agent` | `cmd/agent` | Browser automation — observe, execute, step |
| `extract` | `cmd/extract` | Structured content extraction CLI |
| `train` | `cmd/train` | ML training data generation |
| `ml_datagen` | `cmd/ml_datagen` | ML dataset generation |
| `benchmark` | `cmd/benchmark` | Performance benchmarks |
| `evalbench` | `cmd/evalbench` | Evaluation suite |
| `eval_e2e` | `cmd/eval_e2e` | End-to-end evaluation |
| `vecbench` | `cmd/vecbench` | Vector/benchmark tooling |
| `scanciphers` | `cmd/scanciphers` | TLS cipher scanner |
| `crawl` | `cmd/crawl` | Standalone crawler |
| `pipeline` | `cmd/pipeline` | Processing pipeline |
| `test_realworld` | `cmd/test_realworld` | Real-world integration tests |
| `test_semantic` | `cmd/test_semantic` | Semantic pipeline tests |
| `gencert` | `cmd/gencert` | TLS cert generation for MITM |

---

## Summary

**Stealth is five layers that work together:**

1. **Engine** — Abstracts HTTP clients and browsers. Pick `native` for speed, `chromium` for JS.
2. **Stealth** — Makes you invisible. TLS spoofing, behavioral simulation, challenge solving, RL adaptation.
3. **Semantic** — Makes content useful. Compresses HTML into structured trees for LLMs.
4. **Agent** — Makes browsing autonomous. Observes pages, enumerates actions, executes decisions.
5. **Agentic** — Makes scraping programmable. Composes LLM-driven nodes into directed graphs for structured extraction.

**Use it as a scraper** when you need structured data from the web.
**Use it as an agent** when you need an AI to browse, decide, and complete tasks.
**Use it as an agentic pipeline** when you need LLM-driven graph execution for multi-URL research.

All paths share the same foundation: real browser fingerprints, adaptive anti-detection, and clean data extraction.
