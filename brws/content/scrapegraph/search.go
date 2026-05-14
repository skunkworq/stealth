package scrapegraph

import (
	"context"
	"fmt"
	"strings"
	"time"

	agent "github.com/skunkworq/stealth/brws/content/agent"
	"github.com/skunkworq/stealth/brws/stealth"
)

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

// SearchConfig configures a web search task.
type SearchConfig struct {
	// Domain to search (e.g. "amazon.com"). Scheme is optional.
	Domain string
	// Query is the search term (e.g. "laptop under $500").
	Query string
	// LLM drives all decisions. If nil, NewLLMFromEnv() is used.
	LLM LLM
	// MaxSteps caps the number of agent steps before extracting whatever is on
	// screen. Default: 20.
	MaxSteps int
	// StealthClient provides anti-bot handling and tab management. Required.
	StealthClient *stealth.Adaptive
	// AgentConfig overrides default agent settings (optional).
	AgentConfig *agent.Config
}

// ResultItem is one search result extracted from the results page.
type ResultItem struct {
	Title   string `json:"title"`
	URL     string `json:"url,omitempty"`
	Snippet string `json:"snippet,omitempty"`
	Price   string `json:"price,omitempty"`
}

// SearchResult is returned by SearchCoordinator.Run.
type SearchResult struct {
	Query    string       `json:"query"`
	Domain   string       `json:"domain"`
	Items    []ResultItem `json:"items"`
	FinalURL string       `json:"final_url"`
	Steps    int          `json:"steps"`
}

// ---------------------------------------------------------------------------
// SearchCoordinator
// ---------------------------------------------------------------------------

// SearchCoordinator runs a goal-directed observe→decide→execute loop that
// finds and submits a search form on a target domain, then extracts results.
type SearchCoordinator struct {
	cfg SearchConfig
	llm LLM
	ag  *agent.Agent
}

// NewSearchCoordinator constructs a coordinator from the given config.
// Returns an error if a required field is missing or the LLM cannot be built.
func NewSearchCoordinator(cfg SearchConfig) (*SearchCoordinator, error) {
	if cfg.Domain == "" {
		return nil, fmt.Errorf("SearchConfig.Domain is required")
	}
	if cfg.Query == "" {
		return nil, fmt.Errorf("SearchConfig.Query is required")
	}
	if cfg.StealthClient == nil {
		return nil, fmt.Errorf("SearchConfig.StealthClient is required")
	}

	llm := cfg.LLM
	if llm == nil {
		var err error
		llm, err = NewLLMFromEnv()
		if err != nil {
			return nil, fmt.Errorf("no LLM configured and OPENROUTER_API_KEY not set: %w", err)
		}
	}

	if cfg.MaxSteps <= 0 {
		cfg.MaxSteps = 20
	}

	agCfg := agent.DefaultConfig()
	if cfg.AgentConfig != nil {
		agCfg = *cfg.AgentConfig
	}
	agCfg.StealthClient = cfg.StealthClient
	agCfg.StealthMode = true
	agCfg.IncludeForms = true

	ag := agent.NewAgent(agCfg, nil, nil, nil)

	return &SearchCoordinator{cfg: cfg, llm: llm, ag: ag}, nil
}

// Run navigates to the domain, searches for the configured query, and returns
// the extracted results. The caller's context controls overall timeout.
func (sc *SearchCoordinator) Run(ctx context.Context) (*SearchResult, error) {
	startURL := normaliseURL(sc.cfg.Domain)

	tabCtx, tabCancel, err := sc.ag.NewStealthTab(ctx, startURL)
	if err != nil {
		return nil, fmt.Errorf("open tab on %s: %w", startURL, err)
	}
	defer tabCancel()

	decideFn := sc.buildDecideFn(ctx)

	for step := 0; step < sc.cfg.MaxSteps; step++ {
		s, stepErr := sc.ag.Step(tabCtx, decideFn)
		if stepErr != nil {
			// Non-fatal: the page may still have usable content.
			sc.cfg.StealthClient.Logger().Warn("agent step error", "step", step+1, "error", stepErr)
		}
		if s != nil && s.Decision.Type == agent.ActionNone {
			// LLM signalled it's done.
			break
		}
		time.Sleep(300 * time.Millisecond)
	}

	pageCtx := sc.ag.LastContext()
	finalURL := ""
	if pageCtx != nil && pageCtx.Snapshot != nil {
		finalURL = pageCtx.Snapshot.URL
	}

	items, err := sc.extractResults(ctx, pageCtx)
	if err != nil {
		return nil, fmt.Errorf("extract results: %w", err)
	}

	return &SearchResult{
		Query:    sc.cfg.Query,
		Domain:   sc.cfg.Domain,
		Items:    items,
		FinalURL: finalURL,
		Steps:    len(sc.ag.History()),
	}, nil
}

// ---------------------------------------------------------------------------
// decideFn — LLM-driven action selection
// ---------------------------------------------------------------------------

// decideResponse is the JSON shape the LLM returns for each step.
type decideResponse struct {
	ActionID string `json:"action_id"`
	Text     string `json:"text,omitempty"` // filled for ActionTypeText
	URL      string `json:"url,omitempty"`  // filled for ActionNavigate
	Reason   string `json:"reason"`
}

// buildDecideFn returns the callback that Agent.Step() calls on every cycle.
// ctx is the caller's context (not the chromedp tab context).
func (sc *SearchCoordinator) buildDecideFn(ctx context.Context) func(*agent.Context, []agent.Action, string, []agent.Step) (agent.Action, error) {
	return func(pageCtx *agent.Context, actions []agent.Action, formatted string, history []agent.Step) (agent.Action, error) {
		actionList := formatActionList(actions)
		histSummary := formatHistorySummary(history)

		userPrompt := fmt.Sprintf(
			"SEARCH TASK: find %q on %s\n\nCURRENT PAGE:\n%s\n\nAVAILABLE ACTIONS:\n%s\nRECENT HISTORY:\n%s",
			sc.cfg.Query, sc.cfg.Domain, formatted, actionList, histSummary,
		)

		var resp decideResponse
		if err := sc.llm.CompleteJSON(ctx, buildSearchSystemPrompt(sc.cfg.Query, sc.cfg.Domain), userPrompt, &resp); err != nil {
			return agent.Action{Type: agent.ActionNone}, fmt.Errorf("LLM decision: %w", err)
		}

		return resolveAction(actions, pageCtx, resp), nil
	}
}

// resolveAction finds the action chosen by the LLM, injects its parameters
// (selector from snapshot, text/url from the LLM response), and returns it.
func resolveAction(actions []agent.Action, pageCtx *agent.Context, resp decideResponse) agent.Action {
	for _, a := range actions {
		if a.ID != resp.ActionID {
			continue
		}

		if a.Parameters == nil {
			a.Parameters = make(map[string]interface{})
		}

		// The DOM action space builder does not populate "selector" in
		// Parameters (only TargetID is set). Look it up from the snapshot
		// so the executor can find the element.
		if _, ok := a.Parameters["selector"]; !ok && a.TargetID != "" && pageCtx != nil && pageCtx.Snapshot != nil {
			for _, elem := range pageCtx.Snapshot.Elements {
				if elem.ID == a.TargetID {
					a.Parameters["selector"] = elem.Selector
					break
				}
			}
		}

		if resp.Text != "" {
			a.Parameters["text"] = resp.Text
		}
		if resp.URL != "" {
			a.Parameters["url"] = resp.URL
		}

		return a
	}

	// Unknown action ID — treat as done rather than looping forever.
	return agent.Action{ID: "done", Type: agent.ActionNone}
}

// ---------------------------------------------------------------------------
// Result extractor
// ---------------------------------------------------------------------------

// extractResults sends the final page state to the LLM and asks it to pull
// out structured search results.
func (sc *SearchCoordinator) extractResults(ctx context.Context, pageCtx *agent.Context) ([]ResultItem, error) {
	if pageCtx == nil || pageCtx.Snapshot == nil {
		return nil, fmt.Errorf("no page context available for extraction")
	}

	snap := pageCtx.Snapshot

	var content strings.Builder
	content.WriteString(fmt.Sprintf("URL: %s\nTitle: %s\n\n", snap.URL, snap.Title))

	// Element text (capped to avoid token blowout).
	content.WriteString("VISIBLE ELEMENTS:\n")
	for i, elem := range snap.Elements {
		if i >= 150 {
			break
		}
		if elem.Text != "" {
			content.WriteString(fmt.Sprintf("[%s] %s\n", elem.Tag, elem.Text))
		}
	}

	// Links are the richest signal for result extraction.
	if len(snap.Links) > 0 {
		content.WriteString("\nLINKS:\n")
		for i, link := range snap.Links {
			if i >= 100 {
				break
			}
			if link.Text != "" {
				content.WriteString(fmt.Sprintf("- %s → %s\n", link.Text, link.Href))
			}
		}
	}

	userPrompt := fmt.Sprintf("Original query: %q\n\n%s", sc.cfg.Query, content.String())

	var result struct {
		Items []ResultItem `json:"items"`
	}
	if err := sc.llm.CompleteJSON(ctx, extractSystemPrompt, userPrompt, &result); err != nil {
		return nil, err
	}

	return result.Items, nil
}

// ---------------------------------------------------------------------------
// Prompts
// ---------------------------------------------------------------------------

func buildSearchSystemPrompt(query, domain string) string {
	return fmt.Sprintf(`You are a browser automation agent. Your task: find search results for %q on %s.

DECISION RULES (apply in order):
1. If a CAPTCHA or anti-bot challenge is visible → choose action "solve_challenge".
2. If a search input is visible (input[type=search], input with placeholder containing "search"/"find"/"query", or a visible text box near a search button) and the query has NOT been typed yet → choose the type action for that input and provide "text".
3. If the query is typed and a submit button / search icon is visible → click it.
4. If results matching the query are already visible on the page → choose action "done".
5. If no search box is visible but there is a search icon or nav link → click it.
6. If completely stuck after scrolling, navigate directly: {"action_id":"navigate","url":"https://%s/search?q=%s"}.
7. Never repeat the exact same action twice consecutively.

Respond with valid JSON only. No markdown. Use one of these shapes:
{"action_id":"<id>","reason":"<why>"}
{"action_id":"<type_id>","text":"<search query>","reason":"<why>"}
{"action_id":"navigate","url":"<full url>","reason":"<why>"}
{"action_id":"done","reason":"results are visible"}`,
		query, domain, domain, query)
}

const extractSystemPrompt = `You are a web scraper. Extract search results from the page content below.

Return a JSON object: {"items": [...]}
Each item: {"title": "...", "url": "...", "snippet": "...", "price": "..."}
- title: required. The result heading or product name.
- url: the result link (full URL preferred).
- snippet: a short description or excerpt (optional).
- price: only if the result has a price (optional).

Include only results relevant to the query. Maximum 20 items.
Output valid JSON only. No markdown.`

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func normaliseURL(domain string) string {
	if strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://") {
		return domain
	}
	return "https://" + domain
}

// formatActionList renders actions as a compact numbered list for the LLM.
func formatActionList(actions []agent.Action) string {
	var b strings.Builder
	for _, a := range actions {
		line := fmt.Sprintf("  %-40s %s", a.ID+":", a.Description)
		switch a.Type {
		case agent.ActionTypeText:
			line += " [provide: text]"
		case agent.ActionNavigate:
			line += " [provide: url]"
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

// formatHistorySummary returns a compact summary of the last 5 steps.
func formatHistorySummary(history []agent.Step) string {
	if len(history) == 0 {
		return "  (none yet)\n"
	}
	n := 5
	if len(history) < n {
		n = len(history)
	}
	recent := history[len(history)-n:]
	var b strings.Builder
	for i, s := range recent {
		status := "ok"
		if s.Result != nil && !s.Result.Success {
			status = "FAIL: " + s.Result.Error
		}
		b.WriteString(fmt.Sprintf("  %d. %s (%s) → %s\n",
			len(history)-n+i+1, s.Decision.ID, s.Decision.Type, status))
	}
	return b.String()
}
