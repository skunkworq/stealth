package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/chromedp/chromedp"

	"github.com/skunkworq/stealth/brws/content/agent"
	"github.com/skunkworq/stealth/brws/stealth"
)

// ---------------------------------------------------------------------------
// observe
// ---------------------------------------------------------------------------

func runObserve(args []string) error {
	fs := flag.NewFlagSet("observe", flag.ExitOnError)
	url := fs.String("url", "", "URL to navigate to and observe (required)")
	format := fs.String("format", "compact", "Output format: compact, markdown, json, semantic")
	maxElements := fs.Int("max-elements", 50, "Max interactive elements to capture")
	semanticFlag := fs.Bool("semantic", false, "Enable semantic enrichment (tree, meta, images, etc.)")
	semanticLLM := fs.Bool("semantic-llm", false, "Use LLM for richer semantic tree (requires OPENROUTER_API_KEY)")
	describeImages := fs.Bool("describe-images", false, "Describe images via vision API (requires OPENROUTER_API_KEY)")
	representation := fs.String("representation", "dom", "Primary representation: dom or semantic")
	stealthFlag := fs.Bool("stealth", false, "Use stealth client for challenge-aware navigation")
	cf, err := parseCommonFlags(fs, args)
	if err != nil {
		return err
	}
	if *url == "" {
		return fmt.Errorf("--url is required")
	}
	rep := agent.RepresentationDOM
	if *representation == "semantic" {
		rep = agent.RepresentationSemantic
	}

	ctx, cancel, sc, err := ensureAgentSession(cf.SessionDir, cf.ChromePath, *stealthFlag)
	if err != nil {
		return err
	}
	defer cancel()

	// Navigate if URL changed from last state
	lastURL := readLastURL(cf.SessionDir)
	if lastURL != *url {
		if sc != nil {
			// Use stealth client for challenge-aware navigation
			if _, err := sc.Navigate(ctx, *url); err != nil {
				return fmt.Errorf("stealth navigate to %s: %w", *url, err)
			}
		}
		if err := chromedp.Run(ctx, chromedp.Navigate(*url)); err != nil {
			return fmt.Errorf("navigating to %s: %w", *url, err)
		}
	}

	// Observe
	obs := agent.DefaultObserver()
	obs.MaxElements = *maxElements
	obs.MaxTextLen = 120
	if *semanticFlag {
		obs.SemanticEnhancer = &agent.SemanticEnhancer{
			EnableTree:     true,
			EnableTreeLLM:  *semanticLLM,
			EnableMeta:     true,
			EnableImages:   true,
			EnableSocial:   true,
			EnableColors:   true,
			EnableFonts:    true,
			DescribeImages: *describeImages,
		}
	}
	snap, err := obs.Observe(ctx)
	if err != nil {
		return fmt.Errorf("observing: %w", err)
	}

	// Build context with both action spaces
	agCtx := agent.NewContext(snap)
	if snap.SemanticTree != nil {
		agCtx.SemanticActionSpace = agent.BuildSemanticActionSpace(snap)
	}
	agCtx.Representation = rep

	// Choose active action space
	actionSpace := agCtx.ActionSpace
	if rep == agent.RepresentationSemantic && agCtx.SemanticActionSpace != nil {
		actionSpace = agCtx.SemanticActionSpace
	}

	// Format
	var formatted string
	fmttr := agent.DefaultFormatter()
	fmttr.Representation = rep
	if *semanticFlag {
		fmttr.IncludeMeta = true
		fmttr.IncludeImages = true
		fmttr.IncludeSemanticTree = true
	}
	switch *format {
	case "markdown":
		formatted = fmttr.Format(agCtx)
	case "json":
		formatted = fmttr.FormatJSON(agCtx)
	case "semantic":
		formatted = fmttr.FormatSemanticCompact(agCtx)
	default:
		if rep == agent.RepresentationSemantic {
			formatted = fmttr.FormatSemanticCompact(agCtx)
		} else {
			formatted = fmttr.FormatCompact(agCtx)
		}
	}

	// Save state
	if err := saveState(cf.SessionDir, snap.URL); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}

	// Output
	out := map[string]interface{}{
		"snapshot":       snap,
		"action_space":   actionSpace,
		"formatted":      formatted,
		"representation": string(rep),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// ---------------------------------------------------------------------------
// execute
// ---------------------------------------------------------------------------

func runExecute(args []string) error {
	fs := flag.NewFlagSet("execute", flag.ExitOnError)
	actionJSON := fs.String("action", "", "Action JSON to execute (required)")
	stealthFlag := fs.Bool("stealth", false, "Use stealth client for challenge-aware execution")
	cf, err := parseCommonFlags(fs, args)
	if err != nil {
		return err
	}
	if *actionJSON == "" {
		return fmt.Errorf("--action is required")
	}

	var act agent.Action
	if err := json.Unmarshal([]byte(*actionJSON), &act); err != nil {
		return fmt.Errorf("parsing action JSON: %w", err)
	}

	ctx, cancel, sc, err := ensureAgentSession(cf.SessionDir, cf.ChromePath, *stealthFlag)
	if err != nil {
		return err
	}
	defer cancel()

	exec := &agent.Executor{}
	if sc != nil {
		exec.StealthClient = sc
	}
	res, err := exec.Execute(ctx, act)
	if err != nil {
		// Still output the result even on error
		_ = outputResult(res)
		return fmt.Errorf("executing action: %w", err)
	}

	return outputResult(res)
}

// ---------------------------------------------------------------------------
// step
// ---------------------------------------------------------------------------

func runStep(args []string) error {
	fs := flag.NewFlagSet("step", flag.ExitOnError)
	url := fs.String("url", "", "URL to navigate to (required)")
	decision := fs.String("decision", "", "Action ID to execute after observation (optional)")
	format := fs.String("format", "compact", "Output format: compact, markdown, json, semantic")
	maxElements := fs.Int("max-elements", 50, "Max interactive elements to capture")
	semanticFlag := fs.Bool("semantic", false, "Enable semantic enrichment (tree, meta, images, etc.)")
	semanticLLM := fs.Bool("semantic-llm", false, "Use LLM for richer semantic tree (requires OPENROUTER_API_KEY)")
	describeImages := fs.Bool("describe-images", false, "Describe images via vision API (requires OPENROUTER_API_KEY)")
	representation := fs.String("representation", "dom", "Primary representation: dom or semantic")
	stealthFlag := fs.Bool("stealth", false, "Use stealth client for challenge-aware navigation")
	cf, err := parseCommonFlags(fs, args)
	if err != nil {
		return err
	}
	if *url == "" {
		return fmt.Errorf("--url is required")
	}
	rep := agent.RepresentationDOM
	if *representation == "semantic" {
		rep = agent.RepresentationSemantic
	}

	ctx, cancel, sc, err := ensureAgentSession(cf.SessionDir, cf.ChromePath, *stealthFlag)
	if err != nil {
		return err
	}
	defer cancel()

	// Navigate if URL changed
	lastURL := readLastURL(cf.SessionDir)
	if lastURL != *url {
		if sc != nil {
			if _, err := sc.Navigate(ctx, *url); err != nil {
				return fmt.Errorf("stealth navigate to %s: %w", *url, err)
			}
		}
		if err := chromedp.Run(ctx, chromedp.Navigate(*url)); err != nil {
			return fmt.Errorf("navigating to %s: %w", *url, err)
		}
	}

	// Observe
	obs := agent.DefaultObserver()
	obs.MaxElements = *maxElements
	obs.MaxTextLen = 120
	if *semanticFlag {
		obs.SemanticEnhancer = &agent.SemanticEnhancer{
			EnableTree:     true,
			EnableTreeLLM:  *semanticLLM,
			EnableMeta:     true,
			EnableImages:   true,
			EnableSocial:   true,
			EnableColors:   true,
			EnableFonts:    true,
			DescribeImages: *describeImages,
		}
	}
	snap, err := obs.Observe(ctx)
	if err != nil {
		return fmt.Errorf("observing: %w", err)
	}

	// Build context with both action spaces
	agCtx := agent.NewContext(snap)
	if snap.SemanticTree != nil {
		agCtx.SemanticActionSpace = agent.BuildSemanticActionSpace(snap)
	}
	agCtx.Representation = rep

	// Choose active action space
	actionSpace := agCtx.ActionSpace
	if rep == agent.RepresentationSemantic && agCtx.SemanticActionSpace != nil {
		actionSpace = agCtx.SemanticActionSpace
	}

	// Format
	var formatted string
	fmttr := agent.DefaultFormatter()
	fmttr.Representation = rep
	if *semanticFlag {
		fmttr.IncludeMeta = true
		fmttr.IncludeImages = true
		fmttr.IncludeSemanticTree = true
	}
	switch *format {
	case "markdown":
		formatted = fmttr.Format(agCtx)
	case "json":
		formatted = fmttr.FormatJSON(agCtx)
	case "semantic":
		formatted = fmttr.FormatSemanticCompact(agCtx)
	default:
		if rep == agent.RepresentationSemantic {
			formatted = fmttr.FormatSemanticCompact(agCtx)
		} else {
			formatted = fmttr.FormatCompact(agCtx)
		}
	}

	// Save state
	_ = saveState(cf.SessionDir, snap.URL)

	// Optionally execute decision
	var result *agent.ExecuteResult
	if *decision != "" {
		found := actionSpace.Find(*decision)
		if found == nil {
			return fmt.Errorf("action %q not found in action space", *decision)
		}
		exec := &agent.Executor{}
		if sc != nil {
			exec.StealthClient = sc
		}
		res, execErr := exec.Execute(ctx, *found)
		result = res
		if execErr != nil {
			_ = outputStep(snap, actionSpace, formatted, result, rep)
			return fmt.Errorf("executing %s: %w", *decision, execErr)
		}
		// Re-observe after execution for up-to-date state
		newSnap, obsErr := obs.Observe(ctx)
		if obsErr == nil {
			snap = newSnap
			agCtx = agent.NewContext(snap)
			if snap.SemanticTree != nil {
				agCtx.SemanticActionSpace = agent.BuildSemanticActionSpace(snap)
			}
			agCtx.Representation = rep
			actionSpace = agCtx.ActionSpace
			if rep == agent.RepresentationSemantic && agCtx.SemanticActionSpace != nil {
				actionSpace = agCtx.SemanticActionSpace
			}
			if rep == agent.RepresentationSemantic {
				formatted = fmttr.FormatSemanticCompact(agCtx)
			} else {
				formatted = fmttr.FormatCompact(agCtx)
			}
		}
		_ = saveState(cf.SessionDir, snap.URL)
	}

	return outputStep(snap, actionSpace, formatted, result, rep)
}

// ---------------------------------------------------------------------------
// session-stop
// ---------------------------------------------------------------------------

func runSessionStop(args []string) error {
	fs := flag.NewFlagSet("session-stop", flag.ExitOnError)
	cf, err := parseCommonFlags(fs, args)
	if err != nil {
		return err
	}
	if err := stopSession(cf.SessionDir); err != nil {
		return err
	}
	fmt.Println(`{"stopped": true}`)
	return nil
}

// ---------------------------------------------------------------------------
// State persistence helpers
// ---------------------------------------------------------------------------

type sessionState struct {
	LastURL string `json:"last_url"`
}

func readLastURL(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		return ""
	}
	var st sessionState
	_ = json.Unmarshal(data, &st)
	return st.LastURL
}

func saveState(dir, url string) error {
	st := sessionState{LastURL: url}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "state.json"), data, 0644)
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

func outputResult(res *agent.ExecuteResult) error {
	out := map[string]interface{}{
		"success":          res != nil && res.Success,
		"action_id":        "",
		"new_url":          "",
		"scroll_delta":     0,
		"challenge_solved": false,
		"error":            "",
	}
	if res != nil {
		out["action_id"] = res.ActionID
		out["new_url"] = res.NewURL
		out["scroll_delta"] = res.ScrollDelta
		out["challenge_solved"] = res.ChallengeSolved
		if !res.Success {
			out["error"] = res.Error
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func outputStep(snap *agent.PageSnapshot, as *agent.ActionSpace, formatted string, result *agent.ExecuteResult, rep agent.Representation) error {
	out := map[string]interface{}{
		"observation": map[string]interface{}{
			"snapshot":       snap,
			"action_space":   as,
			"formatted":      formatted,
			"representation": string(rep),
		},
		"result": result,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// ensureAgentSession returns a chromedp context and optionally a stealth client.
// When stealth is enabled, it creates a stealth client and a persistent tab from
// its browser instance. Otherwise, it falls back to the standard session manager.
func ensureAgentSession(dir, chromePath string, useStealth bool) (context.Context, context.CancelFunc, *stealth.Client, error) {
	if !useStealth {
		ctx, cancel, err := ensureSession(dir, chromePath)
		return ctx, cancel, nil, err
	}

	// Stealth mode: create a stealth client with default config
	cfg := *stealth.DefaultConfig()
	if chromePath != "" {
		// The stealth client doesn't accept chrome path directly,
		// but we can set it via environment or accept the default discovery
	}
	sc, err := stealth.NewClient(cfg)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating stealth client: %w", err)
	}

	// Create a persistent tab from the stealth browser
	tabCtx, tabCancel, ok := sc.NewTab()
	if !ok {
		sc.Close()
		return nil, nil, nil, fmt.Errorf("stealth client does not support persistent tabs")
	}

	// Combined cancel that cleans up both tab and stealth client
	combinedCancel := func() {
		tabCancel()
		sc.Close()
	}

	return tabCtx, combinedCancel, sc, nil
}
