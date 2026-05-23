// Package agent — Observation Layer
//
// The observer extracts a PageSnapshot from a live browser tab via CDP.
// It is intentionally separate from action enumeration and formatting so that
// observation strategies can be swapped (e.g. headless vs headed, cached vs live).
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"

	"github.com/skunkworq/stealth/brws/content/understand"
)

// Observer extracts PageSnapshots from a live browser context.
type Observer struct {
	// MaxElements caps the number of visible elements returned.
	// Zero means unlimited.
	MaxElements int

	// MaxTextLen caps the text content per element.
	MaxTextLen int

	// SemanticEnhancer optionally enriches snapshots with semantic metadata.
	// If nil, no semantic enrichment is performed.
	SemanticEnhancer *SemanticEnhancer
}

// DefaultObserver returns an observer with sensible limits for LLM context.
func DefaultObserver() *Observer {
	return &Observer{
		MaxElements: 50,
		MaxTextLen:  120,
	}
}

// Observe captures a full PageSnapshot from a chromedp context.
func (o *Observer) Observe(ctx context.Context) (*PageSnapshot, error) {
	snap := &PageSnapshot{}

	// 1. Basic page info
	if err := chromedp.Run(ctx,
		chromedp.Location(&snap.URL),
		chromedp.Title(&snap.Title),
	); err != nil {
		return nil, fmt.Errorf("location/title: %w", err)
	}

	// 2. Layout metrics (viewport + document size)
	_, _, _, cssLayoutViewport, _, cssContentSize, err := page.GetLayoutMetrics().Do(ctx)
	if err != nil {
		return nil, fmt.Errorf("layout metrics: %w", err)
	}
	if cssLayoutViewport != nil {
		snap.Viewport = Viewport{
			Width:  float64(cssLayoutViewport.ClientWidth),
			Height: float64(cssLayoutViewport.ClientHeight),
		}
	}
	if cssContentSize != nil {
		snap.DocumentSize = DocumentSize{
			Width:  float64(cssContentSize.Width),
			Height: float64(cssContentSize.Height),
		}
	}

	// 3. Scroll position & document height
	scrollJS := `
	(function() {
		return {
			x: window.scrollX,
			y: window.scrollY,
			docHeight: document.documentElement.scrollHeight,
			viewportHeight: window.innerHeight
		};
	})();`
	var scrollResult map[string]interface{}
	if err := chromedp.Run(ctx, chromedp.Evaluate(scrollJS, &scrollResult)); err != nil {
		return nil, fmt.Errorf("scroll eval: %w", err)
	}
	snap.Scroll = parseScrollState(scrollResult, snap.Viewport.Height)

	// 4. History state via CDP (accurate back/forward entries)
	snap.History = o.queryHistory(ctx)

	// 5. Tabs
	snap.Tabs = o.queryTabs(ctx)

	// 6. Interactive elements
	elems, err := o.queryInteractiveElements(ctx)
	if err != nil {
		return nil, fmt.Errorf("interactive elements: %w", err)
	}
	snap.Elements = elems

	// 7. Links
	links, err := o.queryLinks(ctx)
	if err != nil {
		return nil, fmt.Errorf("links: %w", err)
	}
	snap.Links = links

	// 8. Forms (extract from outerHTML)
	var html string
	if err := chromedp.Run(ctx, chromedp.OuterHTML("html", &html)); err == nil {
		snap.Forms = understand.ExtractFormSchemas(html)
	}

	// 9. Challenge detection
	if html != "" {
		if chType := detectPageChallenge(html); chType != "" {
			snap.ChallengeDetected = true
			snap.ChallengeType = chType
		}
	}

	// 10. Semantic enrichment (optional)
	if o.SemanticEnhancer != nil && html != "" {
		_ = o.SemanticEnhancer.Enhance(ctx, snap, html, snap.URL)
	}

	snap.Timestamp = time.Now()
	return snap, nil
}

// queryHistory uses CDP Page.getNavigationHistory for accurate history entries.
func (o *Observer) queryHistory(ctx context.Context) HistoryState {
	currentIndex, entries, err := page.GetNavigationHistory().Do(ctx)
	if err != nil || entries == nil {
		return HistoryState{}
	}
	histEntries := make([]HistoryEntry, 0, len(entries))
	for _, e := range entries {
		histEntries = append(histEntries, HistoryEntry{
			URL:   e.URL,
			Title: e.Title,
		})
	}
	canBack := currentIndex > 0
	canForward := currentIndex < int64(len(entries))-1
	return HistoryState{
		Length:       len(entries),
		CurrentIndex: int(currentIndex),
		CanGoBack:    canBack,
		CanGoForward: canForward,
		Entries:      histEntries,
	}
}

// queryTabs lists all open browser tabs via CDP target.getTargets.
func (o *Observer) queryTabs(ctx context.Context) []TabState {
	infos, err := target.GetTargets().Do(ctx)
	if err != nil {
		return nil
	}

	// Determine which tab is currently active
	activeID := ""
	if t := chromedp.FromContext(ctx); t != nil && t.Target != nil {
		activeID = string(t.Target.TargetID)
	}

	var tabs []TabState
	idx := 0
	for _, t := range infos {
		if t.Type != "page" {
			continue
		}
		tid := string(t.TargetID)
		tabs = append(tabs, TabState{
			TargetID: tid,
			URL:      t.URL,
			Title:    t.Title,
			IsActive: tid == activeID,
			Index:    idx,
		})
		idx++
	}
	return tabs
}

// queryInteractiveElements finds all clickable/fillable/selectable elements
// and computes their bounding boxes.
//
// It uses a multi-pass strategy to catch poorly-formatted sites that attach
// click listeners to generic divs/spans without semantic markup.
func (o *Observer) queryInteractiveElements(ctx context.Context) ([]VisibleElement, error) {
	// Multi-pass query: base selectors → focusable → pointer-cursor → framework attrs
	query := `
	(function() {
		const seen = new Set();
		const results = [];

		function add(el) {
			if (seen.has(el)) return;
			seen.add(el);
			const rect = el.getBoundingClientRect();
			const style = window.getComputedStyle(el);
			const isVisible = rect.width > 0 && rect.height > 0 && style.visibility !== 'hidden' && style.display !== 'none';
			if (!isVisible) return;
			results.push(el);
		}

		// Pass 1: obvious interactive elements
		const base = 'a, button, input, textarea, select, [role="button"], [role="link"], [role="menuitem"], [role="tab"], [role="option"], [onclick]';
		document.querySelectorAll(base).forEach(add);

		// Pass 2: focusable / editable elements
		const focusable = '[tabindex]:not([tabindex="-1"]), [contenteditable], label, details, summary';
		document.querySelectorAll(focusable).forEach(add);

		// Pass 3: generic elements with pointer cursor (catches clickable divs/spans)
		const generic = 'div, span, li, td, th, article, section, header, footer, main, aside, nav, p, h1, h2, h3, h4, h5, h6';
		document.querySelectorAll(generic).forEach(el => {
			const style = window.getComputedStyle(el);
			if (style.cursor === 'pointer') add(el);
		});

		// Pass 4: framework-specific click attributes
		const framework = '[jsaction*="click"], [ng-click], [data-click], [data-action*="click"]';
		document.querySelectorAll(framework).forEach(add);

		return results.map((el, idx) => {
			const rect = el.getBoundingClientRect();
			return {
				index: idx,
				tag: el.tagName.toLowerCase(),
				id: el.id || '',
				class: el.getAttribute('class') || '',
				text: (el.innerText || el.value || el.getAttribute('aria-label') || el.getAttribute('placeholder') || '').substring(0, 200),
				x: rect.x + window.scrollX,
				y: rect.y + window.scrollY,
				width: rect.width,
				height: rect.height,
				isVisible: true,
				type: el.type || '',
				href: el.href || '',
				name: el.name || '',
				placeholder: el.placeholder || '',
				role: el.getAttribute('role') || ''
			};
		});
	})();`

	var raw []map[string]interface{}
	if err := chromedp.Run(ctx, chromedp.Evaluate(query, &raw)); err != nil {
		return nil, err
	}

	elems := make([]VisibleElement, 0, len(raw))
	for i, r := range raw {
		if o.MaxElements > 0 && i >= o.MaxElements {
			break
		}
		elem := VisibleElement{
			ID:       fmt.Sprintf("E%d", i+1),
			Selector: buildSelector(r),
			Tag:      cdpString(r,"tag"),
			Text:     truncate(cdpString(r,"text"), o.MaxTextLen),
			Bounds: BoundingBox{
				X:      cdpFloat(r, "x"),
				Y:      cdpFloat(r, "y"),
				Width:  cdpFloat(r, "width"),
				Height: cdpFloat(r, "height"),
			},
			IsVisible:     cdpBool(r, "isVisible"),
			IsInteractive: true,
			Attrs: map[string]string{
				"href":        cdpString(r,"href"),
				"type":        cdpString(r,"type"),
				"name":        cdpString(r,"name"),
				"placeholder": cdpString(r,"placeholder"),
				"role":        cdpString(r,"role"),
			},
		}
		elem.ActionTypes = inferActionTypes(elem)
		elems = append(elems, elem)
	}
	return elems, nil
}

// queryLinks extracts all anchor tags with hrefs.
func (o *Observer) queryLinks(ctx context.Context) ([]Link, error) {
	query := `
	(function() {
		return Array.from(document.querySelectorAll('a[href]')).map(a => ({
			text: (a.innerText || '').substring(0, 100),
			href: a.href
		}));
	})();`
	var raw []map[string]interface{}
	if err := chromedp.Run(ctx, chromedp.Evaluate(query, &raw)); err != nil {
		return nil, err
	}
	links := make([]Link, 0, len(raw))
	seen := make(map[string]bool)
	for _, r := range raw {
		href := cdpString(r,"href")
		if href == "" || seen[href] || strings.HasPrefix(href, "javascript:") {
			continue
		}
		seen[href] = true
		links = append(links, Link{
			Text: truncate(cdpString(r,"text"), 80),
			Href: href,
		})
	}
	return links, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func parseScrollState(m map[string]interface{}, viewportHeight float64) ScrollState {
	s := ScrollState{
		Y:    cdpFloat(m, "y"),
		MaxY: cdpFloat(m, "docHeight") - viewportHeight,
	}
	if s.MaxY < 0 {
		s.MaxY = 0
	}
	return s
}

func buildSelector(r map[string]interface{}) string {
	tag := cdpString(r,"tag")
	id := cdpString(r,"id")
	cls := cdpString(r,"class")
	if id != "" {
		return fmt.Sprintf("%s#%s", tag, id)
	}
	if cls != "" {
		parts := strings.Fields(cls)
		if len(parts) > 0 {
			return fmt.Sprintf("%s.%s", tag, strings.Join(parts, "."))
		}
	}
	idx := int(cdpFloat(r, "index"))
	return fmt.Sprintf("%s:nth-of-type(%d)", tag, idx+1)
}

func inferActionTypes(elem VisibleElement) []ActionType {
	var types []ActionType
	switch elem.Tag {
	case "a", "button":
		types = append(types, ActionClick, ActionHover, ActionFocus)
	case "input":
		inpType := elem.Attrs["type"]
		switch inpType {
		case "checkbox", "radio":
			types = append(types, ActionToggle, ActionFocus)
		default:
			types = append(types, ActionTypeText, ActionFocus, ActionClearInput)
		}
	case "textarea":
		types = append(types, ActionTypeText, ActionFocus, ActionClearInput)
	case "select":
		types = append(types, ActionSelect, ActionFocus)
	}
	if elem.Attrs["role"] == "button" || elem.Attrs["role"] == "link" {
		types = append(types, ActionClick, ActionHover, ActionFocus)
	}
	return types
}

func cdpString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		switch val := v.(type) {
		case string:
			return val
		case json.Number:
			return val.String()
		default:
			return fmt.Sprintf("%v", v)
		}
	}
	return ""
}

func cdpFloat(m map[string]interface{}, key string) float64 {
	if v, ok := m[key]; ok {
		switch val := v.(type) {
		case float64:
			return val
		case json.Number:
			f, _ := val.Float64()
			return f
		case int:
			return float64(val)
		case int64:
			return float64(val)
		}
	}
	return 0
}

func cdpBool(m map[string]interface{}, key string) bool {
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// detectPageChallenge scans HTML body for known anti-bot challenge markers.
// Returns the challenge vendor name (lowercase) or empty string if none detected.
func detectPageChallenge(body string) string {
	lower := strings.ToLower(body)
	checks := []struct {
		marker string
		vendor string
	}{
		{"cf-browser-verification", "cloudflare"},
		{"challenge-platform", "cloudflare"},
		{"turnstile", "cloudflare"},
		{"datadome", "datadome"},
		{"_Incapsula_Resource", "imperva"},
		{"visid_incap", "imperva"},
		{"recaptcha", "recaptcha"},
		{"g-recaptcha", "recaptcha"},
		{"hcaptcha", "hcaptcha"},
		{"perimeterx", "perimeterx"},
		{"px-captcha", "perimeterx"},
		{"akamai", "akamai"},
		{"bm_sz", "akamai"},
	}
	for _, c := range checks {
		if strings.Contains(lower, c.marker) {
			return c.vendor
		}
	}
	return ""
}
