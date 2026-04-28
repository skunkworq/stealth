// Package agent — Formatter Layer
//
// Converts PageSnapshot + ActionSpace into compact, token-efficient prompts
// for LLM agents.  Multiple formats are supported; the default is a
// markdown-like structured text optimized for reasoning models.
package agent

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/skunkworq/stealth/brws/semantic"
)

// Formatter renders AgentContext into a string prompt.
type Formatter struct {
	// MaxTokens caps the approximate output length.  Zero = unlimited.
	MaxTokens int
	// IncludeLinks includes the full link list.
	IncludeLinks bool
	// IncludeForms includes form schemas.
	IncludeForms bool
	// IncludeBounds includes element bounding boxes.
	IncludeBounds bool
	// IncludeMeta includes page metadata (title, description, OG, etc.).
	IncludeMeta bool
	// IncludeImages includes image references.
	IncludeImages bool
	// IncludeSemanticTree includes the semantic tree summary.
	IncludeSemanticTree bool
	// Representation controls which view is rendered as the primary
	// element list.  "dom" (default) or "semantic".
	Representation Representation
}

// DefaultFormatter returns a formatter with sensible defaults for LLM prompts.
func DefaultFormatter() *Formatter {
	return &Formatter{
		MaxTokens:           4000,
		IncludeLinks:        false,
		IncludeForms:        true,
		IncludeBounds:       false,
		IncludeMeta:         false,
		IncludeImages:       false,
		IncludeSemanticTree: false,
	}
}

// Format renders the full agent prompt.
func (f *Formatter) Format(ctx *Context) string {
	var b strings.Builder
	b.WriteString(f.formatHeader(ctx))
	b.WriteString("\n")
	b.WriteString(f.formatElements(ctx))
	b.WriteString("\n")
	b.WriteString(f.formatScrollActions(ctx))
	b.WriteString("\n")
	b.WriteString(f.formatNavActions(ctx))
	b.WriteString("\n")
	b.WriteString(f.formatTabActions(ctx))
	b.WriteString("\n")
	b.WriteString(f.formatOtherActions(ctx))
	if f.IncludeForms {
		b.WriteString("\n")
		b.WriteString(f.formatForms(ctx))
	}
	if f.IncludeLinks {
		b.WriteString("\n")
		b.WriteString(f.formatLinks(ctx))
	}
	if f.IncludeMeta && ctx.Snapshot.Meta != nil {
		b.WriteString("\n")
		b.WriteString(f.formatMeta(ctx))
	}
	if f.IncludeImages && len(ctx.Snapshot.Images) > 0 {
		b.WriteString("\n")
		b.WriteString(f.formatImages(ctx))
	}
	if f.IncludeSemanticTree && ctx.Snapshot.SemanticTree != nil {
		b.WriteString("\n")
		b.WriteString(f.formatSemanticTreeMarkdown(ctx.Snapshot.SemanticTree))
	}
	b.WriteString("\n")
	b.WriteString(f.formatInstructions())
	return b.String()
}

// FormatCompact returns a one-line-per-element compact representation.
func (f *Formatter) FormatCompact(ctx *Context) string {
	var b strings.Builder
	s := ctx.Snapshot
	b.WriteString(fmt.Sprintf("PAGE %s | %q | vp=%.0fx%.0f | scroll=%.0f/%.0f(%d%%)\n",
		s.URL, s.Title,
		s.Viewport.Width, s.Viewport.Height,
		s.Scroll.Y, s.Scroll.MaxY,
		scrollPercent(s.Scroll),
	))
	if len(s.Tabs) > 0 {
		b.WriteString(fmt.Sprintf("TABS: %d open | ", len(s.Tabs)))
		for _, t := range s.Tabs {
			if t.IsActive {
				b.WriteString(fmt.Sprintf("[%d]*%s ", t.Index, truncate(t.Title, 30)))
			} else {
				b.WriteString(fmt.Sprintf("[%d]%s ", t.Index, truncate(t.Title, 30)))
			}
		}
		b.WriteString("\n")
	}
	if s.History.CanGoBack && len(s.History.Entries) > 0 {
		backIdx := s.History.CurrentIndex - 1
		if backIdx >= 0 {
			b.WriteString(fmt.Sprintf("BACK: %s\n", truncate(s.History.Entries[backIdx].URL, 80)))
		}
	}

	for _, elem := range ctx.Snapshot.Elements {
		actions := make([]string, len(elem.ActionTypes))
		for i, at := range elem.ActionTypes {
			actions[i] = string(at)
		}
		b.WriteString(fmt.Sprintf("[%s] %s %q @ %.0f,%.0f → %s\n",
			elem.ID, elem.Tag, elem.Text, elem.Bounds.X, elem.Bounds.Y,
			strings.Join(actions, ","),
		))
	}

	b.WriteString("SCROLL: ")
	for _, a := range ctx.ActionSpace.ScrollActions {
		b.WriteString(a.ID + " ")
	}
	b.WriteString("\nNAV: ")
	for _, a := range ctx.ActionSpace.NavActions {
		b.WriteString(a.ID + " ")
	}
	if len(ctx.ActionSpace.TabActions) > 0 {
		b.WriteString("\nTABS: ")
		for _, a := range ctx.ActionSpace.TabActions {
			b.WriteString(a.ID + " ")
		}
	}
	b.WriteString("\nMETA: wait screenshot done\n")

	if f.IncludeMeta && ctx.Snapshot.Meta != nil {
		b.WriteString("\n")
		b.WriteString(f.formatMetaCompact(ctx))
	}
	if f.IncludeImages && len(ctx.Snapshot.Images) > 0 {
		b.WriteString("\n")
		b.WriteString(f.formatImagesCompact(ctx))
	}
	if f.IncludeSemanticTree && ctx.Snapshot.SemanticTree != nil {
		b.WriteString("\n")
		b.WriteString(f.formatSemanticTreeCompact(ctx.Snapshot.SemanticTree))
	}
	return b.String()
}

// FormatJSON returns a JSON representation (useful for structured parsing).
func (f *Formatter) FormatJSON(ctx *Context) string {
	b, _ := json.MarshalIndent(ctx, "", "  ")
	return string(b)
}

// ---------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------

func (f *Formatter) formatHeader(ctx *Context) string {
	s := ctx.Snapshot
	pct := scrollPercent(s.Scroll)
	scrollRegion := "top"
	if pct > 33 && pct < 66 {
		scrollRegion = "middle"
	} else if pct >= 66 {
		scrollRegion = "bottom"
	}

	hist := fmt.Sprintf("History:  %d entries | back=%v | forward=%v",
		s.History.Length, s.History.CanGoBack, s.History.CanGoForward)
	if s.History.CanGoBack && len(s.History.Entries) > 0 {
		backIdx := s.History.CurrentIndex - 1
		if backIdx >= 0 && backIdx < len(s.History.Entries) {
			hist += fmt.Sprintf("\n  ← back to: %s", truncate(s.History.Entries[backIdx].URL, 80))
		}
	}
	if s.History.CanGoForward && len(s.History.Entries) > 0 {
		fwdIdx := s.History.CurrentIndex + 1
		if fwdIdx >= 0 && fwdIdx < len(s.History.Entries) {
			hist += fmt.Sprintf("\n  → forward to: %s", truncate(s.History.Entries[fwdIdx].URL, 80))
		}
	}

	tabs := ""
	if len(s.Tabs) > 0 {
		tabs = fmt.Sprintf("\nTabs:     %d open", len(s.Tabs))
		for _, t := range s.Tabs {
			marker := ""
			if t.IsActive {
				marker = " *active*"
			}
			tabs += fmt.Sprintf("\n  [%d] %s%s", t.Index, truncate(t.Title, 60), marker)
		}
	}

	return fmt.Sprintf(`=== PAGE CONTEXT ===
URL:     %s
Title:   %s
Viewport: %.0f x %.0f
Scroll:   %.0f / %.0f px (%d%% — %s third)
%s%s`,
		s.URL, s.Title,
		s.Viewport.Width, s.Viewport.Height,
		s.Scroll.Y, s.Scroll.MaxY, pct, scrollRegion,
		hist, tabs,
	)
}

func (f *Formatter) formatElements(ctx *Context) string {
	var b strings.Builder
	b.WriteString("\n=== INTERACTIVE ELEMENTS ===\n")
	if len(ctx.Snapshot.Elements) == 0 {
		b.WriteString("(none visible)\n")
		return b.String()
	}
	for _, elem := range ctx.Snapshot.Elements {
		bounds := ""
		if f.IncludeBounds {
			bounds = fmt.Sprintf(" @ (%.0f,%.0f %.0fx%.0f)",
				elem.Bounds.X, elem.Bounds.Y, elem.Bounds.Width, elem.Bounds.Height)
		}
		actions := make([]string, 0, len(elem.ActionTypes))
		for _, at := range elem.ActionTypes {
			actions = append(actions, string(at))
		}
		line := fmt.Sprintf("  [%s] <%s>%s → %s",
			elem.ID, elem.Tag, bounds, strings.Join(actions, ","))
		if elem.Text != "" {
			line += fmt.Sprintf(" | %q", elem.Text)
		}
		if ph := elem.Attrs["placeholder"]; ph != "" {
			line += fmt.Sprintf(" [placeholder=%q]", ph)
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

func (f *Formatter) formatScrollActions(ctx *Context) string {
	var b strings.Builder
	b.WriteString("\n=== SCROLL ACTIONS ===\n")
	for _, a := range ctx.ActionSpace.ScrollActions {
		b.WriteString(fmt.Sprintf("  [%s] %s\n", a.ID, a.Description))
	}
	return b.String()
}

func (f *Formatter) formatNavActions(ctx *Context) string {
	var b strings.Builder
	b.WriteString("\n=== NAVIGATION ACTIONS ===\n")
	for _, a := range ctx.ActionSpace.NavActions {
		b.WriteString(fmt.Sprintf("  [%s] %s\n", a.ID, a.Description))
	}
	return b.String()
}

func (f *Formatter) formatTabActions(ctx *Context) string {
	var b strings.Builder
	if len(ctx.ActionSpace.TabActions) == 0 {
		return ""
	}
	b.WriteString("\n=== TAB ACTIONS ===\n")
	for _, a := range ctx.ActionSpace.TabActions {
		b.WriteString(fmt.Sprintf("  [%s] %s\n", a.ID, a.Description))
	}
	return b.String()
}

func (f *Formatter) formatOtherActions(ctx *Context) string {
	var b strings.Builder
	b.WriteString("\n=== OTHER ACTIONS ===\n")
	for _, a := range ctx.ActionSpace.OtherActions {
		b.WriteString(fmt.Sprintf("  [%s] %s\n", a.ID, a.Description))
	}
	return b.String()
}

func (f *Formatter) formatForms(ctx *Context) string {
	var b strings.Builder
	if len(ctx.Snapshot.Forms) == 0 {
		return ""
	}
	b.WriteString("\n=== FORMS ===\n")
	for i, form := range ctx.Snapshot.Forms {
		b.WriteString(fmt.Sprintf("  Form[%d] %s %s → %s\n", i, form.Method, form.Action, form.SubmitButton))
		for _, field := range form.Fields {
			req := ""
			if field.Required {
				req = " *required"
			}
			opts := ""
			if len(field.Options) > 0 {
				opts = fmt.Sprintf(" options=%v", field.Options)
			}
			b.WriteString(fmt.Sprintf("    - %s (%s)%s%s\n", field.Label, field.Type, req, opts))
		}
	}
	return b.String()
}

func (f *Formatter) formatLinks(ctx *Context) string {
	var b strings.Builder
	if len(ctx.Snapshot.Links) == 0 {
		return ""
	}
	b.WriteString("\n=== LINKS ===\n")
	for _, link := range ctx.Snapshot.Links {
		text := link.Text
		if text == "" {
			text = "(no text)"
		}
		b.WriteString(fmt.Sprintf("  - %s → %s\n", text, link.Href))
	}
	return b.String()
}

func (f *Formatter) formatInstructions() string {
	return `
=== INSTRUCTIONS ===
Choose ONE action by responding with its ID in brackets, e.g.:
  [E1_click]

For "type" actions, include the text after a colon:
  [E3_type]: hello world

For "navigate", include the URL:
  [navigate]: https://example.com/other

For "wait", you may include milliseconds:
  [wait]: 2000

If the task is complete, respond with [done].
`
}

// FormatSemanticCompact renders a compact representation using the semantic tree
// instead of raw DOM elements.  This is much more token-efficient for LLMs.
func (f *Formatter) FormatSemanticCompact(ctx *Context) string {
	var b strings.Builder
	s := ctx.Snapshot
	b.WriteString(fmt.Sprintf("PAGE %s | %q | vp=%.0fx%.0f | scroll=%.0f/%.0f(%d%%)\n",
		s.URL, s.Title,
		s.Viewport.Width, s.Viewport.Height,
		s.Scroll.Y, s.Scroll.MaxY,
		scrollPercent(s.Scroll),
	))
	if len(s.Tabs) > 0 {
		b.WriteString(fmt.Sprintf("TABS: %d open | ", len(s.Tabs)))
		for _, t := range s.Tabs {
			if t.IsActive {
				b.WriteString(fmt.Sprintf("[%d]*%s ", t.Index, truncate(t.Title, 30)))
			} else {
				b.WriteString(fmt.Sprintf("[%d]%s ", t.Index, truncate(t.Title, 30)))
			}
		}
		b.WriteString("\n")
	}
	if s.History.CanGoBack && len(s.History.Entries) > 0 {
		backIdx := s.History.CurrentIndex - 1
		if backIdx >= 0 {
			b.WriteString(fmt.Sprintf("BACK: %s\n", truncate(s.History.Entries[backIdx].URL, 80)))
		}
	}

	if s.SemanticTree != nil {
		b.WriteString(f.formatSemanticTreeCompact(s.SemanticTree))
	} else {
		b.WriteString("(no semantic tree available)\n")
		// Fall back to raw elements
		for _, elem := range s.Elements {
			actions := make([]string, len(elem.ActionTypes))
			for i, at := range elem.ActionTypes {
				actions[i] = string(at)
			}
			b.WriteString(fmt.Sprintf("[%s] %s %q @ %.0f,%.0f → %s\n",
				elem.ID, elem.Tag, elem.Text, elem.Bounds.X, elem.Bounds.Y,
				strings.Join(actions, ","),
			))
		}
	}

	b.WriteString("SCROLL: ")
	for _, a := range ctx.ActionSpace.ScrollActions {
		b.WriteString(a.ID + " ")
	}
	b.WriteString("\nNAV: ")
	for _, a := range ctx.ActionSpace.NavActions {
		b.WriteString(a.ID + " ")
	}
	if len(ctx.ActionSpace.TabActions) > 0 {
		b.WriteString("\nTABS: ")
		for _, a := range ctx.ActionSpace.TabActions {
			b.WriteString(a.ID + " ")
		}
	}
	b.WriteString("\nMETA: wait screenshot done\n")
	return b.String()
}

// ---------------------------------------------------------------------------
// Semantic formatting helpers
// ---------------------------------------------------------------------------

func (f *Formatter) formatMeta(ctx *Context) string {
	m := ctx.Snapshot.Meta
	if m == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n=== PAGE META ===\n")
	if m.Title != "" {
		b.WriteString(fmt.Sprintf("Title:       %s\n", m.Title))
	}
	if m.Description != "" {
		b.WriteString(fmt.Sprintf("Description: %s\n", truncate(m.Description, 200)))
	}
	if m.Language != "" {
		b.WriteString(fmt.Sprintf("Language:    %s\n", m.Language))
	}
	if len(m.Keywords) > 0 {
		b.WriteString(fmt.Sprintf("Keywords:    %s\n", strings.Join(m.Keywords, ", ")))
	}
	if m.Author != "" {
		b.WriteString(fmt.Sprintf("Author:      %s\n", m.Author))
	}
	if len(m.OG) > 0 {
		b.WriteString("OpenGraph:\n")
		for k, v := range m.OG {
			b.WriteString(fmt.Sprintf("  og:%s = %s\n", k, truncate(v, 100)))
		}
	}
	return b.String()
}

func (f *Formatter) formatMetaCompact(ctx *Context) string {
	m := ctx.Snapshot.Meta
	if m == nil {
		return ""
	}
	var parts []string
	if m.Description != "" {
		parts = append(parts, fmt.Sprintf("desc=%q", truncate(m.Description, 120)))
	}
	if m.Language != "" {
		parts = append(parts, fmt.Sprintf("lang=%s", m.Language))
	}
	if len(parts) == 0 {
		return ""
	}
	return "META: " + strings.Join(parts, " | ") + "\n"
}

func (f *Formatter) formatImages(ctx *Context) string {
	imgs := ctx.Snapshot.Images
	if len(imgs) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n=== IMAGES ===\n")
	for i, img := range imgs {
		if i >= 20 {
			b.WriteString(fmt.Sprintf("  ... and %d more\n", len(imgs)-20))
			break
		}
		alt := img.Alt
		if alt == "" {
			alt = "(no alt)"
		}
		desc := ""
		if img.Description != "" {
			desc = fmt.Sprintf(" | %q", truncate(img.Description, 80))
		}
		b.WriteString(fmt.Sprintf("  [%d] %s | alt=%q%s\n", i+1, truncate(img.URL, 80), alt, desc))
	}
	return b.String()
}

func (f *Formatter) formatImagesCompact(ctx *Context) string {
	imgs := ctx.Snapshot.Images
	if len(imgs) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("IMAGES: ")
	for i, img := range imgs {
		if i >= 10 {
			b.WriteString(fmt.Sprintf("...+%d ", len(imgs)-10))
			break
		}
		alt := img.Alt
		if alt == "" {
			alt = "?"
		}
		b.WriteString(fmt.Sprintf("[%d]%s ", i+1, truncate(alt, 20)))
	}
	b.WriteString("\n")
	return b.String()
}

func (f *Formatter) formatSemanticTreeMarkdown(tree *semantic.SemanticTree) string {
	var b strings.Builder
	b.WriteString("\n=== SEMANTIC TREE ===\n")
	for i := range tree.RootNodes {
		f.formatSemanticNodeMarkdown(&b, &tree.RootNodes[i], 0)
	}
	return b.String()
}

func (f *Formatter) formatSemanticNodeMarkdown(b *strings.Builder, node *semantic.SemanticNode, depth int) {
	indent := strings.Repeat("  ", depth)
	line := fmt.Sprintf("%s[%s] %s", indent, node.ID, node.Summary)
	if len(node.Actions) > 0 {
		var acts []string
		for _, a := range node.Actions {
			acts = append(acts, string(a.Type))
		}
		line += fmt.Sprintf(" → %s", strings.Join(acts, ","))
	}
	if node.DOMSelector != "" {
		line += fmt.Sprintf(" (%s)", node.DOMSelector)
	}
	b.WriteString(line + "\n")
	for i := range node.Children {
		f.formatSemanticNodeMarkdown(b, &node.Children[i], depth+1)
	}
}

func (f *Formatter) formatSemanticTreeCompact(tree *semantic.SemanticTree) string {
	var b strings.Builder
	for i := range tree.RootNodes {
		f.formatSemanticNodeCompact(&b, &tree.RootNodes[i], 0)
	}
	return b.String()
}

func (f *Formatter) formatSemanticNodeCompact(b *strings.Builder, node *semantic.SemanticNode, depth int) {
	prefix := ""
	if depth > 0 {
		prefix = strings.Repeat("  ", depth)
	}
	actions := ""
	if len(node.Actions) > 0 {
		var acts []string
		for _, a := range node.Actions {
			acts = append(acts, string(a.Type))
		}
		actions = fmt.Sprintf(" → %s", strings.Join(acts, ","))
	}
	b.WriteString(fmt.Sprintf("%s[%s] %s%s\n", prefix, node.ID, node.Summary, actions))
	for i := range node.Children {
		f.formatSemanticNodeCompact(b, &node.Children[i], depth+1)
	}
}
