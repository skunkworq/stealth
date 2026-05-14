// Package agent — Action Space Layer
//
// Builds the complete set of actions an agent can take from a PageSnapshot.
// This is intentionally separate from observation so that action enumeration
// strategies can evolve independently (e.g. prune low-priority actions,
// add domain-specific actions, etc.).
package agent

import (
	"fmt"
	"math"

	"github.com/skunkworq/stealth/brws/content/understand"
)

// BuildActionSpace enumerates all possible actions from a snapshot.
func BuildActionSpace(snap *PageSnapshot) *ActionSpace {
	as := &ActionSpace{}

	// 1. Element-bound actions (click, type, select, toggle)
	for _, elem := range snap.Elements {
		for _, at := range elem.ActionTypes {
			act := Action{
				ID:       fmt.Sprintf("%s_%s", at, elem.ID),
				Type:     at,
				TargetID: elem.ID,
			}
			switch at {
			case ActionClick:
				act.Description = fmt.Sprintf("Click '%s' (%s)", elem.Text, elem.Tag)
				act.IsLink = elem.Attrs["href"] != ""
				act.IsFormSubmit = elem.Attrs["type"] == "submit"
			case ActionTypeText:
				placeholder := elem.Attrs["placeholder"]
				if placeholder == "" {
					placeholder = elem.Text
				}
				act.Description = fmt.Sprintf("Type into '%s' (%s)", placeholder, elem.Tag)
				act.Parameters = map[string]interface{}{
					"field_type": elem.Attrs["type"],
					"name":       elem.Attrs["name"],
				}
			case ActionSelect:
				act.Description = fmt.Sprintf("Select option in '%s' (%s)", elem.Text, elem.Tag)
			case ActionToggle:
				act.Description = fmt.Sprintf("Toggle '%s' (%s)", elem.Text, elem.Tag)
			case ActionHover:
				act.Description = fmt.Sprintf("Hover over '%s' (%s)", elem.Text, elem.Tag)
			case ActionFocus:
				act.Description = fmt.Sprintf("Focus '%s' (%s)", elem.Text, elem.Tag)
			case ActionClearInput:
				act.Description = fmt.Sprintf("Clear input '%s' (%s)", elem.Text, elem.Tag)
			}
			as.ElementActions = append(as.ElementActions, act)
		}
	}

	// 2. Scroll actions — always available when there is scrollable room
	as.ScrollActions = buildScrollActions(snap)

	// 3. Navigation actions
	as.NavActions = buildNavActions(snap)

	// 4. Tab actions
	as.TabActions = buildTabActions(snap)

	// 5. Other actions
	as.OtherActions = buildOtherActions()

	// 6. Challenge action — only when a challenge is detected on the page
	if snap.ChallengeDetected {
		as.OtherActions = append(as.OtherActions, Action{
			ID:          "solve_challenge",
			Type:        ActionSolveChallenge,
			Description: fmt.Sprintf("Attempt to solve the %s anti-bot challenge", snap.ChallengeType),
			Parameters: map[string]interface{}{
				"challenge_type": snap.ChallengeType,
			},
		})
	}

	return as
}

func buildOtherActions() []Action {
	return []Action{
		{ID: "wait", Type: ActionWait, Description: "Wait for page to settle"},
		{ID: "screenshot", Type: ActionScreenshot, Description: "Capture screenshot"},
		{ID: "key_press", Type: ActionKeyPress, Description: "Press a key (Enter, Escape, Tab, etc.)", Parameters: map[string]interface{}{"key": "<key name>"}},
		{ID: "wait_for_selector", Type: ActionWaitForSelector, Description: "Wait until an element appears on the page", Parameters: map[string]interface{}{"selector": "<CSS selector>", "timeout_ms": 5000}},
		{ID: "wait_for_navigation", Type: ActionWaitForNavigation, Description: "Wait until the page navigates to a new URL", Parameters: map[string]interface{}{"timeout_ms": 5000}},
		{ID: "done", Type: ActionNone, Description: "Task complete — no further actions"},
	}
}

// buildScrollActions creates scroll actions based on current scroll position
// and document size.  Scroll is a first-class interaction in this framework.
func buildScrollActions(snap *PageSnapshot) []Action {
	var actions []Action
	scroll := snap.Scroll
	pagePct := scrollPercent(scroll)

	// Down — always offered if not at bottom
	if scroll.Y < scroll.MaxY-1 {
		actions = append(actions, Action{
			ID:          "scroll_down",
			Type:        ActionScrollDown,
			Description: fmt.Sprintf("Scroll down (~%d%% of viewport)", 50),
			Parameters: map[string]interface{}{
				"amount":      snap.Viewport.Height * 0.5,
				"current_pct": pagePct,
			},
		})
		// Large scroll down
		actions = append(actions, Action{
			ID:          "scroll_down_large",
			Type:        ActionScrollDown,
			Description: fmt.Sprintf("Scroll down one full viewport (~%d%%)", 100),
			Parameters: map[string]interface{}{
				"amount":      snap.Viewport.Height,
				"current_pct": pagePct,
			},
		})
	}

	// Up — always offered if not at top
	if scroll.Y > 0 {
		actions = append(actions, Action{
			ID:          "scroll_up",
			Type:        ActionScrollUp,
			Description: fmt.Sprintf("Scroll up (~%d%% of viewport)", 50),
			Parameters: map[string]interface{}{
				"amount":      snap.Viewport.Height * 0.5,
				"current_pct": pagePct,
			},
		})
	}

	// To bottom
	if scroll.Y < scroll.MaxY-1 {
		actions = append(actions, Action{
			ID:          "scroll_bottom",
			Type:        ActionScrollBottom,
			Description: "Scroll to the bottom of the page",
			Parameters:  map[string]interface{}{"target": "bottom", "current_pct": pagePct},
		})
	}

	// To top
	if scroll.Y > 0 {
		actions = append(actions, Action{
			ID:          "scroll_top",
			Type:        ActionScrollTop,
			Description: "Scroll to the top of the page",
			Parameters:  map[string]interface{}{"target": "top", "current_pct": pagePct},
		})
	}

	// Scroll-to-element actions for each off-screen or partially-visible element
	for _, elem := range snap.Elements {
		if !isFullyInViewport(elem, snap.Viewport, scroll) {
			actions = append(actions, Action{
				ID:          fmt.Sprintf("scroll_to_%s", elem.ID),
				Type:        ActionScrollTo,
				TargetID:    elem.ID,
				Description: fmt.Sprintf("Scroll until '%s' is in view", elem.Text),
				Parameters: map[string]interface{}{
					"target_id": elem.ID,
					"selector":  elem.Selector,
					"y":         elem.Bounds.Y,
				},
			})
		}
	}

	return actions
}

// buildNavActions creates navigation actions based on history state.
func buildNavActions(snap *PageSnapshot) []Action {
	var actions []Action
	if snap.History.CanGoBack && len(snap.History.Entries) > 0 {
		backIdx := snap.History.CurrentIndex - 1
		if backIdx >= 0 && backIdx < len(snap.History.Entries) {
			entry := snap.History.Entries[backIdx]
			actions = append(actions, Action{
				ID:          "nav_back",
				Type:        ActionBack,
				Description: fmt.Sprintf("Go back to: %s", truncate(entry.URL, 80)),
				Parameters:  map[string]interface{}{"destination_url": entry.URL, "destination_title": entry.Title},
			})
		}
	}
	if snap.History.CanGoForward && len(snap.History.Entries) > 0 {
		fwdIdx := snap.History.CurrentIndex + 1
		if fwdIdx >= 0 && fwdIdx < len(snap.History.Entries) {
			entry := snap.History.Entries[fwdIdx]
			actions = append(actions, Action{
				ID:          "nav_forward",
				Type:        ActionForward,
				Description: fmt.Sprintf("Go forward to: %s", truncate(entry.URL, 80)),
				Parameters:  map[string]interface{}{"destination_url": entry.URL, "destination_title": entry.Title},
			})
		}
	}
	actions = append(actions, Action{
		ID:          "nav_reload",
		Type:        ActionReload,
		Description: "Reload the current page",
	})
	actions = append(actions, Action{
		ID:          "navigate",
		Type:        ActionNavigate,
		Description: "Navigate to a specific URL",
		Parameters:  map[string]interface{}{"url": "<provide URL>"},
	})
	return actions
}

// buildTabActions creates tab management actions from the browser's tab list.
func buildTabActions(snap *PageSnapshot) []Action {
	var actions []Action
	for _, tab := range snap.Tabs {
		if !tab.IsActive {
			actions = append(actions, Action{
				ID:          fmt.Sprintf("switch_tab_%d", tab.Index),
				Type:        ActionSwitchTab,
				Description: fmt.Sprintf("Switch to tab %d: %s", tab.Index, truncate(tab.Title, 60)),
				Parameters:  map[string]interface{}{"target_id": tab.TargetID, "index": tab.Index},
			})
		}
		actions = append(actions, Action{
			ID:          fmt.Sprintf("close_tab_%d", tab.Index),
			Type:        ActionCloseTab,
			Description: fmt.Sprintf("Close tab %d: %s", tab.Index, truncate(tab.Title, 60)),
			Parameters:  map[string]interface{}{"target_id": tab.TargetID, "index": tab.Index},
		})
	}
	actions = append(actions, Action{
		ID:          "new_tab",
		Type:        ActionNewTab,
		Description: "Open a new browser tab",
		Parameters:  map[string]interface{}{"url": "about:blank"},
	})
	return actions
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func scrollPercent(s ScrollState) int {
	if s.MaxY <= 0 {
		return 100
	}
	pct := int(math.Round((s.Y / s.MaxY) * 100))
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return pct
}

func isFullyInViewport(elem VisibleElement, vp Viewport, scroll ScrollState) bool {
	// Convert element position to viewport-relative
	relY := elem.Bounds.Y - scroll.Y
	relX := elem.Bounds.X - scroll.X
	return relX >= 0 && relY >= 0 &&
		relX+elem.Bounds.Width <= vp.Width &&
		relY+elem.Bounds.Height <= vp.Height
}

// ---------------------------------------------------------------------------
// Semantic Action Space
// ---------------------------------------------------------------------------

// BuildSemanticActionSpace derives an action space from a semantic tree.
// It maps semantic node actions to agent actions and supplements them with
// scroll / nav / tab / meta actions from the snapshot.
func BuildSemanticActionSpace(snap *PageSnapshot) *ActionSpace {
	if snap.SemanticTree == nil {
		return BuildActionSpace(snap)
	}

	as := &ActionSpace{}

	// 1. Element-bound actions from semantic tree nodes
	var walk func(nodes []understand.SemanticNode)
	walk = func(nodes []understand.SemanticNode) {
		for i := range nodes {
			node := &nodes[i]
			for _, sa := range node.Actions {
				act := Action{
					ID:          fmt.Sprintf("%s_%s", node.ID, sa.Type),
					Type:        mapSemanticActionType(sa.Type),
					Description: sa.Description,
					TargetID:    node.ID,
					Parameters:  map[string]interface{}{"selector": sa.Selector},
				}
				as.ElementActions = append(as.ElementActions, act)
			}
			walk(node.Children)
		}
	}
	walk(snap.SemanticTree.RootNodes)

	// 2. Scroll actions (same as DOM-based)
	as.ScrollActions = buildScrollActions(snap)

	// 3. Nav actions (same as DOM-based)
	as.NavActions = buildNavActions(snap)

	// 4. Tab actions (same as DOM-based)
	as.TabActions = buildTabActions(snap)

	// 5. Other actions (same as DOM-based)
	as.OtherActions = buildOtherActions()

	return as
}

func mapSemanticActionType(t understand.ActionType) ActionType {
	switch t {
	case understand.ActionClick:
		return ActionClick
	case understand.ActionFill:
		return ActionTypeText
	case understand.ActionSelect:
		return ActionSelect
	case understand.ActionToggle:
		return ActionToggle
	}
	return ActionClick
}
