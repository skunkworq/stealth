// Package agent provides a compartmentalized framework for observing web page
// state, enumerating possible actions, formatting context for LLM agents, and
// executing agent-chosen actions.
package agent

import (
	"time"

	"github.com/skunkworq/stealth/brws/content/understand"
)

// ---------------------------------------------------------------------------
// Page Snapshot (Observation Layer)
// ---------------------------------------------------------------------------

// TabState describes one browser tab.
type TabState struct {
	TargetID string `json:"target_id"`
	URL      string `json:"url"`
	Title    string `json:"title,omitempty"`
	IsActive bool   `json:"is_active"`
	Index    int    `json:"index"`
}

// PageSnapshot captures everything observable about the current page state.
type PageSnapshot struct {
	URL          string                `json:"url"`
	Title        string                `json:"title"`
	Viewport     Viewport              `json:"viewport"`
	Scroll       ScrollState           `json:"scroll"`
	DocumentSize DocumentSize          `json:"document_size"`
	Elements     []VisibleElement      `json:"elements"`
	Forms        []understand.FormSchema `json:"forms,omitempty"`
	Links        []Link                `json:"links,omitempty"`
	History      HistoryState          `json:"history"`
	Tabs         []TabState            `json:"tabs,omitempty"` // all open tabs
	Timestamp    time.Time             `json:"timestamp"`

	// --- Challenge detection ---
	ChallengeDetected bool   `json:"challenge_detected,omitempty"`
	ChallengeType     string `json:"challenge_type,omitempty"`     // e.g. "cloudflare", "datadome", "recaptcha"

	// --- Semantic enrichment (optional) ---
	Meta         *understand.PageMeta     `json:"meta,omitempty"`
	Images       []understand.ImageRef    `json:"images,omitempty"`
	Social       *understand.SocialLinks  `json:"social,omitempty"`
	Colors       []understand.ColorInfo   `json:"colors,omitempty"`
	Fonts        []understand.FontInfo    `json:"fonts,omitempty"`
	SemanticTree *understand.SemanticTree `json:"semantic_tree,omitempty"`
}

// Viewport describes the browser viewport.
type Viewport struct {
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

// ScrollState describes current scroll position and limits.
type ScrollState struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
	// MaxY is the maximum scrollable Y position (document height - viewport height)
	MaxY float64 `json:"max_y"`
}

// DocumentSize describes the full document dimensions.
type DocumentSize struct {
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

// HistoryEntry is one item in the browser's session history.
type HistoryEntry struct {
	URL   string `json:"url"`
	Title string `json:"title,omitempty"`
}

// HistoryState describes the browser history stack.
type HistoryState struct {
	Length       int            `json:"length"`
	CurrentIndex int            `json:"current_index"`
	CanGoBack    bool           `json:"can_go_back"`
	CanGoForward bool           `json:"can_go_forward"`
	Entries      []HistoryEntry `json:"entries,omitempty"` // actual URLs/titles the agent can go back/forward to
}

// VisibleElement is an element visible in the current viewport (or near it).
type VisibleElement struct {
	ID            string            `json:"id"`
	Selector      string            `json:"selector"`
	Tag           string            `json:"tag"`
	Text          string            `json:"text,omitempty"`
	Bounds        BoundingBox       `json:"bounds"`
	IsVisible     bool              `json:"is_visible"`
	IsInteractive bool              `json:"is_interactive"`
	ActionTypes   []ActionType      `json:"action_types,omitempty"`
	Attrs         map[string]string `json:"attrs,omitempty"`
}

// BoundingBox gives screen coordinates in CSS pixels.
type BoundingBox struct {
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

// Link is a navigable anchor.
type Link struct {
	Text string `json:"text,omitempty"`
	Href string `json:"href"`
	ID   string `json:"id,omitempty"`
}

// ---------------------------------------------------------------------------
// Representation mode
// ---------------------------------------------------------------------------

// Representation controls which page representation the agent uses for
// observation and action enumeration.
type Representation string

const (
	// RepresentationDOM uses raw DOM elements (live CDP bounding boxes + selectors).
	RepresentationDOM Representation = "dom"
	// RepresentationSemantic uses the semantic tree (hierarchical summaries).
	RepresentationSemantic Representation = "semantic"
)

// ---------------------------------------------------------------------------
// Action Space (Enumeration Layer)
// ---------------------------------------------------------------------------

// ActionType categorizes agent actions.
type ActionType string

const (
	ActionClick        ActionType = "click"
	ActionTypeText     ActionType = "type"
	ActionSelect       ActionType = "select"
	ActionToggle       ActionType = "toggle"
	ActionScrollDown   ActionType = "scroll_down"
	ActionScrollUp     ActionType = "scroll_up"
	ActionScrollBottom ActionType = "scroll_bottom"
	ActionScrollTop    ActionType = "scroll_top"
	ActionScrollTo     ActionType = "scroll_to"
	ActionNavigate     ActionType = "navigate"
	ActionBack         ActionType = "back"
	ActionForward      ActionType = "forward"
	ActionReload       ActionType = "reload"
	ActionWait         ActionType = "wait"
	ActionScreenshot   ActionType = "screenshot"
	ActionHover        ActionType = "hover"
	ActionFocus        ActionType = "focus"
	ActionKeyPress     ActionType = "key_press"
	ActionClearInput   ActionType = "clear_input"
	ActionWaitForSelector   ActionType = "wait_for_selector"
	ActionWaitForNavigation ActionType = "wait_for_navigation"
	ActionNewTab       ActionType = "new_tab"
	ActionSwitchTab    ActionType = "switch_tab"
	ActionCloseTab     ActionType = "close_tab"
	ActionSolveChallenge ActionType = "solve_challenge"
	ActionNone         ActionType = "done"
)

// ---------------------------------------------------------------------------
// Typed parameter structs — one per logical action group.
// These replace the former map[string]interface{} Parameters bag.
// ---------------------------------------------------------------------------

// ClickParams holds parameters for click, hover, focus, toggle, and clear_input actions.
type ClickParams struct {
	Selector string  `json:"selector,omitempty"`
	X        float64 `json:"x,omitempty"`
	Y        float64 `json:"y,omitempty"`
}

// TypeParams holds parameters for type_text actions.
type TypeParams struct {
	Selector  string `json:"selector,omitempty"`
	Text      string `json:"text,omitempty"`
	FieldType string `json:"field_type,omitempty"`
	Name      string `json:"name,omitempty"`
}

// SelectParams holds parameters for select actions.
type SelectParams struct {
	Selector string `json:"selector,omitempty"`
	Value    string `json:"value,omitempty"`
}

// ScrollParams holds parameters for scroll_down and scroll_up actions.
type ScrollParams struct {
	Amount     float64 `json:"amount,omitempty"`
	CurrentPct float64 `json:"current_pct,omitempty"`
}

// ScrollToParams holds parameters for scroll_to_<elem> actions.
type ScrollToParams struct {
	TargetID string  `json:"target_id,omitempty"`
	Selector string  `json:"selector,omitempty"`
	Y        float64 `json:"y,omitempty"`
}

// ScrollTargetParams holds parameters for scroll_bottom and scroll_top actions.
type ScrollTargetParams struct {
	Target     string  `json:"target,omitempty"`
	CurrentPct float64 `json:"current_pct,omitempty"`
}

// NavigateParams holds parameters for navigate and new_tab actions.
type NavigateParams struct {
	URL string `json:"url,omitempty"`
}

// NavHistoryParams holds parameters for nav_back and nav_forward actions.
type NavHistoryParams struct {
	DestinationURL   string `json:"destination_url,omitempty"`
	DestinationTitle string `json:"destination_title,omitempty"`
}

// WaitParams holds parameters for wait actions.
type WaitParams struct {
	Ms       int    `json:"ms,omitempty"`
	Duration string `json:"duration,omitempty"`
}

// ScreenshotParams holds parameters for screenshot actions.
type ScreenshotParams struct {
	Path string `json:"path,omitempty"`
}

// KeyPressParams holds parameters for key_press actions.
type KeyPressParams struct {
	Key      string `json:"key,omitempty"`
	Selector string `json:"selector,omitempty"`
}

// WaitForSelectorParams holds parameters for wait_for_selector actions.
type WaitForSelectorParams struct {
	Selector  string `json:"selector,omitempty"`
	TimeoutMs int    `json:"timeout_ms,omitempty"`
}

// WaitForNavParams holds parameters for wait_for_navigation actions.
type WaitForNavParams struct {
	TimeoutMs int `json:"timeout_ms,omitempty"`
}

// SolveChallengeParams holds parameters for solve_challenge actions.
type SolveChallengeParams struct {
	ChallengeType string `json:"challenge_type,omitempty"`
}

// TabParams holds parameters for switch_tab and close_tab actions.
type TabParams struct {
	TargetID string `json:"target_id,omitempty"`
	Index    int    `json:"index,omitempty"`
}

// Action describes one possible action the agent can take.
type Action struct {
	ID           string      `json:"id"`
	Type         ActionType  `json:"type"`
	Description  string      `json:"description"`
	TargetID     string      `json:"target_id,omitempty"` // references VisibleElement.ID
	Parameters   interface{} `json:"parameters,omitempty"`
	IsLink       bool        `json:"is_link,omitempty"`        // true if this click navigates to a link
	IsFormSubmit bool        `json:"is_form_submit,omitempty"` // true if this click submits a form
}

// ActionSpace is the complete set of actions available on the current page.
type ActionSpace struct {
	ElementActions []Action `json:"element_actions"`
	ScrollActions  []Action `json:"scroll_actions"`
	NavActions     []Action `json:"nav_actions"`
	TabActions     []Action `json:"tab_actions,omitempty"`
	OtherActions   []Action `json:"other_actions"`
}

// All returns every action in a single flat slice.
func (as *ActionSpace) All() []Action {
	out := make([]Action, 0,
		len(as.ElementActions)+len(as.ScrollActions)+len(as.NavActions)+len(as.TabActions)+len(as.OtherActions))
	out = append(out, as.ElementActions...)
	out = append(out, as.ScrollActions...)
	out = append(out, as.NavActions...)
	out = append(out, as.TabActions...)
	out = append(out, as.OtherActions...)
	return out
}

// Find looks up an action by its ID.
func (as *ActionSpace) Find(id string) *Action {
	for _, a := range as.All() {
		if a.ID == id {
			return &a
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Agent Context (Orchestration Layer)
// ---------------------------------------------------------------------------

// Context bundles the observed page state and the enumerated action space.
type Context struct {
	Snapshot            *PageSnapshot  `json:"snapshot"`
	ActionSpace         *ActionSpace   `json:"action_space"`                    // primary (DOM-based)
	SemanticActionSpace *ActionSpace   `json:"semantic_action_space,omitempty"` // derived from semantic tree
	Representation      Representation `json:"representation"`
}

// NewContext creates an AgentContext from a snapshot.
func NewContext(snap *PageSnapshot) *Context {
	return &Context{
		Snapshot:       snap,
		ActionSpace:    BuildActionSpace(snap),
		Representation: RepresentationDOM,
	}
}
