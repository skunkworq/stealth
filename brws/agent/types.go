// Package agent provides a compartmentalized framework for observing web page
// state, enumerating possible actions, formatting context for LLM agents, and
// executing agent-chosen actions.
package agent

import (
	"time"

	"github.com/skunkworq/stealth/brws/semantic"
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
	Forms        []semantic.FormSchema `json:"forms,omitempty"`
	Links        []Link                `json:"links,omitempty"`
	History      HistoryState          `json:"history"`
	Tabs         []TabState            `json:"tabs,omitempty"` // all open tabs
	Timestamp    time.Time             `json:"timestamp"`

	// --- Semantic enrichment (optional) ---
	Meta         *semantic.PageMeta     `json:"meta,omitempty"`
	Images       []semantic.ImageRef    `json:"images,omitempty"`
	Social       *semantic.SocialLinks  `json:"social,omitempty"`
	Colors       []semantic.ColorInfo   `json:"colors,omitempty"`
	Fonts        []semantic.FontInfo    `json:"fonts,omitempty"`
	SemanticTree *semantic.SemanticTree `json:"semantic_tree,omitempty"`
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
	ActionNewTab       ActionType = "new_tab"
	ActionSwitchTab    ActionType = "switch_tab"
	ActionCloseTab     ActionType = "close_tab"
	ActionNone         ActionType = "done"
)

// Action describes one possible action the agent can take.
type Action struct {
	ID           string                 `json:"id"`
	Type         ActionType             `json:"type"`
	Description  string                 `json:"description"`
	TargetID     string                 `json:"target_id,omitempty"` // references VisibleElement.ID
	Parameters   map[string]interface{} `json:"parameters,omitempty"`
	IsLink       bool                   `json:"is_link,omitempty"`        // true if this click navigates to a link
	IsFormSubmit bool                   `json:"is_form_submit,omitempty"` // true if this click submits a form
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
