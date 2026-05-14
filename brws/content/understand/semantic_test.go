package understand

import (
	"strings"
	"testing"
)

func TestSemanticNodeFind(t *testing.T) {
	tree := &SemanticTree{
		URL:    "https://example.com",
		Domain: "example.com",
		Title:  "Test",
		RootNodes: []SemanticNode{
			{
				ID:      "nav",
				Summary: "Navigation",
				Children: []SemanticNode{
					{ID: "nav-0", Summary: "Home link"},
					{ID: "nav-1", Summary: "About link"},
				},
			},
			{
				ID:      "main",
				Summary: "Main content",
				Children: []SemanticNode{
					{
						ID:      "main-grid",
						Summary: "Product grid",
						Children: []SemanticNode{
							{ID: "main-grid-0", Summary: "Product 1"},
							{ID: "main-grid-1", Summary: "Product 2"},
						},
					},
				},
			},
		},
	}

	tests := []struct {
		id       string
		expected string
		found    bool
	}{
		{"nav", "Navigation", true},
		{"main", "Main content", true},
		{"nav-0", "Home link", true},
		{"main-grid-1", "Product 2", true},
		{"missing", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			node := tree.FindNode(tt.id)
			if tt.found {
				if node == nil {
					t.Fatalf("expected to find node %s", tt.id)
				}
				if node.Summary != tt.expected {
					t.Errorf("expected summary %q, got %q", tt.expected, node.Summary)
				}
			} else {
				if node != nil {
					t.Fatalf("expected not to find node %s", tt.id)
				}
			}
		})
	}
}

func TestSemanticNodeUnfoldCost(t *testing.T) {
	tests := []struct {
		name     string
		node     SemanticNode
		expected uint32
	}{
		{
			name: "parent with children",
			node: SemanticNode{
				TokenCount:        10,
				SubtreeTokenCount: 50,
				Children:          []SemanticNode{{ID: "child"}},
			},
			expected: 40,
		},
		{
			name: "leaf with raw text",
			node: SemanticNode{
				RawTextTokens: 25,
			},
			expected: 25,
		},
		{
			name: "leaf without raw text",
			node: SemanticNode{
				Summary: "test",
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.node.UnfoldCost()
			if got != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, got)
			}
		})
	}
}

func TestSemanticTreeAncestorPath(t *testing.T) {
	tree := &SemanticTree{
		RootNodes: []SemanticNode{
			{
				ID: "header",
				Children: []SemanticNode{
					{ID: "header-nav"},
				},
			},
			{
				ID: "main",
				Children: []SemanticNode{
					{
						ID: "main-section",
						Children: []SemanticNode{
							{ID: "main-section-grid"},
							{ID: "main-section-item"},
						},
					},
				},
			},
		},
	}

	tests := []struct {
		targetID    string
		expectedLen int
	}{
		{"header", 0},
		{"header-nav", 1},
		{"main-section-grid", 2},
		{"main-section-item", 2},
	}

	for _, tt := range tests {
		t.Run(tt.targetID, func(t *testing.T) {
			path := tree.AncestorPath(tt.targetID)
			if tt.expectedLen == 0 {
				if len(path) > 0 {
					t.Errorf("expected no ancestors, got %v", path)
				}
			} else {
				if path == nil {
					t.Fatalf("expected %d ancestors, got nil", tt.expectedLen)
				}
				if len(path) != tt.expectedLen {
					t.Errorf("expected %d ancestors, got %d", tt.expectedLen, len(path))
				}
			}
		})
	}
}

func TestUnfoldState(t *testing.T) {
	tree := &SemanticTree{
		CompressedTokenCount: 100,
		FullTokenCount:       500,
		RootNodes: []SemanticNode{
			{
				ID:                "nav",
				TokenCount:        20,
				SubtreeTokenCount: 20,
			},
			{
				ID:                "main",
				TokenCount:        30,
				SubtreeTokenCount: 100,
				Children: []SemanticNode{
					{ID: "main-0", TokenCount: 10, SubtreeTokenCount: 10},
					{ID: "main-1", TokenCount: 10, SubtreeTokenCount: 10},
					{ID: "main-2", TokenCount: 10, SubtreeTokenCount: 10},
				},
			},
		},
	}

	t.Run("initial pack", func(t *testing.T) {
		state := InitialPack(tree, 5000, 128000)
		if state.TokenUsage != 100 {
			t.Errorf("expected token usage 100, got %d", state.TokenUsage)
		}
		if state.RemainingBudget() != 127900 {
			t.Errorf("expected remaining 127900, got %d", state.RemainingBudget())
		}
	})

	t.Run("unfold node", func(t *testing.T) {
		state := InitialPack(tree, 5000, 128000)
		cost, ok := UnfoldNode(tree, state, "main")
		if !ok {
			t.Fatal("expected unfold to succeed")
		}
		if cost != 70 {
			t.Errorf("expected cost 70, got %d", cost)
		}
		if state.TokenUsage != 170 {
			t.Errorf("expected token usage 170, got %d", state.TokenUsage)
		}
	})

	t.Run("unfold over budget", func(t *testing.T) {
		state := InitialPack(tree, 150, 150)
		_, ok := UnfoldNode(tree, state, "main")
		if ok {
			t.Error("expected unfold to fail due to budget")
		}
	})

	t.Run("fold node", func(t *testing.T) {
		state := InitialPack(tree, 5000, 128000)
		UnfoldNode(tree, state, "main")
		reclaimed, ok := FoldNode(tree, state, "main")
		if !ok {
			t.Fatal("expected fold to succeed")
		}
		if reclaimed != 70 {
			t.Errorf("expected reclaimed 70, got %d", reclaimed)
		}
		if state.TokenUsage != 100 {
			t.Errorf("expected token usage 100, got %d", state.TokenUsage)
		}
	})
}

func TestAutoUnfold(t *testing.T) {
	tree := &SemanticTree{
		CompressedTokenCount: 60,
		FullTokenCount:       300,
		RootNodes: []SemanticNode{
			{
				ID:                "nav",
				TokenCount:        20,
				SubtreeTokenCount: 40,
				Children:          []SemanticNode{{ID: "nav-child"}},
			},
			{
				ID:                "main",
				TokenCount:        20,
				SubtreeTokenCount: 100,
				Children:          []SemanticNode{{ID: "main-child"}},
			},
			{
				ID:                "footer",
				TokenCount:        20,
				SubtreeTokenCount: 160,
				Children:          []SemanticNode{{ID: "footer-child"}},
			},
		},
	}

	state := InitialPack(tree, 200, 1000)
	unfolded := AutoUnfold(tree, state)

	// AutoUnfold expands root nodes based on budget
	if len(unfolded) == 0 {
		t.Error("expected at least one node to be unfolded")
	}

	// Verify token usage increased
	if state.TokenUsage <= 60 {
		t.Errorf("token usage should increase, got %d", state.TokenUsage)
	}
}

func TestStructuralHash(t *testing.T) {
	t.Run("same structure same hash", func(t *testing.T) {
		h1 := StructuralHash("div", []string{"container", "main"}, []string{})
		h2 := StructuralHash("div", []string{"main", "container"}, []string{})
		if h1 != h2 {
			t.Error("class order should not affect hash")
		}
	})

	t.Run("different tag different hash", func(t *testing.T) {
		h1 := StructuralHash("div", []string{"container"}, []string{})
		h2 := StructuralHash("section", []string{"container"}, []string{})
		if h1 == h2 {
			t.Error("different tags should produce different hashes")
		}
	})

	t.Run("children affect hash", func(t *testing.T) {
		childHash := StructuralHash("span", []string{}, []string{})
		h1 := StructuralHash("div", []string{}, []string{childHash})
		h2 := StructuralHash("div", []string{}, []string{})
		if h1 == h2 {
			t.Error("children should affect hash")
		}
	})
}

func TestContentHash(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		h1 := ContentHash("test content")
		h2 := ContentHash("test content")
		if h1 != h2 {
			t.Error("same content should produce same hash")
		}
	})

	t.Run("different content", func(t *testing.T) {
		h1 := ContentHash("test content 1")
		h2 := ContentHash("test content 2")
		if h1 == h2 {
			t.Error("different content should produce different hash")
		}
	})
}

func TestSelectorToID(t *testing.T) {
	tests := []struct {
		selector string
	}{
		{"body > div"},
		{"body > main > section"},
		{"#content"},
		{".grid > .item"},
	}

	ids := make(map[string]bool)
	for _, tt := range tests {
		t.Run(tt.selector, func(t *testing.T) {
			id := SelectorToID(tt.selector)
			if id == "" {
				t.Error("expected non-empty ID")
			}
			if !strings.HasPrefix(id, "n-") {
				t.Errorf("expected ID to start with 'n-', got %s", id)
			}
			if ids[id] {
				t.Errorf("duplicate ID for selector %s", tt.selector)
			}
			ids[id] = true
		})
	}

	t.Run("consistent for same selector", func(t *testing.T) {
		id1 := SelectorToID("body > div")
		id2 := SelectorToID("body > div")
		if id1 != id2 {
			t.Error("same selector should produce same ID")
		}
	})
}

func TestEstimateTokens(t *testing.T) {
	tests := []struct {
		text        string
		minExpected uint32
	}{
		{"", 1},
		{"a", 1},
		{"abcd", 1},
		{"abcdefgh", 2},
		{"this is a longer text with multiple words", 8},
	}

	for _, tt := range tests {
		got := EstimateTokens(tt.text)
		if got < tt.minExpected {
			t.Errorf("EstimateTokens(%q) = %d, want at least %d", tt.text, got, tt.minExpected)
		}
	}
}

func TestSerializeTree(t *testing.T) {
	tree := &SemanticTree{
		URL:                  "https://example.com",
		Domain:               "example.com",
		Title:                "Example Site",
		CompressedTokenCount: 50,
		FullTokenCount:       150,
		RootNodes: []SemanticNode{
			{
				ID:         "nav",
				Summary:    "Navigation bar with links",
				Actions:    []Action{{Type: ActionClick, Selector: "nav a", Description: "Navigate"}},
				TokenCount: 8,
				Children:   []SemanticNode{},
			},
			{
				ID:         "main",
				Summary:    "Main content with product grid",
				TokenCount: 12,
				Children: []SemanticNode{
					{ID: "main-0", Summary: "Product 1", TokenCount: 10},
					{ID: "main-1", Summary: "Product 2", TokenCount: 10},
				},
			},
		},
	}

	state := InitialPack(tree, 5000, 128000)
	output := SerializeTree(tree, state, nil)

	if !strings.Contains(output, "[WEBFURL]") {
		t.Error("expected [WEBFURL] header")
	}
	if !strings.Contains(output, "[/WEBFURL]") {
		t.Error("expected [/WEBFURL] footer")
	}
	if !strings.Contains(output, "https://example.com") {
		t.Error("expected URL in output")
	}
	if !strings.Contains(output, "Navigation bar") {
		t.Error("expected nav summary in output")
	}
	if !strings.Contains(output, "(clickable)") {
		t.Error("expected clickable marker for action")
	}
}

func TestCollapseTree(t *testing.T) {
	tree := &SemanticTree{
		URL:            "https://example.com",
		Domain:         "example.com",
		FullTokenCount: 1000,
		RootNodes: []SemanticNode{
			{Summary: "Navigation"},
			{Summary: "Main content"},
			{Summary: "Footer"},
		},
	}

	collapsed := CollapseTree(tree, "Browsed products")

	if collapsed.URL != tree.URL {
		t.Error("expected URL to be preserved")
	}
	if collapsed.OriginalTokens != 1000 {
		t.Errorf("expected original tokens 1000, got %d", collapsed.OriginalTokens)
	}
	if !strings.Contains(collapsed.Summary, "Browsed products") {
		t.Error("expected interaction summary")
	}
}

func TestCosineSimilarity(t *testing.T) {
	tests := []struct {
		name     string
		a, b     []float32
		expected float32
	}{
		{
			name:     "identical vectors",
			a:        []float32{1.0, 2.0, 3.0},
			b:        []float32{1.0, 2.0, 3.0},
			expected: 1.0,
		},
		{
			name:     "orthogonal vectors",
			a:        []float32{1.0, 0.0},
			b:        []float32{0.0, 1.0},
			expected: 0.0,
		},
		{
			name:     "opposite vectors",
			a:        []float32{1.0, 1.0},
			b:        []float32{-1.0, -1.0},
			expected: -1.0,
		},
		{
			name:     "empty vectors",
			a:        []float32{},
			b:        []float32{},
			expected: 0.0,
		},
		{
			name:     "different lengths",
			a:        []float32{1.0},
			b:        []float32{1.0, 2.0},
			expected: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CosineSimilarity(tt.a, tt.b)
			if abs32(got-tt.expected) > 0.0001 {
				t.Errorf("expected %f, got %f", tt.expected, got)
			}
		})
	}
}

func TestEncodeDecodeJSON(t *testing.T) {
	node := &SemanticNode{
		ID:              "test-node",
		Summary:         "Test summary",
		StructuralHash:  "hash123",
		IsDynamic:       true,
		DynamicSelector: ".test",
		TokenCount:      42,
		Actions: []Action{
			{Type: ActionClick, Selector: "button", Description: "Click me"},
		},
	}

	encoded := encodeJSON(node)
	var decoded SemanticNode
	err := decodeJSON(encoded, &decoded)
	if err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if decoded.ID != node.ID {
		t.Errorf("ID mismatch: got %q, want %q", decoded.ID, node.ID)
	}
	if decoded.Summary != node.Summary {
		t.Errorf("Summary mismatch: got %q, want %q", decoded.Summary, node.Summary)
	}
	if decoded.TokenCount != node.TokenCount {
		t.Errorf("TokenCount mismatch: got %d, want %d", decoded.TokenCount, node.TokenCount)
	}
}

func TestActionTypes(t *testing.T) {
	tests := []struct {
		action   Action
		wantType string
	}{
		{
			action:   Action{Type: ActionClick, Selector: "button", Description: "Click"},
			wantType: "click",
		},
		{
			action:   Action{Type: ActionFill, Selector: "input", Description: "Fill"},
			wantType: "fill",
		},
		{
			action:   Action{Type: ActionSelect, Selector: "select", Description: "Select"},
			wantType: "select",
		},
		{
			action:   Action{Type: ActionToggle, Selector: "checkbox", Description: "Toggle"},
			wantType: "toggle",
		},
	}

	for _, tt := range tests {
		if string(tt.action.Type) != tt.wantType {
			t.Errorf("expected type %s, got %s", tt.wantType, tt.action.Type)
		}
	}
}

func abs32(x float32) float32 {
	if x < 0 {
		return -x
	}
	return x
}
