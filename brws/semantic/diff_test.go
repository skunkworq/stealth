package semantic

import (
	"context"
	"testing"
)

func TestComputeDiffIdenticalTrees(t *testing.T) {
	tree := &SemanticTree{
		URL:            "https://example.com",
		StructuralHash: "abc123",
		RootNodes: []SemanticNode{
			{
				ID:             "node1",
				Summary:        "Header section",
				StructuralHash: "hash1",
				DOMSelector:    "header",
			},
			{
				ID:             "node2",
				Summary:        "Main content",
				StructuralHash: "hash2",
				DOMSelector:    "main",
			},
		},
	}

	diff := ComputeDiff(tree, tree)

	if diff.HasChanges() {
		t.Error("Expected no changes for identical trees")
	}
	if diff.UnchangedCount != 2 {
		t.Errorf("Expected 2 unchanged chunks, got %d", diff.UnchangedCount)
	}
	if diff.ChangedPercent() != 0 {
		t.Errorf("Expected 0%% change, got %.1f%%", diff.ChangedPercent())
	}
}

func TestComputeDiffModifiedTree(t *testing.T) {
	oldTree := &SemanticTree{
		URL:            "https://example.com",
		StructuralHash: "old-struct",
		RootNodes: []SemanticNode{
			{
				ID:             "node1",
				Summary:        "Header section",
				StructuralHash: "hash1",
				DOMSelector:    "header",
			},
			{
				ID:             "node2",
				Summary:        "Main content",
				StructuralHash: "hash2",
				DOMSelector:    "main",
			},
		},
	}

	newTree := &SemanticTree{
		URL:            "https://example.com",
		StructuralHash: "new-struct",
		RootNodes: []SemanticNode{
			{
				ID:             "node1",
				Summary:        "Updated header",
				StructuralHash: "hash1-v2",
				DOMSelector:    "header",
			},
			{
				ID:             "node2",
				Summary:        "Main content",
				StructuralHash: "hash2",
				DOMSelector:    "main",
			},
		},
	}

	diff := ComputeDiff(oldTree, newTree)

	if !diff.HasChanges() {
		t.Error("Expected changes detected")
	}
	if len(diff.ChangedChunks) != 1 {
		t.Errorf("Expected 1 changed chunk, got %d", len(diff.ChangedChunks))
	}
	if diff.ChangedChunks[0].Selector != "header" {
		t.Errorf("Expected 'header' selector, got %s", diff.ChangedChunks[0].Selector)
	}
	if diff.ChangedChunks[0].OldSummary != "Header section" {
		t.Errorf("Expected old summary 'Header section', got %s", diff.ChangedChunks[0].OldSummary)
	}
	if diff.ChangedChunks[0].NewSummary != "Updated header" {
		t.Errorf("Expected new summary 'Updated header', got %s", diff.ChangedChunks[0].NewSummary)
	}
	if diff.UnchangedCount != 1 {
		t.Errorf("Expected 1 unchanged node, got %d", diff.UnchangedCount)
	}
}

func TestComputeDiffAddedNodes(t *testing.T) {
	oldTree := &SemanticTree{
		URL:            "https://example.com",
		StructuralHash: "old",
		RootNodes: []SemanticNode{
			{
				ID:             "node1",
				StructuralHash: "h1",
				DOMSelector:    "header",
			},
		},
	}

	newTree := &SemanticTree{
		URL:            "https://example.com",
		StructuralHash: "new",
		RootNodes: []SemanticNode{
			{
				ID:             "node1",
				StructuralHash: "h1",
				DOMSelector:    "header",
			},
			{
				ID:             "node2",
				Summary:        "New footer",
				StructuralHash: "h2",
				DOMSelector:    "footer",
			},
		},
	}

	diff := ComputeDiff(oldTree, newTree)

	if len(diff.AddedChunks) != 1 {
		t.Errorf("Expected 1 added chunk, got %d", len(diff.AddedChunks))
	}
	if diff.AddedChunks[0] != "footer" {
		t.Errorf("Expected 'footer' in added, got %s", diff.AddedChunks[0])
	}
	if len(diff.ChangedChunks) != 0 {
		t.Errorf("Expected 0 changed chunks, got %d", len(diff.ChangedChunks))
	}
}

func TestComputeDiffRemovedNodes(t *testing.T) {
	oldTree := &SemanticTree{
		URL:            "https://example.com",
		StructuralHash: "old",
		RootNodes: []SemanticNode{
			{
				ID:             "node1",
				StructuralHash: "h1",
				DOMSelector:    "header",
			},
			{
				ID:             "node2",
				StructuralHash: "h2",
				DOMSelector:    "footer",
			},
		},
	}

	newTree := &SemanticTree{
		URL:            "https://example.com",
		StructuralHash: "new",
		RootNodes: []SemanticNode{
			{
				ID:             "node1",
				StructuralHash: "h1",
				DOMSelector:    "header",
			},
		},
	}

	diff := ComputeDiff(oldTree, newTree)

	if len(diff.RemovedChunks) != 1 {
		t.Errorf("Expected 1 removed chunk, got %d", len(diff.RemovedChunks))
	}
	if diff.RemovedChunks[0] != "footer" {
		t.Errorf("Expected 'footer' in removed, got %s", diff.RemovedChunks[0])
	}
}

func TestComputeDiffWithActions(t *testing.T) {
	oldTree := &SemanticTree{
		URL:            "https://example.com",
		StructuralHash: "old",
		RootNodes: []SemanticNode{
			{
				ID:             "btn1",
				Summary:        "Button",
				StructuralHash: "h1",
				DOMSelector:    "#submit",
				Actions: []Action{
					{Type: ActionClick, Selector: "#old-submit"},
				},
			},
		},
	}

	newTree := &SemanticTree{
		URL:            "https://example.com",
		StructuralHash: "new",
		RootNodes: []SemanticNode{
			{
				ID:             "btn1",
				Summary:        "Button",
				StructuralHash: "h1-v2",
				DOMSelector:    "#submit",
				Actions: []Action{
					{Type: ActionClick, Selector: "#new-submit"},
				},
			},
		},
	}

	diff := ComputeDiff(oldTree, newTree)

	if len(diff.ChangedChunks) != 1 {
		t.Fatalf("Expected 1 changed chunk, got %d", len(diff.ChangedChunks))
	}
	if len(diff.ChangedChunks[0].FieldChanges) != 1 {
		t.Fatalf("Expected 1 field change, got %d", len(diff.ChangedChunks[0].FieldChanges))
	}
	fc := diff.ChangedChunks[0].FieldChanges[0]
	if fc.Field != "action.click" {
		t.Errorf("Expected field 'action.click', got %s", fc.Field)
	}
	if fc.OldValue != "#old-submit" {
		t.Errorf("Expected old value '#old-submit', got %s", fc.OldValue)
	}
	if fc.NewValue != "#new-submit" {
		t.Errorf("Expected new value '#new-submit', got %s", fc.NewValue)
	}
}

func TestComputeDiffNestedNodes(t *testing.T) {
	oldTree := &SemanticTree{
		URL:            "https://example.com",
		StructuralHash: "old",
		RootNodes: []SemanticNode{
			{
				ID:             "root",
				StructuralHash: "h-root",
				DOMSelector:    "#app",
				Children: []SemanticNode{
					{
						ID:             "child1",
						StructuralHash: "h1",
						DOMSelector:    "#app > .content",
					},
					{
						ID:             "child2",
						StructuralHash: "h2",
						DOMSelector:    "#app > .sidebar",
					},
				},
			},
		},
	}

	newTree := &SemanticTree{
		URL:            "https://example.com",
		StructuralHash: "new",
		RootNodes: []SemanticNode{
			{
				ID:             "root",
				StructuralHash: "h-root",
				DOMSelector:    "#app",
				Children: []SemanticNode{
					{
						ID:             "child1",
						StructuralHash: "h1-v2",
						DOMSelector:    "#app > .content",
					},
					{
						ID:             "child3",
						StructuralHash: "h3",
						DOMSelector:    "#app > .footer",
					},
				},
			},
		},
	}

	diff := ComputeDiff(oldTree, newTree)

	if len(diff.ChangedChunks) != 1 {
		t.Errorf("Expected 1 changed chunk (content), got %d", len(diff.ChangedChunks))
	}
	if len(diff.RemovedChunks) != 1 {
		t.Errorf("Expected 1 removed chunk (sidebar), got %d", len(diff.RemovedChunks))
	}
	if len(diff.AddedChunks) != 1 {
		t.Errorf("Expected 1 added chunk (footer), got %d", len(diff.AddedChunks))
	}
}

func TestDiffResultSummary(t *testing.T) {
	tests := []struct {
		name string
		diff *DiffResult
		want string
	}{
		{
			name: "no changes",
			diff: &DiffResult{
				UnchangedCount: 5,
				TotalChunks:    5,
			},
			want: "No changes detected (5 chunks identical)",
		},
		{
			name: "with changes",
			diff: &DiffResult{
				ChangedChunks: make([]ChunkDiff, 2),
				AddedChunks:   []string{"a", "b"},
				RemovedChunks: []string{"c"},
				TotalChunks:   10,
			},
			want: "Changed: 2, Added: 2, Removed: 1 (50.0% of 10 chunks)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.diff.Summary(); got != tt.want {
				t.Errorf("Summary() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIncrementalUpdater(t *testing.T) {
	config := &PipelineConfig{}
	updater := NewIncrementalUpdater(nil, config)

	html1 := `<!DOCTYPE html><html><body><div id="content">Old content</div></body></html>`
	html2 := `<!DOCTYPE html><html><body><div id="content">New content</div></body></html>`

	tree1, diff1, err := updater.Update(context.TODO(), "https://example.com", html1)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if len(diff1.AddedChunks) != 1 || diff1.AddedChunks[0] != "all" {
		t.Error("First update should mark all as added")
	}

	tree2, diff2, err := updater.Update(context.TODO(), "https://example.com", html2)
	if err != nil {
		t.Fatalf("Second update failed: %v", err)
	}

	_ = tree1
	_ = tree2
	_ = diff2

	if updater.GetPrevious("https://example.com") == nil {
		t.Error("Previous tree should be stored")
	}

	updater.Clear("https://example.com")
	if updater.GetPrevious("https://example.com") != nil {
		t.Error("Clear should remove previous tree")
	}
}

func TestIncrementalUpdaterClearAll(t *testing.T) {
	config := &PipelineConfig{}
	updater := NewIncrementalUpdater(nil, config)

	updater.previous["url1"] = &SemanticTree{URL: "url1"}
	updater.previous["url2"] = &SemanticTree{URL: "url2"}

	updater.ClearAll()

	if len(updater.previous) != 0 {
		t.Errorf("ClearAll should empty previous map, got %d items", len(updater.previous))
	}
}
