package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stealth/brwslab/brws/pipeline"
	"github.com/stealth/brwslab/brws/semantic"
)

func TestSemanticNavigator_NavigateWithIntent(t *testing.T) {
	pipe, err := pipeline.NewPipeline(&pipeline.Config{
		RequestTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Skipf("pipeline init failed: %v", err)
	}
	defer pipe.Close()

	navigator := NewSemanticNavigator(nil, pipe)

	ctx := context.Background()
	result, err := navigator.NavigateWithIntent(ctx, "https://httpbin.org/html", "click")

	if err != nil {
		t.Fatalf("NavigateWithIntent failed: %v", err)
	}

	if result.URL != "https://httpbin.org/html" {
		t.Errorf("URL mismatch: got %s", result.URL)
	}

	if result.SemanticTree == nil {
		t.Error("SemanticTree is nil")
	}

	if result.CompressionStats == nil {
		t.Error("CompressionStats is nil")
	}

	if result.OriginalTokens <= 0 {
		t.Errorf("OriginalTokens should be > 0, got %d", result.OriginalTokens)
	}

	if result.CompressedTokens <= 0 {
		t.Errorf("CompressedTokens should be > 0, got %d", result.CompressedTokens)
	}

	t.Logf("✓ %s → %d tokens (%.1f%% compression)",
		result.URL, result.CompressedTokens,
		100.0-float64(result.CompressionStats.CompressionRatio()))
}

func TestSemanticNavigator_FindRelevantActions(t *testing.T) {
	pipe, err := pipeline.NewPipeline(&pipeline.Config{
		RequestTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Skipf("pipeline init failed: %v", err)
	}
	defer pipe.Close()

	navigator := NewSemanticNavigator(nil, pipe)

	result, err := navigator.NavigateWithIntent(context.Background(), "https://httpbin.org/html", "link")
	if err != nil {
		t.Fatalf("NavigateWithIntent failed: %v", err)
	}

	if len(result.ActionsTaken) == 0 {
		t.Log("No actions found with 'link' intent")
	}

	for _, action := range result.ActionsTaken {
		t.Logf("Found action: %s [%s] - %s", action.Type, action.Selector, action.Description)
	}
}

func TestSemanticNavigator_GetTree(t *testing.T) {
	pipe, err := pipeline.NewPipeline(&pipeline.Config{
		RequestTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Skipf("pipeline init failed: %v", err)
	}
	defer pipe.Close()

	navigator := NewSemanticNavigator(nil, pipe)

	url := "https://httpbin.org/html"
	_, err = navigator.NavigateWithIntent(context.Background(), url, "")
	if err != nil {
		t.Fatalf("NavigateWithIntent failed: %v", err)
	}

	tree := navigator.GetTree(url)
	if tree == nil {
		t.Error("GetTree returned nil")
	}

	tree2 := navigator.GetTree("https://nonexistent.example.com")
	if tree2 != nil {
		t.Error("GetTree should return nil for unknown URLs")
	}
}

func TestSemanticNavigator_ExtractAndNavigate(t *testing.T) {
	pipe, err := pipeline.NewPipeline(&pipeline.Config{
		RequestTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Skipf("pipeline init failed: %v", err)
	}
	defer pipe.Close()

	navigator := NewSemanticNavigator(nil, pipe)

	result, err := navigator.ExtractAndNavigate(context.Background(), "https://httpbin.org/html", "h1")
	if err != nil {
		t.Fatalf("ExtractAndNavigate failed: %v", err)
	}

	if result.SemanticTree == nil {
		t.Error("SemanticTree is nil")
	}

	t.Logf("Actions taken: %d", len(result.ActionsTaken))
}

func TestFindActionBySelector(t *testing.T) {
	tree := &semantic.SemanticTree{
		RootNodes: []semantic.SemanticNode{
			{
				DOMSelector: "body",
				Actions: []semantic.Action{
					{Type: semantic.ActionClick, Selector: "button.submit", Description: "Submit form"},
				},
				Children: []semantic.SemanticNode{
					{
						DOMSelector: "body/div",
						Actions: []semantic.Action{
							{Type: semantic.ActionClick, Selector: "a.link", Description: "Navigate"},
						},
					},
				},
			},
		},
	}

	navigator := &SemanticNavigator{}

	action := navigator.findActionBySelector(tree, "button.submit")
	if action == nil {
		t.Fatal("should find action")
	}
	if action.Selector != "button.submit" {
		t.Errorf("wrong selector: %s", action.Selector)
	}

	action = navigator.findActionBySelector(tree, "a.link")
	if action == nil {
		t.Fatal("should find nested action")
	}

	action = navigator.findActionBySelector(tree, "nonexistent")
	if action != nil {
		t.Error("should not find nonexistent action")
	}
}

func TestFindActionByDescription(t *testing.T) {
	tree := &semantic.SemanticTree{
		RootNodes: []semantic.SemanticNode{
			{
				DOMSelector: "body",
				Actions: []semantic.Action{
					{Type: semantic.ActionClick, Selector: "button", Description: "Submit the form now"},
				},
			},
		},
	}

	navigator := &SemanticNavigator{}

	action := navigator.findActionByDescription(tree, "submit")
	if action == nil {
		t.Fatal("should find action by description")
	}

	action = navigator.findActionByDescription(tree, "Submit the form now")
	if action == nil {
		t.Fatal("should find action with exact description")
	}

	action = navigator.findActionByDescription(tree, "nonexistent")
	if action != nil {
		t.Error("should not find nonexistent action")
	}
}
