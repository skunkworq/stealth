package bench

import (
	"context"
	"testing"

	"github.com/skunkworq/stealth/brws/semantic"
)

func TestBenchmarkSuite(t *testing.T) {
	ctx := context.Background()

	config := &semantic.PipelineConfig{
		MaxDepth:      3,
		MinContentLen: 50,
	}

	suite := NewSuite(config, nil)

	t.Run("run_file", func(t *testing.T) {
		html := `<!DOCTYPE html>
<html>
<head><title>Test Page</title></head>
<body>
<h1>Welcome</h1>
<p>This is a test paragraph with some content.</p>
<nav>
  <a href="/home">Home</a>
  <a href="/about">About</a>
</nav>
<form action="/submit">
  <input type="text" name="query" placeholder="Search">
  <button type="submit">Go</button>
</form>
</body>
</html>`

		result := suite.RunFile(ctx, html, "https://example.com/test")

		if result.Error != "" {
			t.Logf("Expected error without LLM: %s", result.Error)
		}
		if result.HTMLSize > 0 {
			t.Logf("HTML size: %d bytes", result.HTMLSize)
		}
	})

	t.Run("run_url_invalid", func(t *testing.T) {
		result := suite.RunURL(ctx, "https://invalid.example.localhost:99999/")
		if result.Error == "" {
			t.Error("expected error for invalid URL")
		}
		t.Logf("Got expected error: %s", result.Error)
	})

	t.Run("summary", func(t *testing.T) {
		results := []*Result{
			{
				URL:              "https://a.com",
				TokenCount:       1000,
				CompressedTokens: 10,
				HTMLSize:         4000,
			},
			{
				URL:              "https://b.com",
				TokenCount:       2000,
				CompressedTokens: 20,
				HTMLSize:         8000,
			},
			{
				URL:   "https://c.com",
				Error: "failed",
			},
		}

		summary := suite.Summary(results)

		if summary.TotalPages != 3 {
			t.Errorf("expected 3 pages, got %d", summary.TotalPages)
		}
		if summary.SuccessRate != 2.0/3.0 {
			t.Errorf("expected success rate 0.66, got %.2f", summary.SuccessRate)
		}
		if summary.Errors != 1 {
			t.Errorf("expected 1 error, got %d", summary.Errors)
		}
		if summary.TokensSaved != 2970 {
			t.Errorf("expected 2970 tokens saved, got %d", summary.TokensSaved)
		}

		t.Log(summary.String())
	})
}

func TestNodeDepth(t *testing.T) {
	deep := semantic.SemanticNode{
		ID: "root",
		Children: []semantic.SemanticNode{
			{
				ID: "child1",
				Children: []semantic.SemanticNode{
					{ID: "grandchild1"},
				},
			},
			{ID: "child2"},
		},
	}

	depth := nodeDepth(deep, 1)
	if depth != 3 {
		t.Errorf("expected depth 3, got %d", depth)
	}

	flat := semantic.SemanticNode{ID: "single"}
	depth = nodeDepth(flat, 1)
	if depth != 1 {
		t.Errorf("expected depth 1 for flat node, got %d", depth)
	}
}
