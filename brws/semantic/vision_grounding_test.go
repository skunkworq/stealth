package semantic

import (
	"testing"
)

func TestExtractVisualGrounding(t *testing.T) {
	html := `<!DOCTYPE html>
<html>
<body>
	<header>
		<nav>
			<a href="/">Home</a>
			<a href="/about">About</a>
		</nav>
	</header>
	
	<main>
		<h1>Welcome</h1>
		<p>This is a paragraph with some text.</p>
		
		<form action="/search">
			<input type="text" name="q" placeholder="Search">
			<button type="submit">Search</button>
		</form>
		
		<img src="image.jpg" alt="An image">
	</main>
	
	<footer>
		<p>© 2024</p>
	</footer>
</body>
</html>`

	grounding := ExtractVisualGrounding(html, 1280, 800)

	if grounding == nil {
		t.Fatal("Expected visual grounding")
	}

	t.Logf("Found %d visual elements", len(grounding.Elements))
	t.Logf("Page: %dx%d, Viewport: %dx%d",
		grounding.PageWidth, grounding.PageHeight,
		grounding.ViewportWidth, grounding.ViewportHeight)

	if len(grounding.Elements) == 0 {
		t.Error("Expected at least one visual element")
	}

	count := make(map[string]int)
	for _, el := range grounding.Elements {
		count[el.TagName]++
	}

	for tag, n := range count {
		t.Logf("  %s: %d", tag, n)
	}
}

func TestVisualElementBoundingBox(t *testing.T) {
	elements := []VisualElement{
		{
			NodeID:      "vis_0",
			BoundingBox: BoundingBox{X: 0, Y: 0, Width: 100, Height: 50},
		},
		{
			NodeID:      "vis_1",
			BoundingBox: BoundingBox{X: 100, Y: 0, Width: 200, Height: 100},
		},
		{
			NodeID:      "vis_2",
			BoundingBox: BoundingBox{X: 0, Y: 50, Width: 300, Height: 150},
		},
	}

	grounding := &VisualGrounding{
		Elements:       elements,
		PageWidth:      1280,
		PageHeight:     800,
		ViewportWidth:  1280,
		ViewportHeight: 800,
	}

	t.Run("find_by_coordinates", func(t *testing.T) {
		el := grounding.FindByCoordinates(50, 25)
		if el == nil {
			t.Error("Expected to find element at (50, 25)")
		} else if el.NodeID != "vis_0" {
			t.Errorf("Expected vis_0, got %s", el.NodeID)
		}

		el = grounding.FindByCoordinates(150, 50)
		if el == nil {
			t.Error("Expected to find element at (150, 50)")
		} else if el.NodeID != "vis_1" {
			t.Errorf("Expected vis_1, got %s", el.NodeID)
		}

		el = grounding.FindByCoordinates(500, 500)
		if el != nil {
			t.Error("Expected no element at (500, 500)")
		}
	})

	t.Run("get_visible_elements", func(t *testing.T) {
		for i := range elements {
			elements[i].IsVisible = i < 2
			elements[i].Visibility = 0.5
		}

		visible := grounding.GetVisibleElements()
		if len(visible) != 2 {
			t.Errorf("Expected 2 visible elements, got %d", len(visible))
		}
	})
}

func TestBoundingBoxEstimation(t *testing.T) {
	tests := []struct {
		tag         string
		text        string
		expectedMin float64
	}{
		{"h1", "Title", 40},
		{"p", "A paragraph of text", 20},
		{"button", "Click", 40},
		{"input", "", 40},
		{"img", "", 200},
		{"a", "Link", 20},
	}

	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			bb := estimateBoundingBox(tt.tag, tt.text, nil, 0, 0, nil)

			if bb.Height < tt.expectedMin {
				t.Errorf("Expected height >= %.0f, got %.0f", tt.expectedMin, bb.Height)
			}

			t.Logf("%s: %.0fx%.0f at (%.0f, %.0f)",
				tt.tag, bb.Width, bb.Height, bb.X, bb.Y)
		})
	}
}

func TestAttachVisualGrounding(t *testing.T) {
	tree := &SemanticTree{
		URL:   "https://example.com",
		Title: "Test",
		RootNodes: []SemanticNode{
			{
				ID:          "n0",
				Summary:     "Header",
				DOMSelector: "header",
				Children: []SemanticNode{
					{ID: "n0-0", Summary: "Navigation", DOMSelector: "nav"},
				},
			},
			{
				ID:          "n1",
				Summary:     "Main",
				DOMSelector: "main",
			},
		},
	}

	grounding := &VisualGrounding{
		Elements: []VisualElement{
			{NodeID: "vis_0", Selector: "header"},
			{NodeID: "vis_1", Selector: "nav"},
			{NodeID: "vis_2", Selector: "main"},
		},
		PageWidth:      1280,
		PageHeight:     800,
		ViewportWidth:  1280,
		ViewportHeight: 800,
	}

	AttachVisualGrounding(tree, grounding)

	t.Logf("Tree after attaching:")
	for _, root := range tree.RootNodes {
		t.Logf("  %s: %s", root.ID, root.DOMSelector)
	}
}
