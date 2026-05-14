package understand

import (
	"fmt"
	"strings"
)

type BoundingBox struct {
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

type VisualElement struct {
	NodeID      string      `json:"node_id"`
	Selector    string      `json:"selector"`
	TagName     string      `json:"tag_name"`
	Text        string      `json:"text,omitempty"`
	BoundingBox BoundingBox `json:"bounding_box"`
	Visibility  float64     `json:"visibility"`
	Area        float64     `json:"area"`
	IsVisible   bool        `json:"is_visible"`
	IsClickable bool        `json:"is_clickable"`
	ZIndex      int         `json:"z_index,omitempty"`
}

type VisualGrounding struct {
	Elements       []VisualElement `json:"elements"`
	PageWidth      int             `json:"page_width"`
	PageHeight     int             `json:"page_height"`
	ViewportWidth  int             `json:"viewport_width"`
	ViewportHeight int             `json:"viewport_height"`
}

type VisualRegion struct {
	ID          string
	NodeID      string
	BoundingBox BoundingBox
	Content     string
	Actions     []Action
	Children    []VisualRegion
}

func ExtractVisualGrounding(html string, viewportWidth, viewportHeight int) *VisualGrounding {
	elements := extractVisualElements(html)

	pageWidth := viewportWidth
	pageHeight := viewportHeight

	var maxBottom float64
	for _, el := range elements {
		bottom := el.BoundingBox.Y + el.BoundingBox.Height
		if bottom > maxBottom {
			maxBottom = bottom
		}
	}
	if maxBottom > float64(pageHeight) {
		pageHeight = int(maxBottom) + 100
	}

	return &VisualGrounding{
		Elements:       elements,
		PageWidth:      pageWidth,
		PageHeight:     pageHeight,
		ViewportWidth:  viewportWidth,
		ViewportHeight: viewportHeight,
	}
}

func extractVisualElements(htmlStr string) []VisualElement {
	doc, err := parseHTML(htmlStr)
	if err != nil {
		return nil
	}

	var elements []VisualElement
	yOffset := 0.0
	lineHeight := 20.0
	xOffset := 0.0
	charWidth := 8.0

	var traverse func(n interface{}, depth int, parentBB *BoundingBox)
	traverse = func(n interface{}, depth int, parentBB *BoundingBox) {
		node := n.(map[string]interface{})
		tag, _ := node["tag"].(string)

		if tag == "" || tag == "script" || tag == "style" || tag == "meta" || tag == "link" {
			return
		}

		children, _ := node["children"].([]interface{})
		text, _ := node["text"].(string)

		_ = charWidth
		bb := estimateBoundingBox(tag, text, children, xOffset, yOffset, parentBB)

		if isVisualElement(tag) {
			selector := buildSelector(node, tag, len(elements))

			el := VisualElement{
				NodeID:      fmt.Sprintf("vis_%d", len(elements)),
				Selector:    selector,
				TagName:     tag,
				BoundingBox: *bb,
				IsVisible:   bb.Width > 0 && bb.Height > 0,
				IsClickable: isClickable(tag),
				Area:        bb.Width * bb.Height,
			}

			if len(text) > 0 && len(text) < 200 {
				el.Text = strings.TrimSpace(text)
			}

			el.Visibility = calculateVisibility(bb, &BoundingBox{Width: 1920, Height: 1080})

			elements = append(elements, el)
		}

		for _, child := range children {
			traverse(child, depth+1, bb)
		}

		if tag == "br" || tag == "div" || tag == "p" || tag == "h1" || tag == "h2" || tag == "h3" {
			yOffset += lineHeight
			xOffset = 0
		}
	}

	nodes := parseNodes(doc)
	for _, node := range nodes {
		traverse(node, 0, nil)
	}

	return elements
}

func parseHTML(htmlStr string) (interface{}, error) {
	return simpleParseHTML(htmlStr), nil
}

func simpleParseHTML(htmlStr string) map[string]interface{} {
	result := make(map[string]interface{})
	result["tag"] = "html"
	result["children"] = parseChildren(htmlStr)
	return result
}

func parseChildren(htmlStr string) []interface{} {
	var children []interface{}

	tagPattern := "<([^>]+)>"
	tags := extractTags(htmlStr, tagPattern)

	textContent := extractTextContentSimple(htmlStr)

	for _, tag := range tags {
		child := map[string]interface{}{
			"tag": tag,
		}
		children = append(children, child)
	}

	if textContent != "" {
		children = append(children, map[string]interface{}{
			"text": textContent,
		})
	}

	return children
}

func extractTags(htmlStr, pattern string) []string {
	var tags []string
	for i := 0; i < len(htmlStr); i++ {
		if htmlStr[i] == '<' {
			end := strings.Index(htmlStr[i:], ">")
			if end > 0 {
				tagContent := htmlStr[i+1 : i+end]
				if len(tagContent) > 0 && tagContent[0] != '/' && tagContent[0] != '!' {
					spaceIdx := strings.Index(tagContent, " ")
					if spaceIdx > 0 {
						tagContent = tagContent[:spaceIdx]
					}
					tags = append(tags, strings.ToLower(tagContent))
				}
				i += end
			}
		}
	}
	return tags
}

func extractTextContentSimple(htmlStr string) string {
	var result strings.Builder
	inTag := false
	for i := 0; i < len(htmlStr); i++ {
		if htmlStr[i] == '<' {
			inTag = true
		} else if htmlStr[i] == '>' {
			inTag = false
		} else if !inTag {
			result.WriteByte(htmlStr[i])
		}
	}
	return strings.TrimSpace(result.String())
}

func parseNodes(doc interface{}) []map[string]interface{} {
	var nodes []map[string]interface{}
	if node, ok := doc.(map[string]interface{}); ok {
		nodes = append(nodes, node)
	}
	return nodes
}

func estimateBoundingBox(tag, text string, children []interface{}, x, y float64, parent *BoundingBox) *BoundingBox {
	bb := &BoundingBox{X: x, Y: y}

	switch tag {
	case "h1", "h2", "h3", "h4", "h5", "h6":
		bb.Width = 800
		bb.Height = 40
	case "p":
		bb.Width = 800
		bb.Height = maxFloat(20, float64(len(text))/50*20)
	case "img":
		bb.Width = 300
		bb.Height = 200
	case "video":
		bb.Width = 640
		bb.Height = 360
	case "button":
		bb.Width = maxFloat(80, float64(len(text))*10+20)
		bb.Height = 40
	case "input":
		bb.Width = 200
		bb.Height = 40
	case "nav":
		bb.Width = 1200
		bb.Height = 60
	case "header":
		bb.Width = 1200
		bb.Height = 80
	case "footer":
		bb.Width = 1200
		bb.Height = 100
	case "form":
		bb.Width = 600
		bb.Height = 200
	case "table":
		bb.Width = 800
		bb.Height = 300
	case "ul", "ol":
		bb.Width = 600
		bb.Height = 150
	case "a":
		bb.Width = maxFloat(50, float64(len(text))*10)
		bb.Height = 20
	default:
		if len(text) > 0 {
			bb.Width = minFloat(float64(len(text))*8, 800)
			bb.Height = 20
		} else {
			bb.Width = 400
			bb.Height = 100
		}
	}

	return bb
}

func isVisualElement(tag string) bool {
	visual := map[string]bool{
		"button": true, "input": true, "select": true, "textarea": true,
		"a": true, "img": true, "video": true, "iframe": true,
		"h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true,
		"p": true, "div": true, "section": true, "article": true,
		"nav": true, "header": true, "footer": true, "aside": true,
		"form": true, "table": true, "ul": true, "ol": true,
		"li": true, "span": true, "label": true,
	}
	return visual[tag]
}

func isClickable(tag string) bool {
	clickable := map[string]bool{
		"button": true, "a": true, "input": true, "select": true,
		"textarea": true, "label": true,
	}
	return clickable[tag]
}

func buildSelector(node map[string]interface{}, tag string, index int) string {
	return fmt.Sprintf("%s:nth-of-type(%d)", tag, (index%10)+1)
}

func calculateVisibility(bb, viewport *BoundingBox) float64 {
	if bb.Width <= 0 || bb.Height <= 0 {
		return 0
	}

	area := bb.Width * bb.Height
	viewportArea := viewport.Width * viewport.Height

	if area >= viewportArea {
		return 1.0
	}

	return area / viewportArea
}

func (vg *VisualGrounding) FindByCoordinates(x, y float64) *VisualElement {
	for i := range vg.Elements {
		el := &vg.Elements[i]
		if x >= el.BoundingBox.X && x <= el.BoundingBox.X+el.BoundingBox.Width &&
			y >= el.BoundingBox.Y && y <= el.BoundingBox.Y+el.BoundingBox.Height {
			return el
		}
	}
	return nil
}

func (vg *VisualGrounding) GetVisibleElements() []VisualElement {
	var visible []VisualElement
	for _, el := range vg.Elements {
		if el.IsVisible && el.Visibility > 0.01 {
			visible = append(visible, el)
		}
	}
	return visible
}

func (vg *VisualGrounding) GetClickableElements() []VisualElement {
	var clickable []VisualElement
	for _, el := range vg.Elements {
		if el.IsClickable && el.IsVisible {
			clickable = append(clickable, el)
		}
	}
	return clickable
}

func AttachVisualGrounding(tree *SemanticTree, grounding *VisualGrounding) {
	for i := range tree.RootNodes {
		attachVisualToNode(&tree.RootNodes[i], grounding, 0)
	}
}

func attachVisualToNode(node *SemanticNode, grounding *VisualGrounding, index int) {
	if index < len(grounding.Elements) {
		el := &grounding.Elements[index]
		if node.DOMSelector != "" {
			node.DOMSelector = el.Selector
		}
	}

	childIdx := index + 1
	for i := range node.Children {
		if childIdx < len(grounding.Elements) {
			attachVisualToNode(&node.Children[i], grounding, childIdx)
			childIdx++
		}
	}
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
