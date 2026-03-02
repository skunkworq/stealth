package semantic

import "time"

type ImageRef struct {
	URL               string `json:"url"`
	Alt               string `json:"alt,omitempty"`
	Description       string `json:"description,omitempty"`
	URLHash           string `json:"url_hash"`
	DescriptionTokens uint32 `json:"description_tokens,omitempty"`
}

type SemanticNode struct {
	ID                string         `json:"id"`
	Summary           string         `json:"summary"`
	Embedding         []float32      `json:"embedding,omitempty"`
	StructuralHash    string         `json:"structural_hash"`
	IsDynamic         bool           `json:"is_dynamic"`
	DynamicSelector   string         `json:"dynamic_selector,omitempty"`
	Children          []SemanticNode `json:"children,omitempty"`
	Actions           []Action       `json:"actions,omitempty"`
	Images            []ImageRef     `json:"images,omitempty"`
	DOMSelector       string         `json:"dom_selector"`
	TokenCount        uint32         `json:"token_count"`
	SubtreeTokenCount uint32         `json:"subtree_token_count"`
	Stable            bool           `json:"stable,omitempty"`
	RawText           string         `json:"raw_text,omitempty"`
	RawTextTokens     uint32         `json:"raw_text_tokens,omitempty"`
}

type SemanticTree struct {
	URL                  string         `json:"url"`
	Domain               string         `json:"domain"`
	Title                string         `json:"title"`
	RootNodes            []SemanticNode `json:"root_nodes"`
	CompressedTokenCount uint32         `json:"compressed_token_count"`
	FullTokenCount       uint32         `json:"full_token_count"`
	StructuralHash       string         `json:"structural_hash"`
	CreatedAt            time.Time      `json:"created_at"`
	DynamicSlotsFilledAt time.Time      `json:"dynamic_slots_filled_at"`
}

func (n *SemanticNode) Find(id string) *SemanticNode {
	if n.ID == id {
		return n
	}
	for i := range n.Children {
		if found := n.Children[i].Find(id); found != nil {
			return found
		}
	}
	return nil
}

func (n *SemanticNode) FindMut(id string) *SemanticNode {
	if n.ID == id {
		return n
	}
	for i := range n.Children {
		if found := n.Children[i].FindMut(id); found != nil {
			return found
		}
	}
	return nil
}

func (n *SemanticNode) IterDepthFirst() []*SemanticNode {
	result := []*SemanticNode{n}
	for i := range n.Children {
		result = append(result, n.Children[i].IterDepthFirst()...)
	}
	return result
}

func (n *SemanticNode) IterLeaves() []*SemanticNode {
	if len(n.Children) == 0 {
		return []*SemanticNode{n}
	}
	var result []*SemanticNode
	for i := range n.Children {
		result = append(result, n.Children[i].IterLeaves()...)
	}
	return result
}

func (n *SemanticNode) UnfoldCost() uint32 {
	if len(n.Children) > 0 {
		if n.SubtreeTokenCount > n.TokenCount {
			return n.SubtreeTokenCount - n.TokenCount
		}
		return 0
	}
	return n.RawTextTokens
}

func (n *SemanticNode) IsFoldable() bool {
	return len(n.Children) > 0 || n.RawText != ""
}

func (t *SemanticTree) FindNode(id string) *SemanticNode {
	for i := range t.RootNodes {
		if found := t.RootNodes[i].Find(id); found != nil {
			return found
		}
	}
	return nil
}

func (t *SemanticTree) FindNodeMut(id string) *SemanticNode {
	for i := range t.RootNodes {
		if found := t.RootNodes[i].FindMut(id); found != nil {
			return found
		}
	}
	return nil
}

func (t *SemanticTree) AllNodes() []*SemanticNode {
	var result []*SemanticNode
	for i := range t.RootNodes {
		result = append(result, t.RootNodes[i].IterDepthFirst()...)
	}
	return result
}

func (t *SemanticTree) AncestorPath(targetID string) []string {
	var findPath func(node *SemanticNode, target string, path []string) ([]string, bool)
	findPath = func(node *SemanticNode, target string, path []string) ([]string, bool) {
		if node.ID == target {
			return path, true
		}
		path = append(path, node.ID)
		for i := range node.Children {
			if found, ok := findPath(&node.Children[i], target, path); ok {
				return found, true
			}
		}
		return path[:len(path)-1], false
	}

	for i := range t.RootNodes {
		if path, ok := findPath(&t.RootNodes[i], targetID, nil); ok {
			return path
		}
	}
	return nil
}

func (t *SemanticTree) CompressionRatio() float32 {
	if t.FullTokenCount == 0 {
		return 0
	}
	return float32(t.CompressedTokenCount) / float32(t.FullTokenCount)
}
