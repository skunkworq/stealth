package semantic

import (
	"context"
	"fmt"
)

type DiffResult struct {
	URL            string
	OldHash        string
	NewHash        string
	ChangedChunks  []ChunkDiff
	AddedChunks    []string
	RemovedChunks  []string
	UnchangedCount int
	TotalChunks    int
}

type ChunkDiff struct {
	Selector     string
	OldHash      string
	NewHash      string
	OldSummary   string
	NewSummary   string
	FieldChanges []FieldDiff
}

type FieldDiff struct {
	Field    string
	OldValue string
	NewValue string
}

func ComputeDiff(oldTree, newTree *SemanticTree) *DiffResult {
	result := &DiffResult{
		URL:           newTree.URL,
		OldHash:       oldTree.StructuralHash,
		NewHash:       newTree.StructuralHash,
		ChangedChunks: make([]ChunkDiff, 0),
		AddedChunks:   make([]string, 0),
		RemovedChunks: make([]string, 0),
	}

	if oldTree.StructuralHash == newTree.StructuralHash {
		result.TotalChunks = countAllNodes(newTree)
		result.UnchangedCount = result.TotalChunks
		return result
	}

	oldNodes := indexNodesBySelector(oldTree)
	newNodes := indexNodesBySelector(newTree)

	for selector, oldNode := range oldNodes {
		if newNode, exists := newNodes[selector]; exists {
			if oldNode.StructuralHash != newNode.StructuralHash {
				diff := ChunkDiff{
					Selector:   selector,
					OldHash:    oldNode.StructuralHash,
					NewHash:    newNode.StructuralHash,
					OldSummary: oldNode.Summary,
					NewSummary: newNode.Summary,
				}

				if len(oldNode.Actions) > 0 || len(newNode.Actions) > 0 {
					actionDiff := computeActionDiff(oldNode.Actions, newNode.Actions)
					for _, ad := range actionDiff {
						diff.FieldChanges = append(diff.FieldChanges, FieldDiff{
							Field:    fmt.Sprintf("action.%s", ad.Type),
							OldValue: ad.OldSelector,
							NewValue: ad.NewSelector,
						})
					}
				}

				result.ChangedChunks = append(result.ChangedChunks, diff)
			} else {
				result.UnchangedCount++
			}
		} else {
			result.RemovedChunks = append(result.RemovedChunks, selector)
		}
	}

	for selector := range newNodes {
		if _, exists := oldNodes[selector]; !exists {
			result.AddedChunks = append(result.AddedChunks, selector)
		}
	}

	result.TotalChunks = len(newNodes)

	return result
}

func indexNodesBySelector(tree *SemanticTree) map[string]*SemanticNode {
	nodes := make(map[string]*SemanticNode)
	for i := range tree.RootNodes {
		indexNodeRecursive(&tree.RootNodes[i], nodes)
	}
	return nodes
}

func indexNodeRecursive(node *SemanticNode, nodes map[string]*SemanticNode) {
	if node.DOMSelector != "" {
		nodes[node.DOMSelector] = node
	}
	for i := range node.Children {
		indexNodeRecursive(&node.Children[i], nodes)
	}
}

func countAllNodes(tree *SemanticTree) int {
	count := 0
	for i := range tree.RootNodes {
		count += countNodesRecursive(&tree.RootNodes[i])
	}
	return count
}

func countNodesRecursive(node *SemanticNode) int {
	count := 1
	for i := range node.Children {
		count += countNodesRecursive(&node.Children[i])
	}
	return count
}

type ActionDiff struct {
	Type        string
	OldSelector string
	NewSelector string
}

func computeActionDiff(oldActions, newActions []Action) []ActionDiff {
	var diffs []ActionDiff

	oldByType := make(map[string]*Action)
	for i := range oldActions {
		oldByType[string(oldActions[i].Type)] = &oldActions[i]
	}

	newByType := make(map[string]*Action)
	for i := range newActions {
		newByType[string(newActions[i].Type)] = &newActions[i]
	}

	for actionType, oldAction := range oldByType {
		if newAction, exists := newByType[actionType]; exists {
			if oldAction.Selector != newAction.Selector {
				diffs = append(diffs, ActionDiff{
					Type:        actionType,
					OldSelector: oldAction.Selector,
					NewSelector: newAction.Selector,
				})
			}
		}
	}

	return diffs
}

func (d *DiffResult) HasChanges() bool {
	return len(d.ChangedChunks) > 0 || len(d.AddedChunks) > 0 || len(d.RemovedChunks) > 0
}

func (d *DiffResult) ChangedPercent() float64 {
	if d.TotalChunks == 0 {
		return 0
	}
	changed := len(d.ChangedChunks) + len(d.AddedChunks) + len(d.RemovedChunks)
	return float64(changed) / float64(d.TotalChunks) * 100
}

func (d *DiffResult) Summary() string {
	if !d.HasChanges() {
		return fmt.Sprintf("No changes detected (%d chunks identical)", d.UnchangedCount)
	}

	return fmt.Sprintf("Changed: %d, Added: %d, Removed: %d (%.1f%% of %d chunks)",
		len(d.ChangedChunks), len(d.AddedChunks), len(d.RemovedChunks),
		d.ChangedPercent(), d.TotalChunks)
}

type IncrementalUpdater struct {
	cache    *CacheStore
	config   *PipelineConfig
	previous map[string]*SemanticTree
}

func NewIncrementalUpdater(cache *CacheStore, config *PipelineConfig) *IncrementalUpdater {
	return &IncrementalUpdater{
		cache:    cache,
		config:   config,
		previous: make(map[string]*SemanticTree),
	}
}

func (u *IncrementalUpdater) Update(ctx context.Context, url, html string) (*SemanticTree, *DiffResult, error) {
	newTree, _, err := HTMLToSemanticTree(ctx, html, url, u.config)
	if err != nil {
		return nil, nil, err
	}

	var diff *DiffResult
	if oldTree, exists := u.previous[url]; exists {
		diff = ComputeDiff(oldTree, newTree)

		if !diff.HasChanges() {
			newTree = oldTree
		}
	} else {
		diff = &DiffResult{
			URL:         url,
			NewHash:     newTree.StructuralHash,
			AddedChunks: []string{"all"},
			TotalChunks: countAllNodes(newTree),
		}
	}

	u.previous[url] = newTree

	return newTree, diff, nil
}

func (u *IncrementalUpdater) GetPrevious(url string) *SemanticTree {
	return u.previous[url]
}

func (u *IncrementalUpdater) Clear(url string) {
	delete(u.previous, url)
}

func (u *IncrementalUpdater) ClearAll() {
	u.previous = make(map[string]*SemanticTree)
}
