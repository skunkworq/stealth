package integration

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	pipeline "github.com/skunkworq/stealth/brws/crawl/ingest"
	"github.com/skunkworq/stealth/brws/content/understand"
	"github.com/skunkworq/stealth/brws/stealth"
)

type SemanticNavigator struct {
	client   *stealth.Adaptive
	pipeline *pipeline.Pipeline
	cache    *understand.CacheStore

	trees sync.Map // map[string]*understand.SemanticTree - read-heavy, sync.Map ideal
}

type NavigationResult struct {
	URL              string
	FinalURL         string
	SemanticTree     *understand.SemanticTree
	CompressionStats *understand.CompressionStats
	ActionsTaken     []ActionTaken
	CAPTCHAsSolved   int
	OriginalTokens   int
	CompressedTokens int
	Duration         time.Duration
	Error            error
}

type ActionTaken struct {
	Type        string
	Selector    string
	Description string
	Timestamp   time.Time
}

type NavigatorOption func(*SemanticNavigator)

func WithCache(cache *understand.CacheStore) NavigatorOption {
	return func(n *SemanticNavigator) {
		n.cache = cache
	}
}

func NewSemanticNavigator(client *stealth.Adaptive, pipe *pipeline.Pipeline, opts ...NavigatorOption) *SemanticNavigator {
	n := &SemanticNavigator{
		client:   client,
		pipeline: pipe,
	}

	for _, opt := range opts {
		opt(n)
	}

	return n
}

func (n *SemanticNavigator) NavigateWithIntent(ctx context.Context, url, intent string) (*NavigationResult, error) {
	start := time.Now()
	result := &NavigationResult{
		URL:          url,
		ActionsTaken: make([]ActionTaken, 0),
	}

	if n.client != nil {
		resp, err := n.client.Navigate(ctx, url)
		if err != nil {
			result.Error = err
			result.Duration = time.Since(start)
			return result, err
		}
		result.FinalURL = resp.FinalURL
	}

	var tree *understand.SemanticTree
	var stats *understand.CompressionStats

	pageResult := n.pipeline.ProcessURL(ctx, url)
	if pageResult.Error != nil {
		result.Error = pageResult.Error
		result.Duration = time.Since(start)
		return result, pageResult.Error
	}

	tree = pageResult.SemanticTree
	stats = pageResult.CompressionStats

	result.SemanticTree = tree
	result.CompressionStats = stats
	if stats != nil {
		result.OriginalTokens = int(stats.FullTreeTokens)
		result.CompressedTokens = int(stats.CompressedTokens)
	}

	if result.FinalURL == "" {
		result.FinalURL = url
	}

	n.trees.Store(url, tree)
	if result.FinalURL != url {
		n.trees.Store(result.FinalURL, tree)
	}

	if intent != "" {
		actions := n.findRelevantActions(tree, intent)
		result.ActionsTaken = actions
	}

	result.Duration = time.Since(start)

	return result, nil
}

func (n *SemanticNavigator) findRelevantActions(tree *understand.SemanticTree, intent string) []ActionTaken {
	actions := make([]ActionTaken, 0)
	if tree == nil {
		return actions
	}

	intentLower := strings.ToLower(intent)

	var walk func(node *understand.SemanticNode)
	walk = func(node *understand.SemanticNode) {
		for _, action := range node.Actions {
			desc := strings.ToLower(action.Description)
			if strings.Contains(desc, intentLower) ||
				strings.Contains(intentLower, string(action.Type)) {
				actions = append(actions, ActionTaken{
					Type:        string(action.Type),
					Selector:    action.Selector,
					Description: action.Description,
					Timestamp:   time.Now(),
				})
			}
		}

		for i := range node.Children {
			walk(&node.Children[i])
		}
	}

	for i := range tree.RootNodes {
		walk(&tree.RootNodes[i])
	}

	return actions
}

func (n *SemanticNavigator) GetTree(url string) *understand.SemanticTree {
	if val, ok := n.trees.Load(url); ok {
		return val.(*understand.SemanticTree)
	}
	return nil
}

func (n *SemanticNavigator) ExtractAndNavigate(ctx context.Context, url, targetSelector string) (*NavigationResult, error) {
	navResult, err := n.NavigateWithIntent(ctx, url, "")
	if err != nil {
		return navResult, err
	}

	tree := navResult.SemanticTree
	if tree == nil {
		return navResult, fmt.Errorf("no semantic tree extracted")
	}

	action := n.findActionBySelector(tree, targetSelector)
	if action == nil {
		action = n.findActionByDescription(tree, targetSelector)
	}

	if action != nil {
		if n.client != nil {
			clickErr := n.client.ClickSelector(ctx, action.Selector)
			if clickErr != nil {
				navResult.Error = clickErr
				return navResult, clickErr
			}
		}

		navResult.ActionsTaken = append(navResult.ActionsTaken, ActionTaken{
			Type:        "click",
			Selector:    action.Selector,
			Description: action.Description,
			Timestamp:   time.Now(),
		})
	}

	return navResult, nil
}

func (n *SemanticNavigator) findActionBySelector(tree *understand.SemanticTree, selector string) *understand.Action {
	var result *understand.Action

	var walk func(node *understand.SemanticNode)
	walk = func(node *understand.SemanticNode) {
		for i := range node.Actions {
			if strings.Contains(node.Actions[i].Selector, selector) {
				result = &node.Actions[i]
				return
			}
		}
		for i := range node.Children {
			walk(&node.Children[i])
			if result != nil {
				return
			}
		}
	}

	for i := range tree.RootNodes {
		walk(&tree.RootNodes[i])
		if result != nil {
			break
		}
	}

	return result
}

func (n *SemanticNavigator) findActionByDescription(tree *understand.SemanticTree, desc string) *understand.Action {
	var result *understand.Action
	descLower := strings.ToLower(desc)

	var walk func(node *understand.SemanticNode)
	walk = func(node *understand.SemanticNode) {
		for i := range node.Actions {
			nodeDesc := strings.ToLower(node.Actions[i].Description)
			if strings.Contains(nodeDesc, descLower) || strings.Contains(descLower, nodeDesc) {
				result = &node.Actions[i]
				return
			}
		}
		for i := range node.Children {
			walk(&node.Children[i])
			if result != nil {
				return
			}
		}
	}

	for i := range tree.RootNodes {
		walk(&tree.RootNodes[i])
		if result != nil {
			break
		}
	}

	return result
}

func (n *SemanticNavigator) Close() error {
	return n.pipeline.Close()
}
