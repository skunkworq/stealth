package integration

import (
	"context"
	"math"
	"sync"
	"time"

	"github.com/skunkworq/stealth/brws/content/semantic"
)

type ChangeDetector struct {
	previous           sync.Map // map[string]*semantic.SemanticTree
	threshold          float32
	significantChanges sync.Map // map[string][]Change
}

type Change struct {
	Type         ChangeType
	Path         string
	Selector     string
	OldValue     string
	NewValue     string
	Significance float32
	Timestamp    time.Time
}

type ChangeType string

const (
	ChangeAdded    ChangeType = "added"
	ChangeRemoved  ChangeType = "removed"
	ChangeModified ChangeType = "modified"
	ChangeMoved    ChangeType = "moved"
)

type ChangeResult struct {
	URL                string
	HasChanges         bool
	TotalChanges       int
	StructuralHash     string
	Changes            []Change
	SignificantChanges []Change
	Duration           time.Duration
}

type ChangeFilter func(Change) bool

func NewChangeDetector(threshold float32) *ChangeDetector {
	return &ChangeDetector{
		threshold: threshold,
	}
}

func (d *ChangeDetector) DetectChanges(ctx context.Context, url string, newTree *semantic.SemanticTree) (*ChangeResult, error) {
	start := time.Now()
	result := &ChangeResult{
		URL:                url,
		HasChanges:         false,
		Changes:            make([]Change, 0),
		SignificantChanges: make([]Change, 0),
	}

	if val, ok := d.previous.Load(url); ok {
		oldTree := val.(*semantic.SemanticTree)

		if oldTree.StructuralHash == newTree.StructuralHash {
			result.StructuralHash = newTree.StructuralHash
			result.Duration = time.Since(start)
			return result, nil
		}

		changes := d.diffTrees(oldTree, newTree)
		result.Changes = changes
		result.TotalChanges = len(changes)
		result.HasChanges = len(changes) > 0

		significant := d.filterSignificant(changes)
		result.SignificantChanges = significant
	}

	d.previous.Store(url, newTree)
	result.StructuralHash = newTree.StructuralHash
	result.Duration = time.Since(start)

	return result, nil
}

func (d *ChangeDetector) diffTrees(old, new *semantic.SemanticTree) []Change {
	changes := make([]Change, 0)

	oldNodes := d.indexBySelector(old)
	newNodes := d.indexBySelector(new)

	for selector, oldNode := range oldNodes {
		if newNode, exists := newNodes[selector]; !exists {
			changes = append(changes, Change{
				Type:         ChangeRemoved,
				Path:         selector,
				Selector:     selector,
				OldValue:     oldNode.Summary,
				Significance: d.calculateSignificance(oldNode),
				Timestamp:    time.Now(),
			})
		} else {
			if oldNode.Summary != newNode.Summary {
				changes = append(changes, Change{
					Type:         ChangeModified,
					Path:         selector,
					Selector:     selector,
					OldValue:     oldNode.Summary,
					NewValue:     newNode.Summary,
					Significance: d.calculateModificationSignificance(oldNode, newNode),
					Timestamp:    time.Now(),
				})
			}

			if len(oldNode.Actions) != len(newNode.Actions) {
				changes = append(changes, Change{
					Type:         ChangeModified,
					Path:         selector + ":actions",
					Selector:     selector,
					OldValue:     "actions",
					NewValue:     "actions",
					Significance: 0.8,
					Timestamp:    time.Now(),
				})
			}
		}
	}

	for selector, newNode := range newNodes {
		if _, exists := oldNodes[selector]; !exists {
			changes = append(changes, Change{
				Type:         ChangeAdded,
				Path:         selector,
				Selector:     selector,
				NewValue:     newNode.Summary,
				Significance: d.calculateSignificance(newNode),
				Timestamp:    time.Now(),
			})
		}
	}

	return changes
}

func (d *ChangeDetector) indexBySelector(tree *semantic.SemanticTree) map[string]*semantic.SemanticNode {
	index := make(map[string]*semantic.SemanticNode)

	for _, node := range tree.AllNodes() {
		if node.DOMSelector != "" {
			index[node.DOMSelector] = node
		}
	}

	return index
}

func (d *ChangeDetector) calculateSignificance(node *semantic.SemanticNode) float32 {
	significance := float32(0.5)

	if node.IsDynamic {
		significance -= 0.3
	}

	if len(node.Actions) > 0 {
		significance += 0.3
	}

	if node.TokenCount > 50 {
		significance += 0.2
	}

	if significance > 1.0 {
		significance = 1.0
	}
	if significance < 0.0 {
		significance = 0.0
	}

	return significance
}

func (d *ChangeDetector) calculateModificationSignificance(old, new *semantic.SemanticNode) float32 {
	base := d.calculateSignificance(old)

	textDiff := d.textDifference(old.Summary, new.Summary)
	if textDiff > 0.5 {
		base += 0.3
	}

	return base
}

func (d *ChangeDetector) textDifference(a, b string) float32 {
	if a == b {
		return 0.0
	}

	lenA := float64(len(a))
	lenB := float64(len(b))

	if lenA == 0 || lenB == 0 {
		return 1.0
	}

	maxLen := math.Max(lenA, lenB)
	minLen := math.Min(lenA, lenB)

	return float32(1.0 - minLen/maxLen)
}

func (d *ChangeDetector) filterSignificant(changes []Change) []Change {
	significant := make([]Change, 0)

	for _, change := range changes {
		if change.Significance >= d.threshold {
			significant = append(significant, change)
		}
	}

	return significant
}

func (d *ChangeDetector) Watch(url string, interval time.Duration, onChange func(*ChangeResult)) context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if val, ok := d.previous.Load(url); ok {
					_ = val
				}
			}
		}
	}()

	return cancel
}

func (d *ChangeDetector) GetChanges(url string) []Change {
	if val, ok := d.significantChanges.Load(url); ok {
		return val.([]Change)
	}
	return nil
}

func (d *ChangeDetector) HasSignificantChanges(url string) bool {
	changes := d.GetChanges(url)
	return len(changes) > 0
}

func (d *ChangeDetector) ClearHistory(url string) {
	d.previous.Delete(url)
	d.significantChanges.Delete(url)
}

func (d *ChangeDetector) ExportHistory() map[string][]Change {
	export := make(map[string][]Change)

	d.significantChanges.Range(func(key, value interface{}) bool {
		export[key.(string)] = value.([]Change)
		return true
	})

	return export
}

type ChangeAlert struct {
	URL       string
	Changes   []Change
	Timestamp time.Time
	Processed bool
}

type ChangeWatcher struct {
	detector    *ChangeDetector
	alerts      chan ChangeAlert
	subscribers []func(ChangeAlert)
	mu          sync.RWMutex
}

func NewChangeWatcher(detector *ChangeDetector) *ChangeWatcher {
	return &ChangeWatcher{
		detector:    detector,
		alerts:      make(chan ChangeAlert, 100),
		subscribers: make([]func(ChangeAlert), 0),
	}
}

func (w *ChangeWatcher) Subscribe(handler func(ChangeAlert)) {
	w.mu.Lock()
	w.subscribers = append(w.subscribers, handler)
	w.mu.Unlock()
}

func (w *ChangeWatcher) ProcessAlert(alert ChangeAlert) {
	w.mu.RLock()
	subscribers := w.subscribers
	w.mu.RUnlock()

	for _, handler := range subscribers {
		go handler(alert)
	}
}

func (w *ChangeWatcher) Close() {
	close(w.alerts)
}
