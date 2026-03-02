package integration

import (
	"context"
	"testing"

	"github.com/stealth/brwslab/brws/semantic"
)

func TestAdaptiveCrawlerSelectStrategy(t *testing.T) {
	crawler := NewAdaptiveCrawler(nil)

	tests := []struct {
		name     string
		history  *PageHistory
		expected string
	}{
		{
			name:     "no history",
			history:  nil,
			expected: "explore",
		},
		{
			name: "low success rate",
			history: &PageHistory{
				SuccessRate: 0.2,
				VisitCount:  3,
			},
			expected: "cautious_explore",
		},
		{
			name: "high success rate established",
			history: &PageHistory{
				SuccessRate: 0.9,
				VisitCount:  5,
			},
			expected: "optimized_fast",
		},
		{
			name: "visited many times",
			history: &PageHistory{
				SuccessRate: 0.7,
				VisitCount:  6,
			},
			expected: "learned",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := crawler.selectStrategy("", tt.history)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestAdaptiveCrawlerRecordSuccess(t *testing.T) {
	crawler := NewAdaptiveCrawler(nil)

	crawler.recordSuccess("test-url", "explore", 1000000000)

	history := crawler.getHistory("test-url")
	if history == nil {
		t.Fatal("expected history to be recorded")
	}

	if history.VisitCount != 1 {
		t.Errorf("expected 1 visit, got %d", history.VisitCount)
	}

	if history.SuccessRate != 1.0 {
		t.Errorf("expected 1.0 success rate, got %.2f", history.SuccessRate)
	}

	crawler.recordSuccess("test-url", "explore", 500000000)

	history = crawler.getHistory("test-url")
	if history.VisitCount != 2 {
		t.Errorf("expected 2 visits, got %d", history.VisitCount)
	}
}

func TestAdaptivePolicyGetBestStrategy(t *testing.T) {
	policy := NewAdaptivePolicy()

	policy.successfulStrategies.Store("strategy_a", &StrategyStats{
		Name:      "strategy_a",
		Successes: 80,
		Failures:  20,
	})

	policy.successfulStrategies.Store("strategy_b", &StrategyStats{
		Name:      "strategy_b",
		Successes: 30,
		Failures:  70,
	})

	best := policy.GetBestStrategy("")
	if best != "strategy_a" {
		t.Errorf("expected strategy_a, got %s", best)
	}
}

func TestAdaptivePolicyShouldRetry(t *testing.T) {
	policy := NewAdaptivePolicy()

	err := context.Canceled

	if !policy.ShouldRetry("test-url", err) {
		t.Error("should retry for new errors")
	}

	key := "test-url:context canceled"
	policy.failurePatterns.Store(key, &FailurePattern{
		Occurences: 3,
	})

	if policy.ShouldRetry("test-url", err) {
		t.Error("should not retry after 3 failures")
	}
}

func TestChangeDetectorDiffTrees(t *testing.T) {
	detector := NewChangeDetector(0.5)

	oldTree := &semantic.SemanticTree{
		RootNodes: []semantic.SemanticNode{
			{DOMSelector: "div.price", Summary: "Price: $99.99"},
			{DOMSelector: "div.title", Summary: "Product Name"},
		},
	}

	newTree := &semantic.SemanticTree{
		RootNodes: []semantic.SemanticNode{
			{DOMSelector: "div.price", Summary: "Price: $79.99"},
			{DOMSelector: "div.title", Summary: "Product Name"},
			{DOMSelector: "div.new-badge", Summary: "New!"},
		},
	}

	changes := detector.diffTrees(oldTree, newTree)

	hasPriceChange := false
	hasNewBadge := false

	for _, change := range changes {
		if change.Selector == "div.price" && change.Type == ChangeModified {
			hasPriceChange = true
		}
		if change.Selector == "div.new-badge" && change.Type == ChangeAdded {
			hasNewBadge = true
		}
	}

	if !hasPriceChange {
		t.Error("expected price change detection")
	}

	if !hasNewBadge {
		t.Error("expected new badge detection")
	}

	t.Logf("Detected %d changes", len(changes))
}

func TestChangeDetectorSignificance(t *testing.T) {
	detector := NewChangeDetector(0.5)

	tests := []struct {
		name            string
		node            *semantic.SemanticNode
		minSignificance float32
	}{
		{
			name: "static content",
			node: &semantic.SemanticNode{
				Summary:    "Static text",
				TokenCount: 10,
				Actions:    []semantic.Action{},
				IsDynamic:  false,
			},
			minSignificance: 0.5,
		},
		{
			name: "interactive content",
			node: &semantic.SemanticNode{
				Summary:    "Click here",
				TokenCount: 20,
				Actions:    []semantic.Action{{Type: semantic.ActionClick, Selector: "button"}},
				IsDynamic:  false,
			},
			minSignificance: 0.7,
		},
		{
			name: "dynamic content",
			node: &semantic.SemanticNode{
				Summary:    "Ad content",
				TokenCount: 5,
				Actions:    []semantic.Action{},
				IsDynamic:  true,
			},
			minSignificance: 0.1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig := detector.calculateSignificance(tt.node)
			if sig < tt.minSignificance {
				t.Errorf("significance %.2f < min %.2f", sig, tt.minSignificance)
			}
		})
	}
}

func TestPriceMonitorExtractPrice(t *testing.T) {
	monitor := NewPriceMonitor(nil)

	tests := []struct {
		text     string
		expected float64
	}{
		{"Price: $99.99", 99.99},
		{"$1,234.56", 1234.56},
		{"Total: €59.99", 59.99},
		{"£19.99 only", 19.99},
		{"$100 USD", 100},
		{"No price here", 0},
	}

	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			price := monitor.extractPrice(tt.text)
			if price != tt.expected {
				t.Errorf("expected %.2f, got %.2f", tt.expected, price)
			}
		})
	}
}

func TestPriceMonitorDetectCurrency(t *testing.T) {
	monitor := NewPriceMonitor(nil)

	tests := []struct {
		text     string
		expected string
	}{
		{"$99.99", "USD"},
		{"€99.99", "EUR"},
		{"£99.99", "GBP"},
		{"99.99 USD", "USD"},
		{"99.99 EUR", "EUR"},
		{"99.99 GBP", "GBP"},
		{"99.99", "USD"},
	}

	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			currency := monitor.detectCurrency(tt.text)
			if currency != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, currency)
			}
		})
	}
}

func TestABTestDetectorCluster(t *testing.T) {
	detector := NewABTestDetector()

	tree1 := &semantic.SemanticTree{StructuralHash: "hash-a"}
	tree2 := &semantic.SemanticTree{StructuralHash: "hash-a"}
	tree3 := &semantic.SemanticTree{StructuralHash: "hash-b"}
	tree4 := &semantic.SemanticTree{StructuralHash: "hash-a"}

	trees := []*semantic.SemanticTree{tree1, tree2, tree3, tree4}

	groups := detector.clusterByStructure(trees)

	if len(groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(groups))
	}

	if len(groups["hash-a"]) != 3 {
		t.Errorf("expected 3 trees in hash-a, got %d", len(groups["hash-a"]))
	}

	if len(groups["hash-b"]) != 1 {
		t.Errorf("expected 1 tree in hash-b, got %d", len(groups["hash-b"]))
	}
}

func TestABTestDetectorDetect(t *testing.T) {
	detector := NewABTestDetector()

	for i := 0; i < 5; i++ {
		tree := &semantic.SemanticTree{
			StructuralHash: "variant-a",
		}
		detector.RecordSample("test-url", tree)
	}

	result := detector.Detect("test-url")

	if result.Detected {
		t.Error("should not detect A/B test with single variant")
	}

	for i := 0; i < 5; i++ {
		tree := &semantic.SemanticTree{
			StructuralHash: "variant-b",
		}
		detector.RecordSample("test-url", tree)
	}

	result = detector.Detect("test-url")

	if !result.Detected {
		t.Error("should detect A/B test with 2 variants")
	}

	if result.Variants != 2 {
		t.Errorf("expected 2 variants, got %d", result.Variants)
	}

	t.Logf("A/B test detected: %d variants, confidence: %.2f", result.Variants, result.Confidence)
}

func TestCrawlHistoryPatternMatching(t *testing.T) {
	history := &PageHistory{
		ActionPatterns: []ActionPattern{
			{Intent: "login", SuccessCount: 5, FailCount: 2},
			{Intent: "checkout", SuccessCount: 1, FailCount: 3},
		},
	}

	pattern, found := history.FindSuccessfulPattern("login")
	if !found {
		t.Error("expected to find login pattern")
	}

	if pattern.SuccessCount <= pattern.FailCount {
		t.Error("expected success count > fail count")
	}

	_, found = history.FindSuccessfulPattern("checkout")
	if found {
		t.Error("should not find checkout as successful")
	}
}
