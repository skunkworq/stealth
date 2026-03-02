package integration

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/stealth/brwslab/brws/semantic"
)

type PriceMonitor struct {
	navigator  *SemanticNavigator
	priceCache sync.Map // map[string]*PriceHistory
	alerts     chan PriceAlert
}

type PriceInfo struct {
	Price       float64
	Currency    string
	Original    string
	InStock     bool
	Variants    map[string]float64
	LastChecked time.Time
	Selector    string
}

type PriceHistory struct {
	URL       string
	Prices    []PriceEntry
	Lowest    float64
	Highest   float64
	Current   float64
	Currency  string
	LastCheck time.Time
}

type PriceEntry struct {
	Price     float64
	Timestamp time.Time
	Source    string
}

type PriceAlert struct {
	URL           string
	OldPrice      float64
	NewPrice      float64
	Change        float64
	PercentChange float64
	Currency      string
	Timestamp     time.Time
	IsDrop        bool
	IsRise        bool
}

func NewPriceMonitor(nav *SemanticNavigator) *PriceMonitor {
	return &PriceMonitor{
		navigator: nav,
		alerts:    make(chan PriceAlert, 100),
	}
}

func (m *PriceMonitor) CheckPrice(ctx context.Context, url string) (*PriceInfo, error) {
	result, err := m.navigator.NavigateWithIntent(ctx, url, "price")
	if err != nil {
		return nil, err
	}

	tree := result.SemanticTree
	if tree == nil {
		return nil, nil
	}

	priceNode := m.findPriceNode(tree)
	if priceNode == nil {
		return nil, nil
	}

	info := &PriceInfo{
		LastChecked: time.Now(),
		Variants:    make(map[string]float64),
	}

	info.Price = m.extractPrice(priceNode.Summary)
	info.Currency = m.detectCurrency(priceNode.Summary)
	info.Original = priceNode.Summary
	info.InStock = m.checkAvailability(tree)

	variants := m.findPriceVariants(tree)
	for name, price := range variants {
		info.Variants[name] = price
	}

	previous := m.getHistory(url)
	if previous != nil && previous.Current != info.Price {
		alert := PriceAlert{
			URL:           url,
			OldPrice:      previous.Current,
			NewPrice:      info.Price,
			Change:        info.Price - previous.Current,
			PercentChange: (info.Price - previous.Current) / previous.Current * 100,
			Currency:      info.Currency,
			Timestamp:     time.Now(),
			IsDrop:        info.Price < previous.Current,
			IsRise:        info.Price > previous.Current,
		}

		select {
		case m.alerts <- alert:
		default:
		}
	}

	m.recordPrice(url, info)

	return info, nil
}

func (m *PriceMonitor) findPriceNode(tree *semantic.SemanticTree) *semantic.SemanticNode {
	priceKeywords := []string{"price", "cost", "$", "€", "£", "USD", "EUR", "GBP"}

	var bestMatch *semantic.SemanticNode
	bestScore := 0

	for _, node := range tree.AllNodes() {
		score := 0
		summaryLower := strings.ToLower(node.Summary)

		for _, keyword := range priceKeywords {
			if strings.Contains(summaryLower, keyword) {
				score += 10
			}
		}

		if hasPrice, _ := regexp.MatchString(`[\$€£]\s*\d+`, node.Summary); hasPrice {
			score += 20
		}

		if hasPrice, _ := regexp.MatchString(`\d+\.\d{2}`, node.Summary); hasPrice {
			score += 5
		}

		if score > bestScore {
			bestScore = score
			bestMatch = node
		}
	}

	return bestMatch
}

func (m *PriceMonitor) extractPrice(text string) float64 {
	prices := m.extractAllPrices(text)
	if len(prices) > 0 {
		return prices[0]
	}
	return 0
}

func (m *PriceMonitor) extractAllPrices(text string) []float64 {
	prices := make([]float64, 0)

	patterns := []string{
		`\$[\s]*(\d+(?:,\d{3})*(?:\.\d{2})?)`,
		`(\d+(?:,\d{3})*(?:\.\d{2})?)[\s]*(?:USD|dollars?)`,
		`€[\s]*(\d+(?:,\d{3})*(?:\.\d{2})?)`,
		`(\d+(?:,\d{3})*(?:\.\d{2})?)[\s]*(?:EUR|euros?)`,
		`£[\s]*(\d+(?:,\d{3})*(?:\.\d{2})?)`,
		`(\d+(?:,\d{3})*(?:\.\d{2})?)[\s]*(?:GBP|pounds?)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(text, -1)

		for _, match := range matches {
			if len(match) > 1 {
				priceStr := strings.ReplaceAll(match[1], ",", "")
				if price, err := strconv.ParseFloat(priceStr, 64); err == nil {
					prices = append(prices, price)
				}
			}
		}
	}

	return prices
}

func (m *PriceMonitor) detectCurrency(text string) string {
	if strings.Contains(text, "$") || strings.Contains(text, "USD") {
		return "USD"
	}
	if strings.Contains(text, "€") || strings.Contains(text, "EUR") {
		return "EUR"
	}
	if strings.Contains(text, "£") || strings.Contains(text, "GBP") {
		return "GBP"
	}
	return "USD"
}

func (m *PriceMonitor) checkAvailability(tree *semantic.SemanticTree) bool {
	inStockKeywords := []string{"in stock", "available", "add to cart", "buy now"}
	outOfStockKeywords := []string{"out of stock", "unavailable", "sold out", "notify me"}

	for _, node := range tree.AllNodes() {
		summaryLower := strings.ToLower(node.Summary)

		for _, keyword := range outOfStockKeywords {
			if strings.Contains(summaryLower, keyword) {
				return false
			}
		}

		for _, keyword := range inStockKeywords {
			if strings.Contains(summaryLower, keyword) {
				return true
			}
		}
	}

	return true
}

func (m *PriceMonitor) findPriceVariants(tree *semantic.SemanticTree) map[string]float64 {
	variants := make(map[string]float64)

	for _, node := range tree.AllNodes() {
		prices := m.extractAllPrices(node.Summary)
		if len(prices) > 0 {
			variantName := m.extractVariantName(node)
			if variantName != "" {
				variants[variantName] = prices[0]
			}
		}
	}

	return variants
}

func (m *PriceMonitor) extractVariantName(node *semantic.SemanticNode) string {
	summary := node.Summary

	if strings.Contains(summary, "Size") || strings.Contains(summary, "size") {
		re := regexp.MustCompile(`(?i)Size[:\s]+(\w+)`)
		if match := re.FindStringSubmatch(summary); len(match) > 1 {
			return "Size: " + match[1]
		}
	}

	if strings.Contains(summary, "Color") || strings.Contains(summary, "color") {
		re := regexp.MustCompile(`(?i)Color[:\s]+(\w+)`)
		if match := re.FindStringSubmatch(summary); len(match) > 1 {
			return "Color: " + match[1]
		}
	}

	return ""
}

func (m *PriceMonitor) recordPrice(url string, info *PriceInfo) {
	var history *PriceHistory

	if val, ok := m.priceCache.Load(url); ok {
		history = val.(*PriceHistory)
	} else {
		history = &PriceHistory{
			URL:      url,
			Prices:   make([]PriceEntry, 0),
			Currency: info.Currency,
			Lowest:   info.Price,
			Highest:  info.Price,
		}
	}

	entry := PriceEntry{
		Price:     info.Price,
		Timestamp: time.Now(),
		Source:    "semantic",
	}

	history.Prices = append(history.Prices, entry)
	history.Current = info.Price
	history.LastCheck = time.Now()

	if info.Price < history.Lowest {
		history.Lowest = info.Price
	}
	if info.Price > history.Highest {
		history.Highest = info.Price
	}

	m.priceCache.Store(url, history)
}

func (m *PriceMonitor) getHistory(url string) *PriceHistory {
	if val, ok := m.priceCache.Load(url); ok {
		return val.(*PriceHistory)
	}
	return nil
}

func (m *PriceMonitor) GetHistory(url string) *PriceHistory {
	return m.getHistory(url)
}

func (m *PriceMonitor) GetAlerts() <-chan PriceAlert {
	return m.alerts
}

func (m *PriceMonitor) WatchPrice(url string, interval time.Duration) context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.CheckPrice(ctx, url)
			}
		}
	}()

	return cancel
}

func (m *PriceMonitor) IsLowestPrice(url string) bool {
	history := m.getHistory(url)
	if history == nil {
		return false
	}
	return history.Current == history.Lowest
}

func (m *PriceMonitor) PriceDropPercent(url string) float64 {
	if history := m.getHistory(url); history != nil {
		if len(history.Prices) >= 2 {
			prev := history.Prices[len(history.Prices)-2].Price
			curr := history.Current
			if prev > 0 {
				return (prev - curr) / prev * 100
			}
		}
	}
	return 0
}

func (m *PriceMonitor) Close() {
	close(m.alerts)
}

type ABTestDetector struct {
	trees   sync.Map // map[string][]*semantic.SemanticTree
	results sync.Map // map[string]*ABTestResult
}

type ABTestResult struct {
	URL           string
	Variants      int
	Confidence    float32
	VariantGroups []*VariantGroup
	SampleSize    int
	Detected      bool
}

type VariantGroup struct {
	StructuralHash string
	Occurrences    int
	SampleTree     *semantic.SemanticTree
	Differences    []string
}

func NewABTestDetector() *ABTestDetector {
	return &ABTestDetector{}
}

func (d *ABTestDetector) RecordSample(url string, tree *semantic.SemanticTree) *ABTestResult {
	if val, ok := d.trees.Load(url); ok {
		trees := val.([]*semantic.SemanticTree)
		trees = append(trees, tree)
		d.trees.Store(url, trees)
	} else {
		d.trees.Store(url, []*semantic.SemanticTree{tree})
	}

	val, _ := d.trees.Load(url)
	trees := val.([]*semantic.SemanticTree)

	if len(trees) >= 5 {
		return d.Detect(url)
	}

	return &ABTestResult{
		URL:        url,
		SampleSize: len(trees),
		Detected:   false,
	}
}

func (d *ABTestDetector) Detect(url string) *ABTestResult {
	val, ok := d.trees.Load(url)
	if !ok {
		return &ABTestResult{URL: url, Detected: false}
	}

	trees := val.([]*semantic.SemanticTree)
	if len(trees) < 5 {
		return &ABTestResult{
			URL:        url,
			SampleSize: len(trees),
			Detected:   false,
		}
	}

	groups := d.clusterByStructure(trees)

	result := &ABTestResult{
		URL:           url,
		Variants:      len(groups),
		SampleSize:    len(trees),
		VariantGroups: make([]*VariantGroup, 0),
	}

	for hash, group := range groups {
		variant := &VariantGroup{
			StructuralHash: hash,
			Occurrences:    len(group),
			SampleTree:     group[0],
		}
		result.VariantGroups = append(result.VariantGroups, variant)
	}

	if len(groups) > 1 {
		result.Detected = true
		result.Confidence = d.calculateConfidence(groups, len(trees))
	}

	d.results.Store(url, result)
	return result
}

func (d *ABTestDetector) clusterByStructure(trees []*semantic.SemanticTree) map[string][]*semantic.SemanticTree {
	groups := make(map[string][]*semantic.SemanticTree)

	for _, tree := range trees {
		hash := tree.StructuralHash
		if _, exists := groups[hash]; !exists {
			groups[hash] = make([]*semantic.SemanticTree, 0)
		}
		groups[hash] = append(groups[hash], tree)
	}

	return groups
}

func (d *ABTestDetector) calculateConfidence(groups map[string][]*semantic.SemanticTree, total int) float32 {
	if len(groups) < 2 {
		return 0
	}

	sizes := make([]int, 0)
	for _, group := range groups {
		sizes = append(sizes, len(group))
	}

	totalVariance := float32(0)
	mean := float32(total) / float32(len(groups))

	for _, size := range sizes {
		diff := float32(size) - mean
		totalVariance += diff * diff
	}

	variance := totalVariance / float32(len(groups))
	stdDev := float32(0)
	if variance > 0 {
		stdDev = float32(1)
		for i := 0; i < 100; i++ {
			stdDev = (stdDev + variance/stdDev) / 2
		}
	}

	confidence := stdDev / mean

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

func (d *ABTestDetector) GetResult(url string) *ABTestResult {
	if val, ok := d.results.Load(url); ok {
		return val.(*ABTestResult)
	}
	return nil
}

func (d *ABTestDetector) ClearSamples(url string) {
	d.trees.Delete(url)
	d.results.Delete(url)
}
