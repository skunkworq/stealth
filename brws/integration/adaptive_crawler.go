package integration

import (
	"context"
	"encoding/json"
	"math"
	"sync"
	"time"

	"github.com/skunkworq/stealth/brws/semantic"
	"github.com/skunkworq/stealth/brws/stealth"
)

type AdaptiveCrawler struct {
	navigator  *SemanticNavigator
	smartNav   *SmartNavigator
	filler     *SemanticFormFiller
	history    *CrawlHistory
	policy     *AdaptivePolicy
	sessionMgr *SessionManager

	mu sync.RWMutex
}

type CrawlHistory struct {
	pages sync.Map // map[string]*PageHistory
}

type PageHistory struct {
	URL            string
	StructuralHash string
	LastVisited    time.Time
	VisitCount     int
	SuccessRate    float32
	AvgDuration    time.Duration
	LastError      error
	LastAttempt    time.Time
	ActionPatterns []ActionPattern
}

type ActionPattern struct {
	Intent       string
	SuccessCount int
	FailCount    int
	LastUsed     time.Time
}

type CrawlResult struct {
	URL              string
	Success          bool
	Duration         time.Duration
	SemanticTree     *semantic.SemanticTree
	ActionsAvailable int
	ActionsTaken     []string
	Error            error
	Strategy         string
	TokensProcessed  int
	TokensCompressed int
}

type AdaptivePolicy struct {
	successfulStrategies sync.Map // map[string]*StrategyStats
	failurePatterns      sync.Map // map[string]*FailurePattern
	strategyScores       sync.Map // map[string]float32
	mu                   sync.RWMutex
}

type StrategyStats struct {
	Name        string
	Successes   int
	Failures    int
	AvgDuration time.Duration
	LastUsed    time.Time
}

type FailurePattern struct {
	ErrorType  string
	URLPattern string
	Selector   string
	Occurences int
	LastSeen   time.Time
}

type CrawlOption func(*AdaptiveCrawler)

func WithCrawlHistory(history *CrawlHistory) CrawlOption {
	return func(c *AdaptiveCrawler) {
		c.history = history
	}
}

func WithAdaptivePolicy(policy *AdaptivePolicy) CrawlOption {
	return func(c *AdaptiveCrawler) {
		c.policy = policy
	}
}

func NewAdaptiveCrawler(client *stealth.Client, opts ...CrawlOption) *AdaptiveCrawler {
	nav := NewSemanticNavigator(client, nil)
	smartNav := NewSmartNavigator(client, nav)
	filler := NewSemanticFormFiller(client, nav)

	c := &AdaptiveCrawler{
		navigator:  nav,
		smartNav:   smartNav,
		filler:     filler,
		history:    NewCrawlHistory(),
		policy:     NewAdaptivePolicy(),
		sessionMgr: NewSessionManager(),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

func NewCrawlHistory() *CrawlHistory {
	return &CrawlHistory{}
}

func NewAdaptivePolicy() *AdaptivePolicy {
	return &AdaptivePolicy{}
}

func (c *AdaptiveCrawler) Crawl(ctx context.Context, url string) (*CrawlResult, error) {
	start := time.Now()
	result := &CrawlResult{
		URL:          url,
		ActionsTaken: make([]string, 0),
	}

	history := c.getHistory(url)
	strategy := c.selectStrategy(url, history)

	result.Strategy = strategy

	navResult, err := c.navigator.NavigateWithIntent(ctx, url, "")
	if err != nil {
		c.recordFailure(url, strategy, err)
		result.Error = err
		result.Success = false
		result.Duration = time.Since(start)
		return result, err
	}

	result.SemanticTree = navResult.SemanticTree
	result.TokensProcessed = navResult.OriginalTokens
	result.TokensCompressed = navResult.CompressedTokens

	if result.SemanticTree != nil {
		result.ActionsAvailable = c.countActions(result.SemanticTree)
	}

	c.recordSuccess(url, strategy, time.Since(start))
	result.Success = true
	result.Duration = time.Since(start)

	return result, nil
}

func (c *AdaptiveCrawler) CrawlWithIntent(ctx context.Context, url, intent string) (*CrawlResult, error) {
	start := time.Now()
	result := &CrawlResult{
		URL:          url,
		ActionsTaken: make([]string, 0),
	}

	history := c.getHistory(url)
	strategy := c.selectStrategy(url, history)

	if pattern, ok := history.FindSuccessfulPattern(intent); ok {
		result, err := c.executePattern(ctx, url, pattern)
		if err == nil {
			return result, nil
		}
	}

	intentResult, err := c.smartNav.NavigateByIntent(ctx, url, NavigationIntent{
		Description: intent,
	})
	if err != nil {
		c.recordFailure(url, strategy, err)
		return result, err
	}

	if intentResult.Found {
		result.Strategy = strategy + "+intent_match"
	}

	result.Duration = time.Since(start)
	result.Success = true

	c.updatePattern(url, intent, result.Success)

	return result, nil
}

func (c *AdaptiveCrawler) selectStrategy(url string, history *PageHistory) string {
	if history == nil {
		return "explore"
	}

	if history.SuccessRate < 0.3 {
		return "cautious_explore"
	}

	if history.SuccessRate > 0.8 && history.VisitCount > 3 {
		return "optimized_fast"
	}

	if history.VisitCount > 5 {
		return "learned"
	}

	return "standard"
}

func (c *AdaptiveCrawler) getHistory(url string) *PageHistory {
	if val, ok := c.history.pages.Load(url); ok {
		return val.(*PageHistory)
	}
	return nil
}

func (c *AdaptiveCrawler) recordSuccess(url, strategy string, duration time.Duration) {
	if val, ok := c.history.pages.Load(url); ok {
		history := val.(*PageHistory)
		history.VisitCount++
		history.SuccessRate = (history.SuccessRate*float32(history.VisitCount-1) + 1.0) / float32(history.VisitCount)
		history.AvgDuration = (history.AvgDuration*time.Duration(history.VisitCount-1) + duration) / time.Duration(history.VisitCount)
		history.LastVisited = time.Now()
	} else {
		c.history.pages.Store(url, &PageHistory{
			URL:         url,
			VisitCount:  1,
			SuccessRate: 1.0,
			AvgDuration: duration,
			LastVisited: time.Now(),
		})
	}

	if stats, ok := c.policy.successfulStrategies.Load(strategy); ok {
		s := stats.(*StrategyStats)
		s.Successes++
		s.AvgDuration = (s.AvgDuration*time.Duration(s.Successes+s.Failures-1) + duration) / time.Duration(s.Successes+s.Failures)
		s.LastUsed = time.Now()
	} else {
		c.policy.successfulStrategies.Store(strategy, &StrategyStats{
			Name:        strategy,
			Successes:   1,
			AvgDuration: duration,
			LastUsed:    time.Now(),
		})
	}
}

func (c *AdaptiveCrawler) recordFailure(url, strategy string, err error) {
	if val, ok := c.history.pages.Load(url); ok {
		history := val.(*PageHistory)
		history.VisitCount++
		history.SuccessRate = (history.SuccessRate * float32(history.VisitCount-1)) / float32(history.VisitCount)
		history.LastError = err
		history.LastAttempt = time.Now()
	} else {
		c.history.pages.Store(url, &PageHistory{
			URL:         url,
			VisitCount:  1,
			SuccessRate: 0.0,
			LastError:   err,
			LastAttempt: time.Now(),
		})
	}

	if stats, ok := c.policy.successfulStrategies.Load(strategy); ok {
		s := stats.(*StrategyStats)
		s.Failures++
		s.LastUsed = time.Now()
	} else {
		c.policy.successfulStrategies.Store(strategy, &StrategyStats{
			Name:     strategy,
			Failures: 1,
			LastUsed: time.Now(),
		})
	}

	pattern := &FailurePattern{
		ErrorType:  err.Error(),
		URLPattern: url,
		Occurences: 1,
		LastSeen:   time.Now(),
	}
	c.policy.failurePatterns.Store(url+":"+err.Error(), pattern)
}

func (c *AdaptiveCrawler) executePattern(ctx context.Context, url string, pattern ActionPattern) (*CrawlResult, error) {
	result := &CrawlResult{
		URL:      url,
		Strategy: "learned_pattern",
		Success:  true,
	}
	return result, nil
}

func (c *AdaptiveCrawler) updatePattern(url, intent string, success bool) {
	history := c.getHistory(url)
	if history == nil {
		return
	}

	found := false
	for i, p := range history.ActionPatterns {
		if p.Intent == intent {
			if success {
				p.SuccessCount++
			} else {
				p.FailCount++
			}
			p.LastUsed = time.Now()
			history.ActionPatterns[i] = p
			found = true
			break
		}
	}

	if !found {
		pattern := ActionPattern{
			Intent:       intent,
			SuccessCount: 0,
			FailCount:    0,
			LastUsed:     time.Now(),
		}
		if success {
			pattern.SuccessCount = 1
		} else {
			pattern.FailCount = 1
		}
		history.ActionPatterns = append(history.ActionPatterns, pattern)
	}

	c.history.pages.Store(url, history)
}

func (c *AdaptiveCrawler) countActions(tree *semantic.SemanticTree) int {
	count := 0
	for _, node := range tree.AllNodes() {
		count += len(node.Actions)
	}
	return count
}

func (c *AdaptiveCrawler) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})

	pageCount := 0
	c.history.pages.Range(func(key, value interface{}) bool {
		pageCount++
		return true
	})
	stats["pages_visited"] = pageCount

	strategyCount := 0
	c.policy.successfulStrategies.Range(func(key, value interface{}) bool {
		strategyCount++
		return true
	})
	stats["strategies_tracked"] = strategyCount

	failureCount := 0
	c.policy.failurePatterns.Range(func(key, value interface{}) bool {
		failureCount++
		return true
	})
	stats["failure_patterns"] = failureCount

	return stats
}

func (c *AdaptiveCrawler) ExportHistory() ([]byte, error) {
	export := make(map[string]interface{})

	pages := make(map[string]*PageHistory)
	c.history.pages.Range(func(key, value interface{}) bool {
		pages[key.(string)] = value.(*PageHistory)
		return true
	})
	export["pages"] = pages

	return json.Marshal(export)
}

func (c *AdaptiveCrawler) LearnFromFailure(url string, err error, attemptedStrategy string) {
	c.recordFailure(url, attemptedStrategy, err)

	c.policy.mu.Lock()
	defer c.policy.mu.Unlock()

	key := url + ":" + err.Error()
	if val, ok := c.policy.failurePatterns.Load(key); ok {
		pattern := val.(*FailurePattern)
		pattern.Occurences++
		pattern.LastSeen = time.Now()
		c.policy.failurePatterns.Store(key, pattern)
	}
}

func (h *PageHistory) FindSuccessfulPattern(intent string) (ActionPattern, bool) {
	for _, p := range h.ActionPatterns {
		if p.Intent == intent && p.SuccessCount > p.FailCount {
			return p, true
		}
	}
	return ActionPattern{}, false
}

func (p *AdaptivePolicy) GetBestStrategy(url string) string {
	bestScore := float32(0.0)
	bestStrategy := "explore"

	p.successfulStrategies.Range(func(key, value interface{}) bool {
		stats := value.(*StrategyStats)
		total := stats.Successes + stats.Failures
		if total == 0 {
			return true
		}

		successRate := float32(stats.Successes) / float32(total)
		efficiency := float32(1.0)
		if stats.AvgDuration > 0 {
			efficiency = 1.0 / (1.0 + float32(stats.AvgDuration.Seconds()))
		}

		score := successRate*0.7 + efficiency*0.3

		if score > bestScore {
			bestScore = score
			bestStrategy = key.(string)
		}
		return true
	})

	return bestStrategy
}

func (p *AdaptivePolicy) ShouldRetry(url string, err error) bool {
	key := url + ":" + err.Error()
	if val, ok := p.failurePatterns.Load(key); ok {
		pattern := val.(*FailurePattern)
		return pattern.Occurences < 3
	}
	return true
}

func (p *AdaptivePolicy) GetRecommendedWait(url string) time.Duration {
	if val, ok := p.failurePatterns.Load(url); ok {
		pattern := val.(*FailurePattern)
		backoff := time.Duration(math.Pow(2, float64(pattern.Occurences))) * time.Second
		if backoff > 60*time.Second {
			backoff = 60 * time.Second
		}
		return backoff
	}
	return 1 * time.Second
}

func (c *AdaptiveCrawler) Close() error {
	return nil
}
