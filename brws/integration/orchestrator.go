package integration

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/stealth/brwslab/brws/semantic"
	"github.com/stealth/brwslab/brws/stealth"
)

type AgentOrchestrator struct {
	agents      []*SemanticAgent
	coordinator *Coordinator
	results     map[string]*AgentResult
	mu          sync.RWMutex

	maxConcurrent int
	timeout       time.Duration
	retryPolicy   *RetryPolicy
}

type SemanticAgent struct {
	ID         string
	client     *stealth.Client
	navigator  *SemanticNavigator
	smartNav   *SmartNavigator
	sessionMgr *SessionManager
	stats      AgentStats
	mu         sync.Mutex
}

type AgentStats struct {
	PagesProcessed int
	SuccessCount   int
	FailureCount   int
	TotalTokens    int
	TotalDuration  time.Duration
	LastUsed       time.Time
}

type AgentResult struct {
	AgentID   string
	URL       string
	Success   bool
	Tree      *semantic.SemanticTree
	Duration  time.Duration
	Error     error
	TokensIn  int
	TokensOut int
}

type Coordinator struct {
	visitedURLs  sync.Map
	pendingURLs  []string
	resultsCh    chan *AgentResult
	workersWg    sync.WaitGroup
	mu           sync.RWMutex
	maxQueueSize int
	rateLimiter  *RateLimiter
}

type RateLimiter struct {
	tokens     int
	maxTokens  int
	refillRate time.Duration
	lastRefill time.Time
	mu         sync.Mutex
}

type RetryPolicy struct {
	MaxRetries        int
	InitialDelay      time.Duration
	MaxDelay          time.Duration
	BackoffMultiplier float64
}

func NewAgentOrchestrator(maxAgents int, maxConcurrent int) *AgentOrchestrator {
	agents := make([]*SemanticAgent, 0, maxAgents)
	for i := 0; i < maxAgents; i++ {
		agents = append(agents, newAgent(fmt.Sprintf("agent-%d", i)))
	}

	return &AgentOrchestrator{
		agents:        agents,
		coordinator:   newCoordinator(maxConcurrent),
		results:       make(map[string]*AgentResult),
		maxConcurrent: maxConcurrent,
		timeout:       30 * time.Second,
		retryPolicy: &RetryPolicy{
			MaxRetries:        3,
			InitialDelay:      time.Second,
			MaxDelay:          30 * time.Second,
			BackoffMultiplier: 2.0,
		},
	}
}

func newAgent(id string) *SemanticAgent {
	return &SemanticAgent{
		ID:        id,
		navigator: nil,
		smartNav:  nil,
		stats:     AgentStats{},
	}
}

func (a *SemanticAgent) SetClient(client *stealth.Client) {
	a.client = client
	a.navigator = NewSemanticNavigator(client, nil)
	a.smartNav = NewSmartNavigator(client, a.navigator)
	a.sessionMgr = NewSessionManager()
}

func newCoordinator(maxConcurrent int) *Coordinator {
	return &Coordinator{
		resultsCh:    make(chan *AgentResult, 100),
		maxQueueSize: maxConcurrent * 10,
		rateLimiter: &RateLimiter{
			tokens:     maxConcurrent,
			maxTokens:  maxConcurrent,
			refillRate: time.Second,
			lastRefill: time.Now(),
		},
	}
}

func (c *Coordinator) ShouldProcess(url string) bool {
	if _, exists := c.visitedURLs.Load(url); exists {
		return false
	}
	c.visitedURLs.Store(url, true)
	return true
}

func (c *Coordinator) AcquireToken() bool {
	c.rateLimiter.mu.Lock()
	defer c.rateLimiter.mu.Unlock()

	now := time.Now()
	if now.Sub(c.rateLimiter.lastRefill) >= c.rateLimiter.refillRate {
		c.rateLimiter.tokens = c.rateLimiter.maxTokens
		c.rateLimiter.lastRefill = now
	}

	if c.rateLimiter.tokens > 0 {
		c.rateLimiter.tokens--
		return true
	}
	return false
}

func (c *Coordinator) ReleaseToken() {
	c.rateLimiter.mu.Lock()
	defer c.rateLimiter.mu.Unlock()
	c.rateLimiter.tokens++
}

func (o *AgentOrchestrator) ParallelCrawl(ctx context.Context, urls []string) map[string]*AgentResult {
	o.coordinator.resultsCh = make(chan *AgentResult, len(urls))

	var wg sync.WaitGroup
	sem := make(chan struct{}, o.maxConcurrent)

	for _, url := range urls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()

			if !o.coordinator.ShouldProcess(u) {
				return
			}

			sem <- struct{}{}
			defer func() { <-sem }()

			for o.coordinator.AcquireToken() == false {
				time.Sleep(100 * time.Millisecond)
			}

			result := o.crawlURL(ctx, u)

			o.coordinator.ReleaseToken()

			o.coordinator.resultsCh <- result

			o.mu.Lock()
			o.results[u] = result
			o.mu.Unlock()
		}(url)
	}

	go func() {
		wg.Wait()
		close(o.coordinator.resultsCh)
	}()

	// Drain results channel
	for range o.coordinator.resultsCh {
	}

	return o.results
}

func (o *AgentOrchestrator) crawlURL(ctx context.Context, url string) *AgentResult {
	agent := o.selectAgent()
	if agent == nil {
		return &AgentResult{
			URL:     url,
			Success: false,
			Error:   fmt.Errorf("no available agents"),
		}
	}

	agent.mu.Lock()
	agent.stats.PagesProcessed++
	agent.stats.LastUsed = time.Now()
	agent.mu.Unlock()

	result := &AgentResult{
		AgentID: agent.ID,
		URL:     url,
	}

	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()

	err := o.executeWithRetry(ctx, agent, url, result)
	result.Duration = time.Since(start)

	if err != nil {
		result.Success = false
		result.Error = err

		agent.mu.Lock()
		agent.stats.FailureCount++
		agent.mu.Unlock()
	} else {
		result.Success = true

		agent.mu.Lock()
		agent.stats.SuccessCount++
		agent.mu.Unlock()
	}

	return result
}

func (o *AgentOrchestrator) executeWithRetry(ctx context.Context, agent *SemanticAgent, url string, result *AgentResult) error {
	var lastErr error

	for attempt := 0; attempt <= o.retryPolicy.MaxRetries; attempt++ {
		if attempt > 0 {
			delay := time.Duration(float64(o.retryPolicy.InitialDelay) * math.Pow(o.retryPolicy.BackoffMultiplier, float64(attempt-1)))
			if delay > o.retryPolicy.MaxDelay {
				delay = o.retryPolicy.MaxDelay
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}

		err := agent.crawlSingle(ctx, url, result)
		if err == nil {
			return nil
		}

		lastErr = err
	}

	return lastErr
}

func (a *SemanticAgent) crawlSingle(ctx context.Context, url string, result *AgentResult) error {
	if a.navigator == nil {
		return fmt.Errorf("agent %s has no client", a.ID)
	}

	navResult, err := a.navigator.NavigateWithIntent(ctx, url, "")
	if err != nil {
		return err
	}

	result.Tree = navResult.SemanticTree
	if navResult.SemanticTree != nil {
		result.TokensIn = navResult.OriginalTokens
		result.TokensOut = navResult.CompressedTokens

		a.mu.Lock()
		a.stats.TotalTokens += navResult.OriginalTokens
		a.mu.Unlock()
	}

	return nil
}

func (o *AgentOrchestrator) selectAgent() *SemanticAgent {
	var best *SemanticAgent
	var minLoad int = 1 << 30

	o.mu.RLock()
	defer o.mu.RUnlock()

	for _, agent := range o.agents {
		agent.mu.Lock()
		load := agent.stats.PagesProcessed
		agent.mu.Unlock()

		if load < minLoad {
			minLoad = load
			best = agent
		}
	}

	return best
}

func (o *AgentOrchestrator) GetAgentStats() []AgentStats {
	stats := make([]AgentStats, len(o.agents))
	for i, agent := range o.agents {
		agent.mu.Lock()
		stats[i] = agent.stats
		agent.mu.Unlock()
	}
	return stats
}

func (o *AgentOrchestrator) GetCoordinatorStats() map[string]interface{} {
	visitedCount := 0
	o.coordinator.visitedURLs.Range(func(key, value interface{}) bool {
		visitedCount++
		return true
	})

	return map[string]interface{}{
		"urls_visited":        visitedCount,
		"urls_pending":        len(o.coordinator.pendingURLs),
		"results_collected":   len(o.results),
		"max_concurrent":      o.maxConcurrent,
		"rate_limiter_tokens": o.coordinator.rateLimiter.tokens,
	}
}

func (o *AgentOrchestrator) Close() error {
	for _, agent := range o.agents {
		if agent.client != nil {
			agent.client.Close()
		}
	}
	return nil
}
