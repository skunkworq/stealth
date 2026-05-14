// Package proxy provides proxy rotation and management.
//
//nolint:gosec // G404: math/rand used intentionally for non-cryptographic proxy selection
package connpool

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/skunkworq/stealth/brws/core/constants"
)

// Proxy represents a single proxy
type Proxy struct {
	URL       string
	Name      string
	Protocol  string // http, https, socks5
	Username  string
	Password  string
	Uses      int
	LastUsed  time.Time
	Successes int
	Failures  int
	Latency   time.Duration
	IsWorking bool
}

// Pool manages multiple proxies
type Pool struct {
	proxies  []*Proxy
	current  int
	mu       sync.RWMutex
	strategy Strategy
	stats    PoolStats
}

// Strategy defines how proxies are selected
type Strategy int

const (
	// StrategyRoundRobin selects proxies in round-robin order
	StrategyRoundRobin Strategy = iota
	// StrategyRandom selects proxies randomly
	StrategyRandom
	// StrategyLeastUsed selects the least used proxy.
	StrategyLeastUsed
	// StrategyFastest selects the fastest proxy.
	StrategyFastest
	// StrategyWeighted selects proxies based on weight.
	StrategyWeighted
)

// PoolStats tracks proxy pool statistics
type PoolStats struct {
	TotalRequests int64
	Successes     int64
	Failures      int64
}

// NewPool creates a new proxy pool
func NewPool(proxies []string, strategy Strategy) *Pool {
	p := &Pool{
		proxies:  make([]*Proxy, 0, len(proxies)),
		strategy: strategy,
		stats:    PoolStats{},
	}

	for _, proxyURL := range proxies {
		p.proxies = append(p.proxies, &Proxy{
			URL:       proxyURL,
			Name:      fmt.Sprintf("proxy-%d", len(p.proxies)),
			IsWorking: true,
		})
	}

	return p
}

// Get returns the next proxy based on the strategy
func (p *Pool) Get() *Proxy {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.proxies) == 0 {
		return nil
	}

	var proxy *Proxy

	switch p.strategy {
	case StrategyRoundRobin:
		proxy = p.proxies[p.current]
		p.current = (p.current + 1) % len(p.proxies)

	case StrategyRandom:
		proxy = p.proxies[rand.Intn(len(p.proxies))]

	case StrategyLeastUsed:
		minUses := int(^uint(0) >> 1)
		for _, pr := range p.proxies {
			if pr.IsWorking && pr.Uses < minUses {
				minUses = pr.Uses
				proxy = pr
			}
		}

	case StrategyFastest:
		minLatency := time.Hour
		for _, pr := range p.proxies {
			if pr.IsWorking && pr.Latency < minLatency {
				minLatency = pr.Latency
				proxy = pr
			}
		}

	case StrategyWeighted:
		// Weighted strategy not yet implemented, fall back to round robin
		proxy = p.proxies[p.current]
		p.current = (p.current + 1) % len(p.proxies)

	default:
		proxy = p.proxies[p.current]
	}

	if proxy != nil {
		proxy.Uses++
		proxy.LastUsed = time.Now()
		p.stats.TotalRequests++
	}

	return proxy
}

// RecordSuccess records a successful request through a proxy
func (p *Pool) RecordSuccess(proxyURL string, latency time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, pr := range p.proxies {
		if pr.URL == proxyURL {
			pr.Successes++
			pr.IsWorking = true
			pr.Latency = latency
			p.stats.Successes++

			break
		}
	}
}

// RecordFailure records a failed request through a proxy
func (p *Pool) RecordFailure(proxyURL string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, pr := range p.proxies {
		if pr.URL == proxyURL {
			pr.Failures++
			// Mark as not working if too many failures
			if pr.Failures > 5 {
				pr.IsWorking = false
			}

			p.stats.Failures++

			break
		}
	}
}

// Add adds a new proxy to the pool
func (p *Pool) Add(proxyURL string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.proxies = append(p.proxies, &Proxy{
		URL:       proxyURL,
		Name:      fmt.Sprintf("proxy-%d", len(p.proxies)),
		IsWorking: true,
	})
}

// Remove removes a proxy from the pool
func (p *Pool) Remove(proxyURL string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, pr := range p.proxies {
		if pr.URL == proxyURL {
			p.proxies = append(p.proxies[:i], p.proxies[i+1:]...)
			break
		}
	}
}

// Count returns the number of working proxies
func (p *Pool) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	count := 0
	for _, pr := range p.proxies {
		if pr.IsWorking {
			count++
		}
	}
	return count
}

// Stats returns pool statistics
func (p *Pool) Stats() PoolStats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.stats
}

// GetProxyURL returns an HTTP transport proxy function for a proxy
func GetProxyURL(proxyURL string) func(*http.Request) (*url.URL, error) {
	if proxyURL == "" {
		return nil
	}
	return http.ProxyURL(func() *url.URL {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil
		}
		return u
	}())
}

// WithAuth adds authentication to a proxy URL
func WithAuth(proxyURL, username, password string) string {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return proxyURL
	}
	u.User = url.UserPassword(username, password)
	return u.String()
}

// NewHTTPClient creates an HTTP client with proxy
func NewHTTPClient(proxyURL string) (*http.Client, error) {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: constants.DefaultTimeout,
		}).DialContext,
	}

	if proxyURL != "" {
		proxyURLParsed, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURLParsed)
	}

	return &http.Client{
		Transport: transport,
		Timeout:   constants.DefaultTimeout,
	}, nil
}

// RoundRobin creates a round-robin proxy pool
func RoundRobin(proxies []string) *Pool {
	return NewPool(proxies, StrategyRoundRobin)
}

// Random creates a random proxy pool
func Random(proxies []string) *Pool {
	return NewPool(proxies, StrategyRandom)
}

// LeastUsed creates a least-used proxy pool
func LeastUsed(proxies []string) *Pool {
	return NewPool(proxies, StrategyLeastUsed)
}

// Rotation wraps an HTTP client with automatic proxy rotation
type Rotation struct {
	pool   *Pool
	client *http.Client
}

// NewRotation creates a new rotating proxy client
func NewRotation(proxies []string, strategy Strategy) (*Rotation, error) {
	pool := NewPool(proxies, strategy)

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: constants.DefaultTimeout,
		}).DialContext,
	}

	return &Rotation{
		pool: pool,
		client: &http.Client{
			Transport: transport,
			Timeout:   constants.DefaultTimeout,
		},
	}, nil
}

// Do performs a request with automatic proxy rotation
func (r *Rotation) Do(req *http.Request) (*http.Response, error) {
	proxy := r.pool.Get()
	if proxy == nil {
		return r.client.Do(req)
	}

	// Set proxy
	r.client.Transport.(*http.Transport).Proxy = GetProxyURL(proxy.URL)

	// Track timing
	start := time.Now()
	resp, err := r.client.Do(req)
	latency := time.Since(start)

	// Record result
	if err != nil {
		r.pool.RecordFailure(proxy.URL)
	} else {
		r.pool.RecordSuccess(proxy.URL, latency)
	}

	return resp, err
}

// Get performs a GET request with proxy rotation
func (r *Rotation) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return r.Do(req)
}

// ContextDo performs a request with proxy rotation and context
func (r *Rotation) ContextDo(ctx context.Context, req *http.Request) (*http.Response, error) {
	proxy := r.pool.Get()
	if proxy == nil {
		return r.client.Do(req)
	}

	r.client.Transport.(*http.Transport).Proxy = GetProxyURL(proxy.URL)

	start := time.Now()
	resp, err := r.client.Do(req.WithContext(ctx))
	latency := time.Since(start)

	if err != nil {
		r.pool.RecordFailure(proxy.URL)
	} else {
		r.pool.RecordSuccess(proxy.URL, latency)
	}

	return resp, err
}
