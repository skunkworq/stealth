package challenge

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// TokenBucket implements a per-IP token bucket rate limiter.
// Each IP gets a bucket with a configurable capacity and refill rate.
type TokenBucket struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	config  RateLimitConfig
}

// RateLimitConfig controls rate limiting behavior.
type RateLimitConfig struct {
	// Capacity is the maximum number of tokens (burst size).
	Capacity int
	// RefillRate is tokens added per second.
	RefillRate float64
	// CleanupInterval removes stale buckets older than this.
	CleanupInterval time.Duration
}

// DefaultRateLimitConfig returns sensible defaults for CF challenge endpoints.
// 10 requests burst, 2 per second refill — allows legitimate solving but blocks
// rapid automated cycling.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Capacity:        10,
		RefillRate:      2.0,
		CleanupInterval: 5 * time.Minute,
	}
}

type bucket struct {
	tokens    float64
	lastCheck time.Time
	capacity  int
}

// NewTokenBucket creates a new rate limiter.
func NewTokenBucket(config RateLimitConfig) *TokenBucket {
	if config.CleanupInterval <= 0 {
		config.CleanupInterval = 5 * time.Minute
	}
	tb := &TokenBucket{
		buckets: make(map[string]*bucket),
		config:  config,
	}
	go tb.cleanupLoop()
	return tb
}

// Allow checks if a request from the given IP is allowed.
// Returns (allowed, remaining tokens, retry-after seconds).
func (tb *TokenBucket) Allow(ip string) (bool, int, int) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	b, ok := tb.buckets[ip]
	if !ok {
		b = &bucket{
			tokens:    float64(tb.config.Capacity),
			lastCheck: time.Now(),
			capacity:  tb.config.Capacity,
		}
		tb.buckets[ip] = b
	}

	// Refill tokens based on elapsed time
	now := time.Now()
	elapsed := now.Sub(b.lastCheck).Seconds()
	b.tokens += elapsed * tb.config.RefillRate
	if b.tokens > float64(b.capacity) {
		b.tokens = float64(b.capacity)
	}
	b.lastCheck = now

	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true, int(b.tokens), 0
	}

	// Calculate retry-after: time until 1 token is available
	deficit := 1.0 - b.tokens
	retryAfter := int(deficit/tb.config.RefillRate) + 1

	return false, 0, retryAfter
}

// cleanupLoop periodically removes stale buckets.
func (tb *TokenBucket) cleanupLoop() {
	ticker := time.NewTicker(tb.config.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		tb.mu.Lock()
		now := time.Now()
		for ip, b := range tb.buckets {
			if now.Sub(b.lastCheck) > tb.config.CleanupInterval {
				delete(tb.buckets, ip)
			}
		}
		tb.mu.Unlock()
	}
}

// RateLimitMiddleware wraps an http.HandlerFunc with rate limiting.
// Returns 429 Too Many Requests with CF-style headers when the limit is exceeded.
func (tb *TokenBucket) RateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		allowed, remaining, retryAfter := tb.Allow(ip)

		// Always set rate limit headers (like real CF)
		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(tb.config.Capacity))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))

		if !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Server", "cloudflare")
			w.Header().Set("Cf-Mitigated", "challenge")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = fmt.Fprintf(w, `{"success":false,"error":"rate limited","retry_after":%d}`, retryAfter)
			return
		}

		next(w, r)
	}
}

// extractIP gets the client IP from the request, checking X-Forwarded-For first.
func extractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
