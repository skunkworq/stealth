package adversarial

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTokenBucket_AllowsBurst(t *testing.T) {
	tb := NewTokenBucket(RateLimitConfig{
		Capacity:   5,
		RefillRate: 1.0,
	})

	// Should allow 5 requests (burst capacity)
	for i := 0; i < 5; i++ {
		allowed, _, _ := tb.Allow("1.2.3.4")
		if !allowed {
			t.Errorf("request %d should be allowed (within burst)", i+1)
		}
	}

	// 6th request should be denied
	allowed, remaining, retryAfter := tb.Allow("1.2.3.4")
	if allowed {
		t.Error("6th request should be denied (burst exhausted)")
	}
	if remaining != 0 {
		t.Errorf("remaining should be 0, got %d", remaining)
	}
	if retryAfter <= 0 {
		t.Errorf("retry-after should be > 0, got %d", retryAfter)
	}
}

func TestTokenBucket_DifferentIPsIndependent(t *testing.T) {
	tb := NewTokenBucket(RateLimitConfig{
		Capacity:   2,
		RefillRate: 1.0,
	})

	// Exhaust IP1
	tb.Allow("1.1.1.1")
	tb.Allow("1.1.1.1")
	allowed, _, _ := tb.Allow("1.1.1.1")
	if allowed {
		t.Error("IP1 should be exhausted")
	}

	// IP2 should still have tokens
	allowed, _, _ = tb.Allow("2.2.2.2")
	if !allowed {
		t.Error("IP2 should be allowed (independent bucket)")
	}
}

func TestTokenBucket_RateLimitMiddleware_Returns429(t *testing.T) {
	tb := NewTokenBucket(RateLimitConfig{
		Capacity:   1,
		RefillRate: 0.1, // very slow refill
	})

	handler := tb.RateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// First request should pass
	req := httptest.NewRequest(http.MethodPost, "/solve", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("first request: expected 200, got %d", w.Code)
	}

	// Second request should be rate limited
	w2 := httptest.NewRecorder()
	handler(w2, req)

	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("second request: expected 429, got %d", w2.Code)
	}

	// Check CF-style headers
	if w2.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on 429")
	}
	if w2.Header().Get("X-RateLimit-Limit") == "" {
		t.Error("expected X-RateLimit-Limit header")
	}
	if w2.Header().Get("X-RateLimit-Remaining") != "0" {
		t.Errorf("expected X-RateLimit-Remaining=0, got %s", w2.Header().Get("X-RateLimit-Remaining"))
	}
	if w2.Header().Get("Server") != "cloudflare" {
		t.Error("expected Server: cloudflare on 429")
	}
	if w2.Header().Get("Cf-Mitigated") != "challenge" {
		t.Error("expected Cf-Mitigated: challenge on 429")
	}

	// Parse response body
	var resp struct {
		Success    bool   `json:"success"`
		Error      string `json:"error"`
		RetryAfter int    `json:"retry_after"`
	}
	_ = json.NewDecoder(w2.Body).Decode(&resp)

	if resp.Success {
		t.Error("rate limited response should have success=false")
	}
	if resp.Error != "rate limited" {
		t.Errorf("expected error 'rate limited', got %q", resp.Error)
	}
	if resp.RetryAfter <= 0 {
		t.Error("expected positive retry_after in body")
	}
}

func TestTokenBucket_XForwardedFor(t *testing.T) {
	tb := NewTokenBucket(RateLimitConfig{
		Capacity:   1,
		RefillRate: 0.1,
	})

	// Exhaust the IP via X-Forwarded-For
	req1 := httptest.NewRequest(http.MethodPost, "/solve", nil)
	req1.Header.Set("X-Forwarded-For", "10.0.0.1, 192.168.1.1")
	tb.Allow(extractIP(req1))

	// Same X-Forwarded-For should be limited
	allowed, _, _ := tb.Allow(extractIP(req1))
	if allowed {
		t.Error("should be rate limited for same X-Forwarded-For IP")
	}

	// Different X-Forwarded-For should be allowed
	req2 := httptest.NewRequest(http.MethodPost, "/solve", nil)
	req2.Header.Set("X-Forwarded-For", "10.0.0.2")
	allowed, _, _ = tb.Allow(extractIP(req2))
	if !allowed {
		t.Error("different X-Forwarded-For IP should be allowed")
	}
}

func TestExtractIP_RemoteAddr(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.168.1.100:45678"

	ip := extractIP(r)
	if ip != "192.168.1.100" {
		t.Errorf("expected 192.168.1.100, got %s", ip)
	}
}

func TestExtractIP_XForwardedFor(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2, 10.0.0.3")

	ip := extractIP(r)
	if ip != "10.0.0.1" {
		t.Errorf("expected first IP 10.0.0.1, got %s", ip)
	}
}
