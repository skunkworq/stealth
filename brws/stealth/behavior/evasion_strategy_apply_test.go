package behavior

import (
	"net/http"
	"testing"
)

// newTestRequest returns a GET request pre-populated with common browser-looking headers
// so Apply() has something to strip/mutate.
func newTestRequest(t *testing.T, target string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, nil)
	if err != nil {
		t.Fatalf("newTestRequest: %v", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
	req.Header.Set("Sec-Ch-Ua", `"Chromium";v="120"`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("X-Canvas-Fingerprint", "canvas_data")
	req.Header.Set("X-Behavioral-Data", "behavioral_data")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://example.com")
	return req
}

func newTestRG(t *testing.T) *RequestGenerator {
	t.Helper()
	return NewRequestGenerator(nil)
}

func TestFirefoxInitNavStrategy_Apply(t *testing.T) {
	rg := newTestRG(t)
	req := newTestRequest(t, "https://example.com/page")
	s := &FirefoxInitNavStrategy{}
	s.Apply(req, rg, "https://example.com/page")

	if req.Method != http.MethodGet {
		t.Errorf("expected GET, got %s", req.Method)
	}
	if req.Header.Get("Sec-Fetch-Dest") != "document" {
		t.Errorf("expected Sec-Fetch-Dest=document, got %q", req.Header.Get("Sec-Fetch-Dest"))
	}
	if req.Header.Get("Sec-Fetch-Mode") != "navigate" {
		t.Errorf("expected Sec-Fetch-Mode=navigate, got %q", req.Header.Get("Sec-Fetch-Mode"))
	}
	if req.Header.Get("Sec-Fetch-Site") != "none" {
		t.Errorf("expected Sec-Fetch-Site=none, got %q", req.Header.Get("Sec-Fetch-Site"))
	}
	if req.Header.Get("Sec-Fetch-User") != "?1" {
		t.Errorf("expected Sec-Fetch-User=?1, got %q", req.Header.Get("Sec-Fetch-User"))
	}
	// Firefox strips Sec-Ch-Ua headers
	if req.Header.Get("Sec-Ch-Ua") != "" {
		t.Error("Sec-Ch-Ua should be stripped for Firefox")
	}
	// Runtime fingerprint headers should be stripped
	if req.Header.Get("X-Canvas-Fingerprint") != "" {
		t.Error("X-Canvas-Fingerprint runtime header should be stripped")
	}
	// Firefox UA should be set
	ua := req.Header.Get("User-Agent")
	if ua == "" {
		t.Error("User-Agent should be set")
	}
	if req.Header.Get("Sec-Fetch-Mode") != "navigate" {
		t.Error("User-Agent should be Firefox UA")
	}
	// Origin and Content-Type should be removed for GET navigation
	if req.Header.Get("Origin") != "" {
		t.Error("Origin should be removed for initial navigation")
	}
	if req.Header.Get("Content-Type") != "" {
		t.Error("Content-Type should be removed for GET")
	}
}

func TestRealBrowserStrategy_Apply(t *testing.T) {
	rg := newTestRG(t)
	req := newTestRequest(t, "https://target.com/page")
	s := &RealBrowserStrategy{}
	s.Apply(req, rg, "https://target.com/page")

	if req.Method != http.MethodGet {
		t.Errorf("expected GET, got %s", req.Method)
	}
	if req.Header.Get("Sec-Fetch-Dest") != "document" {
		t.Errorf("expected Sec-Fetch-Dest=document, got %q", req.Header.Get("Sec-Fetch-Dest"))
	}
	if req.Header.Get("Sec-Fetch-Mode") != "navigate" {
		t.Errorf("expected Sec-Fetch-Mode=navigate, got %q", req.Header.Get("Sec-Fetch-Mode"))
	}
	if req.Header.Get("Sec-Fetch-Site") != "cross-site" {
		t.Errorf("expected Sec-Fetch-Site=cross-site, got %q", req.Header.Get("Sec-Fetch-Site"))
	}
	if req.Header.Get("Sec-Fetch-User") != "?1" {
		t.Errorf("expected Sec-Fetch-User=?1, got %q", req.Header.Get("Sec-Fetch-User"))
	}
	// Firefox UA (cross-site navigation from Google)
	if req.Header.Get("Sec-Ch-Ua") != "" {
		t.Error("Sec-Ch-Ua should be stripped for Firefox RealBrowserStrategy")
	}
	if req.Header.Get("Referer") != "https://www.google.com/" {
		t.Errorf("expected Referer=https://www.google.com/, got %q", req.Header.Get("Referer"))
	}
	// GET navigation: Origin not sent
	if req.Header.Get("Origin") != "" {
		t.Error("Origin should not be sent for GET navigation")
	}
}

func TestNoneContextCorsStrategy_Apply(t *testing.T) {
	rg := newTestRG(t)
	req := newTestRequest(t, "https://example.com/api")
	s := &NoneContextCorsStrategy{}
	s.Apply(req, rg, "https://example.com/api")

	if req.Method != http.MethodGet {
		t.Errorf("expected GET, got %s", req.Method)
	}
	if req.Header.Get("Sec-Fetch-Dest") != "document" {
		t.Errorf("expected Sec-Fetch-Dest=document, got %q", req.Header.Get("Sec-Fetch-Dest"))
	}
	if req.Header.Get("Sec-Fetch-Site") != "cross-site" {
		t.Errorf("expected Sec-Fetch-Site=cross-site, got %q", req.Header.Get("Sec-Fetch-Site"))
	}
}

func TestPostLoadSameOriginFetchStrategy_Apply(t *testing.T) {
	rg := newTestRG(t)
	req := newTestRequest(t, "https://example.com/data")
	s := &PostLoadSameOriginFetchStrategy{}
	s.Apply(req, rg, "https://example.com/data")

	if req.Header.Get("Sec-Fetch-Dest") != "empty" {
		t.Errorf("expected Sec-Fetch-Dest=empty, got %q", req.Header.Get("Sec-Fetch-Dest"))
	}
	if req.Header.Get("Sec-Fetch-Mode") != "cors" {
		t.Errorf("expected Sec-Fetch-Mode=cors, got %q", req.Header.Get("Sec-Fetch-Mode"))
	}
	if req.Header.Get("Sec-Fetch-Site") != "same-origin" {
		t.Errorf("expected Sec-Fetch-Site=same-origin, got %q", req.Header.Get("Sec-Fetch-Site"))
	}
	// Fetch requests don't include Sec-Fetch-User
	if req.Header.Get("Sec-Fetch-User") != "" {
		t.Error("Sec-Fetch-User should not be set for fetch requests")
	}
}

func TestPostLoadCrossSiteFetchStrategy_Apply(t *testing.T) {
	rg := newTestRG(t)
	req := newTestRequest(t, "https://cdn.example.com/asset.js")
	s := &PostLoadCrossSiteFetchStrategy{}
	s.Apply(req, rg, "https://cdn.example.com/asset.js")

	if req.Header.Get("Sec-Fetch-Dest") != "empty" {
		t.Errorf("expected Sec-Fetch-Dest=empty, got %q", req.Header.Get("Sec-Fetch-Dest"))
	}
	if req.Header.Get("Sec-Fetch-Site") != "cross-site" {
		t.Errorf("expected Sec-Fetch-Site=cross-site, got %q", req.Header.Get("Sec-Fetch-Site"))
	}
}

func TestStrategyNames(t *testing.T) {
	cases := []struct {
		strategy EvasionStrategy
		name     string
	}{
		{&FirefoxInitNavStrategy{}, "firefox_init_nav"},
		{&RealBrowserStrategy{}, "real_browser"},
		{&NoneContextCorsStrategy{}, "none_context_cors"},
		{&PostLoadSameOriginFetchStrategy{}, "postload_same_origin_fetch"},
		{&PostLoadCrossSiteFetchStrategy{}, "postload_cross_site_fetch"},
	}
	for _, tc := range cases {
		if tc.strategy.Name() != tc.name {
			t.Errorf("expected Name()=%q, got %q", tc.name, tc.strategy.Name())
		}
	}
}
