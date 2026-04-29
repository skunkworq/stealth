package spoof

import (
	"net/http"
	"testing"
)

func TestOrderedHeaders_MaintainsOrder(t *testing.T) {
	order := []string{"User-Agent", "Accept", "Accept-Language", "Accept-Encoding"}
	oh := NewOrderedHeaders(order)

	oh.Set("Accept", "text/html")
	oh.Set("User-Agent", "Mozilla/5.0")
	oh.Set("Accept-Language", "en-US")
	oh.Set("Accept-Encoding", "gzip, br")

	keys := oh.SortedKeys()
	if len(keys) != 4 {
		t.Fatalf("expected 4 keys, got %d", len(keys))
	}

	// Keys should come out in the predefined order, not insertion order
	expected := []string{"User-Agent", "Accept", "Accept-Language", "Accept-Encoding"}
	for i, key := range keys {
		if key != expected[i] {
			t.Errorf("key[%d] = %q, want %q", i, key, expected[i])
		}
	}
}

func TestOrderedHeaders_ChromeOrder(t *testing.T) {
	// Chrome 116 header order from the signature
	sig := GetChrome116()
	order := headerOrderFromSignature(sig.HTTP)

	oh := NewOrderedHeaders(order)

	// Add headers in random order (simulating Go map iteration)
	oh.Set("accept-language", "en-US,en;q=0.9")
	oh.Set("sec-fetch-dest", "document")
	oh.Set("user-agent", "Mozilla/5.0 Chrome/116")
	oh.Set("sec-ch-ua", `"Chromium";v="116"`)
	oh.Set("accept", "text/html")
	oh.Set("sec-fetch-mode", "navigate")
	oh.Set("sec-ch-ua-mobile", "?0")
	oh.Set("accept-encoding", "gzip, deflate, br")
	oh.Set("sec-fetch-site", "none")
	oh.Set("sec-ch-ua-platform", `"Windows"`)
	oh.Set("upgrade-insecure-requests", "1")
	oh.Set("sec-fetch-user", "?1")

	keys := oh.SortedKeys()

	// Expected Chrome 116 order (pseudo-headers filtered out)
	expectedOrder := []string{
		"Sec-Ch-Ua",
		"Sec-Ch-Ua-Mobile",
		"Sec-Ch-Ua-Platform",
		"Upgrade-Insecure-Requests",
		"User-Agent",
		"Accept",
		"Sec-Fetch-Site",
		"Sec-Fetch-Mode",
		"Sec-Fetch-User",
		"Sec-Fetch-Dest",
		"Accept-Encoding",
		"Accept-Language",
	}

	if len(keys) != len(expectedOrder) {
		t.Fatalf("expected %d keys, got %d: %v", len(expectedOrder), len(keys), keys)
	}

	for i, key := range keys {
		if key != expectedOrder[i] {
			t.Errorf("Chrome order[%d] = %q, want %q", i, key, expectedOrder[i])
		}
	}
}

func TestOrderedHeaders_UnknownHeadersAppended(t *testing.T) {
	order := []string{"User-Agent", "Accept"}
	oh := NewOrderedHeaders(order)

	oh.Set("User-Agent", "Mozilla/5.0")
	oh.Set("Accept", "text/html")
	oh.Set("X-Custom-Header", "custom-value")
	oh.Set("Authorization", "Bearer token")

	keys := oh.SortedKeys()
	if len(keys) != 4 {
		t.Fatalf("expected 4 keys, got %d", len(keys))
	}

	// First two should be in predefined order
	if keys[0] != "User-Agent" {
		t.Errorf("key[0] = %q, want %q", keys[0], "User-Agent")
	}
	if keys[1] != "Accept" {
		t.Errorf("key[1] = %q, want %q", keys[1], "Accept")
	}

	// Remaining keys should be the unknown ones (order among unknowns is not guaranteed)
	unknowns := make(map[string]bool)
	for _, k := range keys[2:] {
		unknowns[k] = true
	}
	if !unknowns["X-Custom-Header"] {
		t.Error("X-Custom-Header not found in unknown headers")
	}
	if !unknowns["Authorization"] {
		t.Error("Authorization not found in unknown headers")
	}
}

func TestOrderedHeaders_ApplyToRequest(t *testing.T) {
	order := []string{"Sec-Ch-Ua", "User-Agent", "Accept", "Accept-Encoding"}
	oh := NewOrderedHeaders(order)

	oh.Set("User-Agent", "Mozilla/5.0")
	oh.Set("Accept", "text/html")
	oh.Set("Sec-Ch-Ua", `"Chrome";v="116"`)
	oh.Set("Accept-Encoding", "gzip")

	req, err := http.NewRequest("GET", "https://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	oh.ApplyTo(req)

	// Verify all headers are present
	if req.Header.Get("User-Agent") != "Mozilla/5.0" {
		t.Errorf("User-Agent = %q, want %q", req.Header.Get("User-Agent"), "Mozilla/5.0")
	}
	if req.Header.Get("Accept") != "text/html" {
		t.Errorf("Accept = %q, want %q", req.Header.Get("Accept"), "text/html")
	}
	if req.Header.Get("Sec-Ch-Ua") != `"Chrome";v="116"` {
		t.Errorf("Sec-Ch-Ua = %q, want %q", req.Header.Get("Sec-Ch-Ua"), `"Chrome";v="116"`)
	}
	if req.Header.Get("Accept-Encoding") != "gzip" {
		t.Errorf("Accept-Encoding = %q, want %q", req.Header.Get("Accept-Encoding"), "gzip")
	}

	// Verify the header map has exactly the right number of keys
	if len(req.Header) != 4 {
		t.Errorf("expected 4 headers, got %d", len(req.Header))
	}
}

func TestOrderedHeaders_PseudoHeadersFiltered(t *testing.T) {
	order := []string{":method", ":authority", ":scheme", ":path", "user-agent", "accept"}
	oh := NewOrderedHeaders(order)

	// Pseudo-headers should be filtered out
	keys := oh.Order()
	for _, k := range keys {
		if k[0] == ':' {
			t.Errorf("pseudo-header %q should have been filtered", k)
		}
	}
	if len(keys) != 2 {
		t.Errorf("expected 2 keys (pseudo-headers filtered), got %d: %v", len(keys), keys)
	}
}

func TestOrderedHeaders_Del(t *testing.T) {
	order := []string{"User-Agent", "Accept", "Accept-Encoding"}
	oh := NewOrderedHeaders(order)

	oh.Set("User-Agent", "Mozilla/5.0")
	oh.Set("Accept", "text/html")
	oh.Set("Accept-Encoding", "gzip")

	oh.Del("Accept")

	keys := oh.SortedKeys()
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys after delete, got %d", len(keys))
	}
	if keys[0] != "User-Agent" || keys[1] != "Accept-Encoding" {
		t.Errorf("unexpected keys after delete: %v", keys)
	}
	if oh.Get("Accept") != "" {
		t.Error("deleted key still returns a value")
	}
}

func TestOrderedHeaders_Clone(t *testing.T) {
	order := []string{"User-Agent", "Accept"}
	oh := NewOrderedHeaders(order)
	oh.Set("User-Agent", "Mozilla/5.0")
	oh.Set("Accept", "text/html")

	clone := oh.Clone()

	// Modify original
	oh.Set("User-Agent", "Changed")
	oh.Set("X-New", "new")

	// Clone should be unaffected
	if clone.Get("User-Agent") != "Mozilla/5.0" {
		t.Errorf("clone User-Agent = %q, want %q", clone.Get("User-Agent"), "Mozilla/5.0")
	}
	if clone.Get("X-New") != "" {
		t.Error("clone should not have X-New")
	}
	if len(clone.Order()) != 2 {
		t.Errorf("clone order length = %d, want 2", len(clone.Order()))
	}
}

func TestSpoofEngine_HeaderOrdering(t *testing.T) {
	engine, err := NewSpoofEngine("chrome-116")
	if err != nil {
		t.Fatalf("NewSpoofEngine failed: %v", err)
	}

	// Verify the engine has header order populated
	if len(engine.headerOrder) == 0 {
		t.Fatal("engine.headerOrder should not be empty")
	}

	// Create a request and add headers in non-Chrome order
	req, err := http.NewRequest("GET", "https://example.com/test", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set headers in alphabetical order (wrong for Chrome)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Encoding", "gzip, br")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Sec-Ch-Ua", `"Chrome";v="116"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/116")

	// Apply header ordering (the private method)
	engine.applyHeaderOrder(req)

	// After applying, the header map should contain all headers
	if req.Header.Get("User-Agent") != "Mozilla/5.0 Chrome/116" {
		t.Errorf("User-Agent lost after reordering: %q", req.Header.Get("User-Agent"))
	}
	if req.Header.Get("Accept") != "text/html" {
		t.Errorf("Accept lost after reordering: %q", req.Header.Get("Accept"))
	}
	if len(req.Header) != 12 {
		t.Errorf("expected 12 headers, got %d", len(req.Header))
	}

	// Verify the engine's header order matches Chrome 116 signature
	expectedOrder := []string{
		"sec-ch-ua",
		"sec-ch-ua-mobile",
		"sec-ch-ua-platform",
		"upgrade-insecure-requests",
		"user-agent",
		"accept",
		"sec-fetch-site",
		"sec-fetch-mode",
		"sec-fetch-user",
		"sec-fetch-dest",
		"accept-encoding",
		"accept-language",
	}

	if len(engine.headerOrder) != len(expectedOrder) {
		t.Fatalf("header order length = %d, want %d", len(engine.headerOrder), len(expectedOrder))
	}

	for i, name := range engine.headerOrder {
		if name != expectedOrder[i] {
			t.Errorf("headerOrder[%d] = %q, want %q", i, name, expectedOrder[i])
		}
	}
}

func TestSpoofEngine_HeaderOrderPreservesRequestHeaders(t *testing.T) {
	engine, err := NewSpoofEngine("chrome-116")
	if err != nil {
		t.Fatalf("NewSpoofEngine failed: %v", err)
	}

	req, err := http.NewRequest("POST", "https://example.com/api", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set some signature headers and some request-specific ones
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "abc123")

	engine.applyHeaderOrder(req)

	// All headers should be preserved
	if req.Header.Get("Content-Type") != "application/json" {
		t.Error("Content-Type was lost")
	}
	if req.Header.Get("X-Request-Id") != "abc123" {
		t.Error("X-Request-Id was lost")
	}
	if req.Header.Get("User-Agent") != "Mozilla/5.0" {
		t.Error("User-Agent was lost")
	}
}

func TestSpoofEngineFromSignature_HeaderOrdering(t *testing.T) {
	sig := GetFirefox109()
	engine, err := NewSpoofEngineFromSignature("firefox-test", sig)
	if err != nil {
		t.Fatalf("NewSpoofEngineFromSignature failed: %v", err)
	}

	if len(engine.headerOrder) == 0 {
		t.Fatal("engine.headerOrder should not be empty for Firefox")
	}

	// Firefox header order should differ from Chrome
	// Firefox puts user-agent first, Chrome puts sec-ch-ua first
	expectedFirst := "user-agent"
	if engine.headerOrder[0] != expectedFirst {
		t.Errorf("Firefox headerOrder[0] = %q, want %q", engine.headerOrder[0], expectedFirst)
	}
}

func TestHeaderOrderFromSignature_NilHTTP(t *testing.T) {
	order := headerOrderFromSignature(nil)
	if order != nil {
		t.Errorf("expected nil for nil HTTP signature, got %v", order)
	}
}

func TestHeaderOrderFromSignature_FiltersPseudoHeaders(t *testing.T) {
	sig := &HTTPSignature{
		Headers: []HeaderEntry{
			{Name: ":method", Value: "GET"},
			{Name: ":authority", Value: ""},
			{Name: "user-agent", Value: "Mozilla/5.0"},
			{Name: "accept", Value: "text/html"},
		},
	}

	order := headerOrderFromSignature(sig)
	if len(order) != 2 {
		t.Fatalf("expected 2 entries (pseudo-headers filtered), got %d: %v", len(order), order)
	}
	if order[0] != "user-agent" || order[1] != "accept" {
		t.Errorf("unexpected order: %v", order)
	}
}
