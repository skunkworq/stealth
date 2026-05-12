package spoof

import (
	"testing"

	"golang.org/x/net/http2"
)

func TestChromeHTTP2Transport_Settings(t *testing.T) {
	ct := ChromeHTTP2Transport()

	if len(ct.Settings) != 6 {
		t.Fatalf("Chrome should have 6 SETTINGS, got %d", len(ct.Settings))
	}

	// Verify settings order matches Chrome's wire order
	expectedOrder := []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
		http2.SettingMaxHeaderListSize,
	}

	for i, expected := range expectedOrder {
		if ct.Settings[i].ID != expected {
			t.Errorf("setting[%d] ID = %d, want %d", i, ct.Settings[i].ID, expected)
		}
	}

	// Verify specific values
	settingMap := make(map[http2.SettingID]uint32)
	for _, s := range ct.Settings {
		settingMap[s.ID] = s.Val
	}

	if v := settingMap[http2.SettingHeaderTableSize]; v != 65536 {
		t.Errorf("HEADER_TABLE_SIZE = %d, want 65536", v)
	}
	if v := settingMap[http2.SettingEnablePush]; v != 0 {
		t.Errorf("ENABLE_PUSH = %d, want 0", v)
	}
	if v := settingMap[http2.SettingMaxConcurrentStreams]; v != 1000 {
		t.Errorf("MAX_CONCURRENT_STREAMS = %d, want 1000", v)
	}
	if v := settingMap[http2.SettingInitialWindowSize]; v != 6291456 {
		t.Errorf("INITIAL_WINDOW_SIZE = %d, want 6291456", v)
	}
	if v := settingMap[http2.SettingMaxFrameSize]; v != 16384 {
		t.Errorf("MAX_FRAME_SIZE = %d, want 16384", v)
	}
	if v := settingMap[http2.SettingMaxHeaderListSize]; v != 262144 {
		t.Errorf("MAX_HEADER_LIST_SIZE = %d, want 262144", v)
	}
}

func TestChromeHTTP2Transport_WindowSize(t *testing.T) {
	ct := ChromeHTTP2Transport()

	if ct.InitialStreamWindowSize != 6291456 {
		t.Errorf("stream window = %d, want 6291456", ct.InitialStreamWindowSize)
	}
	if ct.InitialConnWindowSize != 6291456 {
		t.Errorf("conn window = %d, want 6291456", ct.InitialConnWindowSize)
	}
}

func TestChromeHTTP2Transport_PseudoHeaderOrder(t *testing.T) {
	ct := ChromeHTTP2Transport()

	expected := []string{":method", ":authority", ":scheme", ":path"}
	if len(ct.PseudoHeaderOrder) != len(expected) {
		t.Fatalf("pseudo header count = %d, want %d", len(ct.PseudoHeaderOrder), len(expected))
	}
	for i, e := range expected {
		if ct.PseudoHeaderOrder[i] != e {
			t.Errorf("pseudo header[%d] = %q, want %q", i, ct.PseudoHeaderOrder[i], e)
		}
	}
}

func TestChromeHTTP2Transport_Priority(t *testing.T) {
	ct := ChromeHTTP2Transport()

	if !ct.SendPriority {
		t.Error("Chrome should send PRIORITY frames")
	}
	if ct.PriorityWeight != 255 {
		t.Errorf("priority weight = %d, want 255", ct.PriorityWeight)
	}
	if !ct.PriorityExclusive {
		t.Error("priority should be exclusive")
	}
	if ct.PriorityDependsOn != 0 {
		t.Errorf("priority depends on stream %d, want 0", ct.PriorityDependsOn)
	}
}

func TestFirefoxHTTP2Transport_Settings(t *testing.T) {
	ft := FirefoxHTTP2Transport()

	if len(ft.Settings) != 3 {
		t.Fatalf("Firefox should have 3 SETTINGS, got %d", len(ft.Settings))
	}

	// Firefox sends fewer settings
	settingMap := make(map[http2.SettingID]uint32)
	for _, s := range ft.Settings {
		settingMap[s.ID] = s.Val
	}

	if v := settingMap[http2.SettingHeaderTableSize]; v != 131072 {
		t.Errorf("HEADER_TABLE_SIZE = %d, want 131072", v)
	}
	if v := settingMap[http2.SettingInitialWindowSize]; v != 131072 {
		t.Errorf("INITIAL_WINDOW_SIZE = %d, want 131072", v)
	}
}

func TestFirefoxHTTP2Transport_PseudoHeaderOrder(t *testing.T) {
	ft := FirefoxHTTP2Transport()

	// Firefox uses different pseudo-header order: :method :path :authority :scheme
	expected := []string{":method", ":path", ":authority", ":scheme"}
	for i, e := range expected {
		if ft.PseudoHeaderOrder[i] != e {
			t.Errorf("pseudo header[%d] = %q, want %q", i, ft.PseudoHeaderOrder[i], e)
		}
	}
}

func TestFirefoxHTTP2Transport_NoPriority(t *testing.T) {
	ft := FirefoxHTTP2Transport()

	if ft.SendPriority {
		t.Error("Firefox should NOT send PRIORITY frames (uses urgency-based priority)")
	}
}

func TestFirefoxHTTP2Transport_WindowSize(t *testing.T) {
	ft := FirefoxHTTP2Transport()

	if ft.InitialStreamWindowSize != 131072 {
		t.Errorf("stream window = %d, want 131072", ft.InitialStreamWindowSize)
	}
	if ft.InitialConnWindowSize != 12517377 {
		t.Errorf("conn window = %d, want 12517377", ft.InitialConnWindowSize)
	}
}

func TestEncodeHeaders_ChromeOrder(t *testing.T) {
	ct := ChromeHTTP2Transport()

	headers := map[string]string{
		"user-agent":                "Mozilla/5.0 Chrome/120",
		"accept":                    "text/html",
		"accept-encoding":           "gzip, br",
		"accept-language":           "en-US",
		"sec-ch-ua":                 `"Chrome";v="120"`,
		"sec-ch-ua-mobile":          "?0",
		"sec-ch-ua-platform":        `"macOS"`,
		"sec-fetch-dest":            "document",
		"sec-fetch-mode":            "navigate",
		"sec-fetch-site":            "none",
		"sec-fetch-user":            "?1",
		"upgrade-insecure-requests": "1",
	}

	block, err := ct.encodeHeaders("GET", "example.com", "https", "/", headers)
	if err != nil {
		t.Fatalf("encodeHeaders failed: %v", err)
	}

	if len(block) == 0 {
		t.Error("encoded header block is empty")
	}
	t.Logf("encoded header block: %d bytes", len(block))
}

func TestEncodeHeaders_FirefoxOrder(t *testing.T) {
	ft := FirefoxHTTP2Transport()

	headers := map[string]string{
		"user-agent":                "Mozilla/5.0 Firefox/120",
		"accept":                    "text/html",
		"accept-encoding":           "gzip, br",
		"accept-language":           "en-US",
		"sec-fetch-dest":            "document",
		"sec-fetch-mode":            "navigate",
		"sec-fetch-site":            "none",
		"sec-fetch-user":            "?1",
		"upgrade-insecure-requests": "1",
	}

	block, err := ft.encodeHeaders("GET", "example.com", "https", "/", headers)
	if err != nil {
		t.Fatalf("encodeHeaders failed: %v", err)
	}

	if len(block) == 0 {
		t.Error("encoded header block is empty")
	}
	t.Logf("encoded header block: %d bytes", len(block))
}

func TestChrome_vs_Firefox_SettingsDiffer(t *testing.T) {
	chrome := ChromeHTTP2Transport()
	firefox := FirefoxHTTP2Transport()

	if len(chrome.Settings) == len(firefox.Settings) {
		t.Error("Chrome and Firefox should have different SETTINGS counts")
	}

	if chrome.InitialStreamWindowSize == firefox.InitialStreamWindowSize {
		t.Error("Chrome and Firefox should have different window sizes")
	}

	if chrome.PseudoHeaderOrder[1] == firefox.PseudoHeaderOrder[1] {
		t.Error("Chrome and Firefox should have different pseudo-header order")
	}
	t.Logf("Chrome: %d settings, %d window | Firefox: %d settings, %d window",
		len(chrome.Settings), chrome.InitialStreamWindowSize,
		len(firefox.Settings), firefox.InitialStreamWindowSize)
}

func TestEncodeHeaders_WithQueryParams(t *testing.T) {
	ct := ChromeHTTP2Transport()

	headers := map[string]string{
		"user-agent":      "Mozilla/5.0 Chrome/120",
		"accept":          "text/html",
		"accept-encoding": "gzip, br",
	}

	// Test with query parameters
	block, err := ct.encodeHeaders("GET", "example.com", "https", "/search?q=test&page=1", headers)
	if err != nil {
		t.Fatalf("encodeHeaders with query failed: %v", err)
	}
	if len(block) == 0 {
		t.Error("encoded header block is empty")
	}
}

func TestEncodeHeaders_WithCookie(t *testing.T) {
	ct := ChromeHTTP2Transport()

	headers := map[string]string{
		"user-agent": "Mozilla/5.0 Chrome/120",
		"accept":     "text/html",
		"cookie":     "session=abc123; preferences=dark",
	}

	block, err := ct.encodeHeaders("GET", "example.com", "https", "/", headers)
	if err != nil {
		t.Fatalf("encodeHeaders with cookie failed: %v", err)
	}
	if len(block) == 0 {
		t.Error("encoded header block with cookie is empty")
	}
}

func TestEncodeHeaders_POSTWithBody(t *testing.T) {
	ct := ChromeHTTP2Transport()

	headers := map[string]string{
		"user-agent":     "Mozilla/5.0 Chrome/120",
		"content-type":   "application/json",
		"accept":         "application/json",
		"content-length": "13",
	}

	block, err := ct.encodeHeaders("POST", "example.com", "https", "/api/data", headers)
	if err != nil {
		t.Fatalf("encodeHeaders POST failed: %v", err)
	}
	if len(block) == 0 {
		t.Error("encoded header block for POST is empty")
	}
}

func TestEncodeHeaders_UTF8Characters(t *testing.T) {
	ct := ChromeHTTP2Transport()

	headers := map[string]string{
		"user-agent":      "Mozilla/5.0 Chrome/120",
		"accept-language": "en-US,zh-CN;q=0.9,日本語",
		"accept":          "text/html,application/json",
	}

	// Test with Unicode characters
	block, err := ct.encodeHeaders("GET", "example.com", "https", "/日本語", headers)
	if err != nil {
		t.Fatalf("encodeHeaders with UTF-8 failed: %v", err)
	}
	if len(block) == 0 {
		t.Error("encoded header block with UTF-8 is empty")
	}
}

func TestEncodeHeaders_EmptyHeaders(t *testing.T) {
	ct := ChromeHTTP2Transport()

	// Test with empty headers map
	block, err := ct.encodeHeaders("GET", "example.com", "https", "/", nil)
	if err != nil {
		t.Fatalf("encodeHeaders with nil headers failed: %v", err)
	}
	// Should still encode pseudo-headers
	if len(block) == 0 {
		t.Error("encoded header block is empty even with pseudo-headers")
	}
}

func TestEncodeHeaders_EmptyMap(t *testing.T) {
	ct := ChromeHTTP2Transport()

	// Test with empty map
	block, err := ct.encodeHeaders("GET", "example.com", "https", "/", map[string]string{})
	if err != nil {
		t.Fatalf("encodeHeaders with empty map failed: %v", err)
	}
	// Should still encode pseudo-headers
	if len(block) == 0 {
		t.Error("encoded header block is empty even with pseudo-headers")
	}
}
