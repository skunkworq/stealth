package tlsfprint

import (
	"strings"
	"testing"
)

func TestCalculateHTTP1Fingerprint(t *testing.T) {
	headers := map[string]string{
		"user-agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
		"accept":          "text/html",
		"accept-language": "en-US",
	}

	fp := CalculateHTTP1Fingerprint(headers)

	if fp == "" {
		t.Error("expected non-empty fingerprint")
	}

	t.Logf("HTTP/1.1 Fingerprint: %s", fp)
}

func TestCalculateJA3H1(t *testing.T) {
	headers := map[string]string{
		"user-agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
		"accept":          "text/html",
		"accept-language": "en-US",
		"accept-encoding": "gzip, deflate, br",
	}

	ja3h1 := CalculateJA3H1(headers)

	if ja3h1 == "" {
		t.Error("expected non-empty JA3H1")
	}

	if len(ja3h1) != 32 {
		t.Errorf("expected JA3H1 length 32, got %d", len(ja3h1))
	}

	t.Logf("JA3H1: %s", ja3h1)
}

func TestHTTP1Signatures(t *testing.T) {
	for name, sig := range HTTP1Signatures {
		t.Run(name, func(t *testing.T) {
			if sig.Name == "" {
				t.Error("expected non-empty name")
			}
			if sig.Platform == "" {
				t.Error("expected non-empty platform")
			}
			if sig.UserAgent == "" {
				t.Error("expected non-empty user agent")
			}

			ja3h1 := CalculateJA3H1(sig.Headers)
			t.Logf("%s JA3H1: %s", name, ja3h1)
		})
	}
}

func TestDetectBrowserFromHTTP1(t *testing.T) {
	tests := []struct {
		headers       map[string]string
		expectedMatch string
	}{
		{
			headers: map[string]string{
				"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
			},
			expectedMatch: "chrome",
		},
		{
			headers: map[string]string{
				"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
			},
			expectedMatch: "firefox",
		},
		{
			headers: map[string]string{
				"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.1 Safari/605.1.15",
			},
			expectedMatch: "safari",
		},
		{
			headers: map[string]string{
				"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
			},
			expectedMatch: "edge",
		},
		{
			headers: map[string]string{
				"user-agent": "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36",
			},
			expectedMatch: "chrome-mobile",
		},
		{
			headers:       map[string]string{},
			expectedMatch: "unknown",
		},
	}

	for _, tt := range tests {
		result := DetectBrowserFromHTTP1(tt.headers)
		if result != tt.expectedMatch {
			t.Errorf("expected %s, got %s", tt.expectedMatch, result)
		}
	}
}

func TestMatchHTTP1Signature(t *testing.T) {
	chromeHeaders := map[string]string{
		"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
		"accept":     "text/html",
	}

	match := MatchHTTP1Signature(chromeHeaders)
	if match == nil {
		t.Error("expected to match Chrome signature")
	} else {
		t.Logf("Matched signature: %s", match.Name)
	}

	firefoxHeaders := map[string]string{
		"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
		"accept":     "text/html",
	}

	match = MatchHTTP1Signature(firefoxHeaders)
	if match == nil {
		t.Error("expected to match Firefox signature")
	} else {
		t.Logf("Matched signature: %s", match.Name)
	}

	safariHeaders := map[string]string{
		"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.1 Safari/605.1.15",
		"accept":     "text/html",
	}

	match = MatchHTTP1Signature(safariHeaders)
	if match == nil {
		t.Error("expected to match Safari signature")
	} else {
		t.Logf("Matched signature: %s", match.Name)
	}

	edgeHeaders := map[string]string{
		"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		"accept":     "text/html",
	}

	match = MatchHTTP1Signature(edgeHeaders)
	if match == nil {
		t.Error("expected to match Edge signature")
	} else {
		t.Logf("Matched signature: %s", match.Name)
	}
}

func TestHTTP1Analyzer(t *testing.T) {
	analyzer := NewHTTP1Analyzer()

	headers := map[string]string{
		"user-agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
		"accept":          "text/html",
		"accept-language": "en-US",
		"accept-encoding": "gzip, deflate, br",
		"sec-ch-ua":       `"Not_A Brand";v="8", "Chromium";v="120"`,
		"sec-fetch-dest":  "document",
		"sec-fetch-mode":  "navigate",
	}

	obs := analyzer.Record(headers)

	if obs.JA3H1 == "" {
		t.Error("expected non-empty JA3H1 in observation")
	}

	if obs.DetectedBrowser != "chrome" {
		t.Errorf("expected chrome, got %s", obs.DetectedBrowser)
	}

	if obs.SignatureMatch == nil {
		t.Error("expected signature match")
	}

	observations := analyzer.GetObservations()
	if len(observations) != 1 {
		t.Errorf("expected 1 observation, got %d", len(observations))
	}

	unique := analyzer.GetUniqueFingerprints()
	if len(unique) != 1 {
		t.Errorf("expected 1 unique fingerprint, got %d", len(unique))
	}

	dist := analyzer.GetBrowserDistribution()
	if dist["chrome"] != 1 {
		t.Errorf("expected chrome count 1, got %d", dist["chrome"])
	}

	sigDist := analyzer.GetSignatureMatchDistribution()
	t.Logf("Signature match distribution: %v", sigDist)
}

func TestHTTP1FingerprintEquality(t *testing.T) {
	headers1 := map[string]string{
		"user-agent":      "Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36",
		"accept":          "text/html",
		"accept-language": "en-US",
	}
	headers2 := map[string]string{
		"user-agent":      "Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36",
		"accept":          "text/html",
		"accept-language": "en-US",
	}

	fp1 := CalculateHTTP1Fingerprint(headers1)
	fp2 := CalculateHTTP1Fingerprint(headers2)

	if fp1 != fp2 {
		t.Errorf("expected equal fingerprints")
	}

	ja3h1_1 := CalculateJA3H1(headers1)
	ja3h1_2 := CalculateJA3H1(headers2)

	if ja3h1_1 != ja3h1_2 {
		t.Errorf("expected equal JA3H1")
	}

	t.Logf("Fingerprint: %s, JA3H1: %s", fp1, ja3h1_1)
}

func TestHTTP1FingerprintDifference(t *testing.T) {
	chromeHeaders := map[string]string{
		"user-agent":      "Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36",
		"accept":          "text/html",
		"accept-language": "en-US",
	}
	firefoxHeaders := map[string]string{
		"user-agent":      "Mozilla/5.0 Firefox/120.0",
		"accept":          "text/html",
		"accept-language": "en-US",
	}

	fp1 := CalculateHTTP1Fingerprint(chromeHeaders)
	fp2 := CalculateHTTP1Fingerprint(firefoxHeaders)

	if fp1 == fp2 {
		t.Error("expected different fingerprints")
	}

	t.Logf("Chrome FP: %s", fp1)
	t.Logf("Firefox FP: %s", fp2)
}

func TestExtractBrowserInfo(t *testing.T) {
	tests := []struct {
		ua               string
		expectedBrowser  string
		expectedPlatform string
	}{
		{
			ua:               "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
			expectedBrowser:  "chrome",
			expectedPlatform: "Windows",
		},
		{
			ua:               "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
			expectedBrowser:  "firefox",
			expectedPlatform: "Windows",
		},
		{
			ua:               "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.1 Safari/605.1.15",
			expectedBrowser:  "safari",
			expectedPlatform: "macOS",
		},
		{
			ua:               "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36",
			expectedBrowser:  "chrome-mobile",
			expectedPlatform: "Android",
		},
		{
			ua:               "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
			expectedBrowser:  "safari-mobile",
			expectedPlatform: "iOS",
		},
	}

	for _, tt := range tests {
		browser, version, platform := ExtractBrowserInfo(tt.ua)
		t.Logf("UA: %s -> browser: %s, version: %s, platform: %s", tt.ua, browser, version, platform)

		if browser != tt.expectedBrowser {
			t.Errorf("expected browser %s, got %s", tt.expectedBrowser, browser)
		}
		if platform != tt.expectedPlatform {
			t.Errorf("expected platform %s, got %s", tt.expectedPlatform, platform)
		}
	}
}

func TestValidateUserAgent(t *testing.T) {
	validUAs := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.1 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		"Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36",
	}

	invalidUAs := []string{
		"",
		"curl/7.81.0",
		"python-requests/2.28.0",
		"Go-http-client/1.1",
	}

	for _, ua := range validUAs {
		if !ValidateUserAgent(ua) {
			t.Errorf("expected valid UA: %s", ua)
		}
	}

	for _, ua := range invalidUAs {
		if ValidateUserAgent(ua) {
			t.Errorf("expected invalid UA: %s", ua)
		}
	}
}

func TestHTTPHeaderGenerator(t *testing.T) {
	sig := HTTP1Signatures["chrome-120-windows"]
	gen := NewHTTPHeaderGenerator(sig, false, 0)

	headers := map[string]string{
		"custom-header": "value",
	}

	generated := gen.Generate(headers)

	if generated["user-agent"] != sig.UserAgent {
		t.Errorf("expected user-agent %s, got %s", sig.UserAgent, generated["user-agent"])
	}

	if generated["custom-header"] != "value" {
		t.Error("expected custom-header to be preserved")
	}

	t.Logf("Generated headers: %v", generated)
}

func TestHTTPHeaderGeneratorWithRandomization(t *testing.T) {
	sig := HTTP1Signatures["chrome-120-windows"]
	gen := NewHTTPHeaderGenerator(sig, true, 12345)

	headers := map[string]string{
		"accept":          "text/html",
		"accept-language": "en-US",
		"user-agent":      sig.UserAgent,
	}

	order := gen.PermuteHeaderOrder(headers)
	t.Logf("Permuted header order: %v", order)

	gen2 := NewHTTPHeaderGenerator(sig, false, 0)
	order2 := gen2.PermuteHeaderOrder(headers)
	t.Logf("Non-permuted header order: %v", order2)
}

func TestHTTP1SignaturesChromeVariants(t *testing.T) {
	chromeWindows := HTTP1Signatures["chrome-120-windows"]
	chromeMacOS := HTTP1Signatures["chrome-120-macos"]
	chromeAndroid := HTTP1Signatures["chrome-120-android"]

	if chromeWindows.Platform != "Windows" {
		t.Errorf("expected Windows, got %s", chromeWindows.Platform)
	}
	if chromeMacOS.Platform != "macOS" {
		t.Errorf("expected macOS, got %s", chromeMacOS.Platform)
	}
	if chromeAndroid.Platform != "Android" {
		t.Errorf("expected Android, got %s", chromeAndroid.Platform)
	}

	if chromeWindows.Headers["sec-ch-ua-platform"] != `"Windows"` {
		t.Errorf("expected sec-ch-ua-platform Windows, got %s", chromeWindows.Headers["sec-ch-ua-platform"])
	}
	if chromeAndroid.Headers["sec-ch-ua-mobile"] != "?1" {
		t.Errorf("expected sec-ch-ua-mobile ?1 for Android, got %s", chromeAndroid.Headers["sec-ch-ua-mobile"])
	}

	t.Logf("Chrome Windows UA: %s", chromeWindows.UserAgent)
	t.Logf("Chrome macOS UA: %s", chromeMacOS.UserAgent)
	t.Logf("Chrome Android UA: %s", chromeAndroid.UserAgent)
}

func TestHTTP1SignaturesFirefoxVariants(t *testing.T) {
	firefoxWindows := HTTP1Signatures["firefox-120-windows"]
	firefoxMacOS := HTTP1Signatures["firefox-120-macos"]

	if firefoxWindows.Platform != "Windows" {
		t.Errorf("expected Windows, got %s", firefoxWindows.Platform)
	}
	if firefoxMacOS.Platform != "macOS" {
		t.Errorf("expected macOS, got %s", firefoxMacOS.Platform)
	}

	if _, ok := firefoxWindows.Headers["sec-ch-ua"]; ok {
		t.Error("Firefox should not have sec-ch-ua headers")
	}

	if _, ok := firefoxWindows.Headers["sec-fetch-dest"]; !ok {
		t.Error("Firefox should have sec-fetch-dest header")
	}

	t.Logf("Firefox Windows UA: %s", firefoxWindows.UserAgent)
	t.Logf("Firefox macOS UA: %s", firefoxMacOS.UserAgent)
}

func TestHTTP1SignaturesSafari(t *testing.T) {
	safari := HTTP1Signatures["safari-17-macos"]

	if safari.Platform != "macOS" {
		t.Errorf("expected macOS, got %s", safari.Platform)
	}

	if _, ok := safari.Headers["sec-ch-ua"]; ok {
		t.Error("Safari should not have sec-ch-ua headers")
	}

	if safari.Headers["sec-fetch-site"] != "same-origin" {
		t.Errorf("expected sec-fetch-site same-origin, got %s", safari.Headers["sec-fetch-site"])
	}

	t.Logf("Safari macOS UA: %s", safari.UserAgent)
}

func TestHTTP1SignaturesEdge(t *testing.T) {
	edge := HTTP1Signatures["edge-120-windows"]

	if edge.Platform != "Windows" {
		t.Errorf("expected Windows, got %s", edge.Platform)
	}

	if edge.Headers["sec-ch-ua"] == "" || !strings.Contains(edge.Headers["sec-ch-ua"], "Microsoft Edge") {
		t.Errorf("Edge should have Microsoft Edge in sec-ch-ua, got: %s", edge.Headers["sec-ch-ua"])
	}

	t.Logf("Edge Windows UA: %s", edge.UserAgent)
}

//nolint:unused
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

//nolint:unused
func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
