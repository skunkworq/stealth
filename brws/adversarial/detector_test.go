package adversarial

import (
	"net/http"
	"testing"

	"github.com/stealth/brwslab/brws/types"
)

func TestDetector_New(t *testing.T) {
	d := NewDetector()
	if d == nil {
		t.Fatal("expected non-nil detector")
	}
	if d.baselines == nil {
		t.Error("expected baselines map to be initialized")
	}
	if d.results == nil {
		t.Error("expected results slice to be initialized")
	}
}

func TestDetector_DetectFromJA3(t *testing.T) {
	d := NewDetector()

	tests := []struct {
		name     string
		ja3      string
		wantBot  bool
		minScore float64
	}{
		{
			name:     "normal browser with many ciphers",
			ja3:      "772,4865-4866-4867-49171-49172-49173-49174-49195-49196-49199-49200-49155-49160-49161-49171-49172-49173-49174-49175-49176-156-157-158-159-160-161,0-23-35-13-45-16-43-27-51-53-21-61-41-47-29-19,29-23-30-25-24-256-257-258-259-260-43-51-45-50-19-22-20-21-47-54-53-48-49-52-55-58-57-56-64-65-66-67-68-69-70-71-72",
			wantBot:  false,
			minScore: 0.0,
		},
		{
			name:     "suspicious minimal fingerprint",
			ja3:      "771,1,0",
			wantBot:  true,
			minScore: 0.3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isBot, score := d.DetectFromJA3(tt.ja3)
			if isBot != tt.wantBot {
				t.Errorf("DetectFromJA3() isBot = %v, want %v", isBot, tt.wantBot)
			}
			if score < tt.minScore {
				t.Errorf("DetectFromJA3() score = %v, want >= %v", score, tt.minScore)
			}
		})
	}
}

func TestDetector_DetectFromHeaders(t *testing.T) {
	d := NewDetector()

	tests := []struct {
		name    string
		headers http.Header
		wantBot bool
	}{
		{
			name: "normal browser headers",
			headers: http.Header{
				"User-Agent":      []string{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"},
				"Accept":          []string{"text/html"},
				"Accept-Language": []string{"en-US,en;q=0.9"},
			},
			wantBot: false,
		},
		{
			name: "suspicious user agent",
			headers: http.Header{
				"User-Agent": []string{"python-requests/2.28.0"},
				"Accept":     []string{"*/*"},
			},
			wantBot: true,
		},
		{
			name: "inconsistent client hints",
			headers: http.Header{
				"User-Agent":         []string{"Mozilla/5.0"},
				"Sec-Ch-Ua":          []string{"\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\""},
				"Sec-Ch-Ua-Platform": []string{"Linux"},
			},
			wantBot: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isBot, _ := d.DetectFromHeaders(tt.headers)
			if isBot != tt.wantBot {
				t.Errorf("DetectFromHeaders() isBot = %v, want %v", isBot, tt.wantBot)
			}
		})
	}
}

func TestDetector_CompareToBaseline(t *testing.T) {
	d := NewDetector()

	baseline := &types.CompleteFingerprint{
		TLS: &types.TLSFingerprint{
			JA4: "t13d",
		},
		HTTP: &types.HTTPFingerprint{
			UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
		},
	}
	d.LoadBaseline("chrome", baseline)

	// Test matching fingerprint
	matching := &types.CompleteFingerprint{
		TLS: &types.TLSFingerprint{
			JA4: "t13d",
		},
		HTTP: &types.HTTPFingerprint{
			UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
		},
	}

	result := d.CompareToBaseline("chrome", matching)
	if result.IsBot {
		t.Error("expected matching fingerprint to not be flagged as bot")
	}
	if result.Score != 0.0 {
		t.Errorf("expected score 0.0 for matching fingerprint, got %f", result.Score)
	}

	// Test mismatching fingerprint
	mismatching := &types.CompleteFingerprint{
		TLS: &types.TLSFingerprint{
			JA4: "t99z", // Different JA4
		},
		HTTP: &types.HTTPFingerprint{
			UserAgent: "curl/7.88.1", // Different UA
		},
	}

	result = d.CompareToBaseline("chrome", mismatching)
	if !result.IsBot {
		t.Error("expected mismatching fingerprint to be flagged as bot")
	}
	if result.Score < 0.3 {
		t.Errorf("expected score > 0.3 for mismatching fingerprint, got %f", result.Score)
	}
}

func TestDetector_LoadBaseline(t *testing.T) {
	d := NewDetector()

	baseline := &types.CompleteFingerprint{
		TLS: &types.TLSFingerprint{
			JA4: "test-ja4",
		},
	}

	d.LoadBaseline("test", baseline)

	// Verify baseline is stored
	d.mu.RLock()
	stored := d.baselines["test"]
	d.mu.RUnlock()

	//nolint:staticcheck // SA5011: Test validation
	if stored == nil {
		t.Error("expected baseline to be stored")
	}
	//nolint:staticcheck // SA5011: Test validation
	if stored.TLS.JA4 != "test-ja4" {
		t.Errorf("expected JA4 'test-ja4', got %s", stored.TLS.JA4)
	}
}

func TestDetector_AddResult(t *testing.T) {
	d := NewDetector()

	result := DetectionResult{
		IsBot:      true,
		Score:      0.8,
		Confidence: 0.8,
	}

	d.AddResult(result)

	results := d.GetResults()
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
	if !results[0].IsBot {
		t.Error("expected result to be flagged as bot")
	}
}

func TestIsGREASE(t *testing.T) {
	tests := []struct {
		value    uint16
		expected bool
	}{
		{0x0a0a, true},  // GREASE
		{0x0a0f, true},  // GREASE
		{0x1a0a, true},  // GREASE
		{0xabcd, false}, // Not GREASE
		{0x002f, false}, // Not GREASE
		{0xc02f, false}, // Not GREASE
	}

	for _, tt := range tests {
		result := isGREASE(tt.value)
		if result != tt.expected {
			t.Errorf("isGREASE(0x%04x) = %v, want %v", tt.value, result, tt.expected)
		}
	}
}

func TestIsSuspiciousUserAgent(t *testing.T) {
	tests := []struct {
		ua       string
		expected bool
	}{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", false},
		{"curl/7.88.1", true},
		{"python-requests/2.28.0", true},
		{"HeadlessChrome/120.0.0.0", true},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", false},
	}

	for _, tt := range tests {
		result := isSuspiciousUserAgent(tt.ua)
		if result != tt.expected {
			t.Errorf("isSuspiciousUserAgent(%q) = %v, want %v", tt.ua, result, tt.expected)
		}
	}
}
