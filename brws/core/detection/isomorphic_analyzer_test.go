package detection_test

import (
	"net/http"
	"testing"

	"github.com/skunkworq/stealth/brws/core/detection"
)

func TestNewIsomorphicAnalyzer(t *testing.T) {
	ia := detection.NewIsomorphicAnalyzer()
	if ia == nil {
		t.Fatal("NewIsomorphicAnalyzer returned nil")
	}
}

func TestIsomorphicAnalyzer_Analyze_nilHTTPInfo(t *testing.T) {
	ia := detection.NewIsomorphicAnalyzer()
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	result := ia.Analyze(req, nil)
	if result != nil {
		t.Error("expected nil when httpInfo is nil")
	}
}

func TestIsomorphicAnalyzer_Analyze_emptyHTTPInfo(t *testing.T) {
	ia := detection.NewIsomorphicAnalyzer()
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	httpInfo := &detection.HTTPFingerprintInfo{}
	result := ia.Analyze(req, httpInfo)
	if result == nil {
		t.Fatal("Analyze returned nil for valid httpInfo")
	}
	if result.Name == "" {
		t.Error("result.Name should not be empty")
	}
	if result.Category != "isomorphic" {
		t.Errorf("Category = %q, want isomorphic", result.Category)
	}
}

func TestIsomorphicAnalyzer_Analyze_returnsDetectionVector(t *testing.T) {
	ia := detection.NewIsomorphicAnalyzer()
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	httpInfo := &detection.HTTPFingerprintInfo{
		UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
		Platform:       "macOS",
		SecCHUAPlatform: "macOS",
		AcceptLanguage: "en-US,en;q=0.9",
	}
	result := ia.Analyze(req, httpInfo)
	if result == nil {
		t.Fatal("Analyze returned nil")
	}
	if result.Weight <= 0 {
		t.Error("Weight should be positive")
	}
}

func TestIsomorphicAnalyzer_Analyze_scoreNotNegative(t *testing.T) {
	ia := detection.NewIsomorphicAnalyzer()
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	httpInfo := &detection.HTTPFingerprintInfo{
		UserAgent: "Mozilla/5.0 Chrome/120.0.0.0",
		Platform:  "Windows",
	}
	result := ia.Analyze(req, httpInfo)
	if result == nil {
		t.Fatal("Analyze returned nil")
	}
	if result.Score < 0 {
		t.Errorf("Score = %f, should not be negative", result.Score)
	}
	if result.Score > 1.0 {
		t.Errorf("Score = %f, should not exceed 1.0", result.Score)
	}
}

func TestIsomorphicAnalyzer_Analyze_detectedFlag(t *testing.T) {
	ia := detection.NewIsomorphicAnalyzer()
	req, _ := http.NewRequest("GET", "http://example.com", nil)

	// Clean request — should not be detected
	httpInfo := &detection.HTTPFingerprintInfo{
		UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
		Platform:       "macOS",
		SecCHUAPlatform: "macOS",
		AcceptLanguage: "en-US,en;q=0.9",
	}
	result := ia.Analyze(req, httpInfo)
	if result == nil {
		t.Fatal("Analyze returned nil")
	}
	// Detected flag should match score > 0
	if result.Detected != (result.Score > 0) {
		t.Errorf("Detected=%v but Score=%f (mismatch)", result.Detected, result.Score)
	}
}

func TestIsomorphicAnalyzer_Analyze_indicatorsSlice(t *testing.T) {
	ia := detection.NewIsomorphicAnalyzer()
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	httpInfo := &detection.HTTPFingerprintInfo{}
	result := ia.Analyze(req, httpInfo)
	if result == nil {
		t.Fatal("Analyze returned nil")
	}
	// Indicators should be a valid (possibly empty) slice, not nil when score is 0
	if result.Indicators == nil && result.Score > 0 {
		t.Error("Indicators slice is nil but Score > 0")
	}
}

func TestIsomorphicAnalyzer_Analyze_withNavigatorHeader(t *testing.T) {
	ia := detection.NewIsomorphicAnalyzer()
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Navigator-Data", `{"platform":"Win32","vendor":"Google Inc.","userAgent":"Mozilla/5.0 Chrome/120.0","languages":["en-US"]}`)
	httpInfo := &detection.HTTPFingerprintInfo{
		UserAgent: "Mozilla/5.0 Chrome/120.0",
		Platform:  "Windows",
	}
	result := ia.Analyze(req, httpInfo)
	if result == nil {
		t.Fatal("Analyze returned nil")
	}
	// Should produce a valid result (not panic)
	if result.Score < 0 || result.Score > 1.0 {
		t.Errorf("Score out of bounds: %f", result.Score)
	}
}

func TestIsomorphicAnalyzer_Analyze_noNavigatorData(t *testing.T) {
	ia := detection.NewIsomorphicAnalyzer()
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	httpInfo := &detection.HTTPFingerprintInfo{
		UserAgent: "Go-http-client/1.1",
	}
	result := ia.Analyze(req, httpInfo)
	if result == nil {
		t.Fatal("Analyze returned nil")
	}
}

func TestIsomorphicAnalyzer_Analyze_multipleCalls(t *testing.T) {
	ia := detection.NewIsomorphicAnalyzer()
	httpInfo := &detection.HTTPFingerprintInfo{
		UserAgent: "Mozilla/5.0 Chrome/120.0",
	}

	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		result := ia.Analyze(req, httpInfo)
		if result == nil {
			t.Fatalf("iteration %d: Analyze returned nil", i)
		}
	}
}
