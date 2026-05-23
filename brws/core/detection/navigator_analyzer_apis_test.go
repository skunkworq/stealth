package detection

import (
	"encoding/json"
	"net/http"
	"testing"
)

func setNavigatorHeader(req *http.Request, data map[string]interface{}) {
	b, _ := json.Marshal(data)
	req.Header.Set("X-Navigator-Data", string(b))
}

func TestNewNavigatorAnalyzer(t *testing.T) {
	na := newNavigatorAnalyzer()
	if na == nil {
		t.Fatal("NewNavigatorAnalyzer returned nil")
	}
}

func TestNavigatorAnalyzer_Analyze_noHeader(t *testing.T) {
	na := newNavigatorAnalyzer()
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	result := na.Analyze(req)
	if result != nil {
		t.Error("expected nil when X-Navigator-Data header is absent")
	}
}

func TestNavigatorAnalyzer_Analyze_invalidJSON(t *testing.T) {
	na := newNavigatorAnalyzer()
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("X-Navigator-Data", "not-json")
	result := na.Analyze(req)
	if result != nil {
		t.Error("expected nil for invalid JSON navigator data")
	}
}

func TestNavigatorAnalyzer_Analyze_webdriverTrue(t *testing.T) {
	na := newNavigatorAnalyzer()
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	setNavigatorHeader(req, map[string]interface{}{
		"webdriver": true,
	})
	result := na.Analyze(req)
	if result == nil {
		t.Fatal("Analyze returned nil")
	}
	if result.Score <= 0 {
		t.Error("expected positive score when webdriver=true")
	}
}

func TestNavigatorAnalyzer_Analyze_webdriverFalse(t *testing.T) {
	na := newNavigatorAnalyzer()
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0")
	setNavigatorHeader(req, map[string]interface{}{
		"webdriver": false,
		"vendor":    "Google Inc.",
		"platform":  "MacIntel",
	})
	result := na.Analyze(req)
	if result == nil {
		t.Fatal("Analyze returned nil")
	}
	// webdriver=false should not add webdriver indicator
	for _, ind := range result.Indicators {
		if ind == "webdriver_true" || ind == "webdriver" {
			t.Errorf("unexpected webdriver indicator: %s", ind)
		}
	}
}

func TestNavigatorAnalyzer_Analyze_vendorMismatch_chromeUA(t *testing.T) {
	na := newNavigatorAnalyzer()
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0")
	setNavigatorHeader(req, map[string]interface{}{
		"webdriver": false,
		"vendor":    "bad-vendor", // mismatch with Chrome UA
	})
	result := na.Analyze(req)
	if result == nil {
		t.Fatal("Analyze returned nil")
	}
	if result.Score <= 0 {
		t.Error("expected positive score for Chrome UA with wrong vendor")
	}
}

func TestNavigatorAnalyzer_Analyze_correctChromeVendor(t *testing.T) {
	na := newNavigatorAnalyzer()
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0")
	setNavigatorHeader(req, map[string]interface{}{
		"webdriver": false,
		"vendor":    "Google Inc.",
	})
	result := na.Analyze(req)
	if result == nil {
		t.Fatal("Analyze returned nil")
	}
	// vendor is correct, should not add vendor_mismatch indicator
	for _, ind := range result.Indicators {
		if ind == "vendor_browser_mismatch" {
			t.Error("unexpected vendor_browser_mismatch indicator")
		}
	}
}

func TestNavigatorAnalyzer_Analyze_returnsCategory(t *testing.T) {
	na := newNavigatorAnalyzer()
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	setNavigatorHeader(req, map[string]interface{}{})
	result := na.Analyze(req)
	if result == nil {
		t.Fatal("Analyze returned nil")
	}
	if result.Category != "navigator" {
		t.Errorf("Category = %q, want navigator", result.Category)
	}
}

func TestNavigatorAnalyzer_Analyze_scoreNotExceedOne(t *testing.T) {
	na := newNavigatorAnalyzer()
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	// Worst case: webdriver=true plus many flags
	setNavigatorHeader(req, map[string]interface{}{
		"webdriver":         true,
		"__webdriver_script_fn":  "present",
		"__fxdriver_evaluate":    "present",
	})
	result := na.Analyze(req)
	if result == nil {
		t.Fatal("Analyze returned nil")
	}
	if result.Score < 0 {
		t.Errorf("Score = %f, should not be negative", result.Score)
	}
}

func TestNavigatorAnalyzer_Analyze_firefoxUA_emptyVendor(t *testing.T) {
	na := newNavigatorAnalyzer()
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0")
	setNavigatorHeader(req, map[string]interface{}{
		"webdriver": false,
		"vendor":    "", // Firefox uses empty vendor
	})
	result := na.Analyze(req)
	if result == nil {
		t.Fatal("Analyze returned nil")
	}
	// Empty vendor for Firefox should not trigger vendor mismatch
	for _, ind := range result.Indicators {
		if ind == "vendor_browser_mismatch" {
			t.Error("unexpected vendor_browser_mismatch for Firefox with empty vendor")
		}
	}
}

func TestNavigatorAnalyzer_Analyze_checkReports(t *testing.T) {
	na := newNavigatorAnalyzer()
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	setNavigatorHeader(req, map[string]interface{}{
		"webdriver": true,
	})
	result := na.Analyze(req)
	if result == nil {
		t.Fatal("Analyze returned nil")
	}
	if len(result.CheckReports) == 0 {
		t.Error("expected at least one CheckReport for webdriver=true")
	}
	for _, cr := range result.CheckReports {
		if cr.Name == "" {
			t.Error("CheckReport has empty Name")
		}
	}
}

func TestNavigatorAnalyzer_Analyze_emptyNavData(t *testing.T) {
	na := newNavigatorAnalyzer()
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	setNavigatorHeader(req, map[string]interface{}{})
	result := na.Analyze(req)
	if result == nil {
		t.Fatal("Analyze returned nil for empty nav data")
	}
	// Empty data - no webdriver flag, just missing fields
	if result.Category != "navigator" {
		t.Errorf("Category = %q, want navigator", result.Category)
	}
}
