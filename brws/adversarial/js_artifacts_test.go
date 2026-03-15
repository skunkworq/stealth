package adversarial_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/skunkworq/stealth/brws/adversarial"
	"github.com/skunkworq/stealth/brws/behavior"
	"github.com/skunkworq/stealth/brws/constants"
)

// buildNavRequest creates a minimal request with the given nav data JSON and User-Agent.
func buildNavRequest(t *testing.T, ua string, navData map[string]interface{}) *http.Request {
	t.Helper()
	req, _ := http.NewRequest("GET", "http://test/", nil)
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("X-Stealth-Header-Order", "User-Agent,Accept,Accept-Language,Accept-Encoding")

	b, _ := json.Marshal(navData)
	req.Header.Set(constants.HeaderNavigatorData, string(b))
	return req
}

func chromeUA() string {
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
}

func firefoxUA() string {
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"
}

// --- Chrome Artifact Tests ---

func TestJSArtifacts_Chrome_PassesDetection(t *testing.T) {
	navData := map[string]interface{}{
		"vendor":            "Google Inc.",
		"productSub":        "20030107",
		"hasChrome":         true,
		"chrome":            map[string]interface{}{},
		"pluginCount":       float64(5),
		"cookieEnabled":     true,
		"pdfViewerEnabled":  true,
		"webdriver":         false,
		"hasLocalStorage":   true,
		"hasSessionStorage": true,
		"hasIndexedDB":      true,
		"platform":          "Win32",
		"userAgent":         chromeUA(),
		"languages":         []interface{}{"en-US", "en"},
		"language":          "en-US",
		"maxTouchPoints":    float64(0),
	}

	req := buildNavRequest(t, chromeUA(), navData)
	detector := adversarial.NewStealthDetector()
	detection := detector.AnalyzeRequest(req, nil)

	// Check that no JS-artifact-related indicators fired
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			switch ind {
			case "productsub_browser_mismatch",
				"missing_window_chrome",
				"plugin_count_zero_chrome",
				"webdriver_true",
				"cookies_disabled",
				"missing_local_storage",
				"missing_session_storage",
				"missing_indexed_db":
				t.Errorf("Chrome artifacts should pass, but indicator fired: %s", ind)
			}
		}
	}
}

func TestJSArtifacts_Firefox_PassesDetection(t *testing.T) {
	navData := map[string]interface{}{
		"vendor":            "",
		"productSub":        "20100101",
		"pluginCount":       float64(0),
		"cookieEnabled":     true,
		"pdfViewerEnabled":  true,
		"webdriver":         false,
		"hasLocalStorage":   true,
		"hasSessionStorage": true,
		"hasIndexedDB":      true,
		"platform":          "Win32",
		"userAgent":         firefoxUA(),
		"languages":         []interface{}{"en-US", "en"},
		"language":          "en-US",
		"maxTouchPoints":    float64(0),
	}

	req := buildNavRequest(t, firefoxUA(), navData)
	detector := adversarial.NewStealthDetector()
	detection := detector.AnalyzeRequest(req, nil)

	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			switch ind {
			case "productsub_browser_mismatch",
				"plugin_count_nonzero_firefox",
				"webdriver_true",
				"cookies_disabled",
				"missing_local_storage",
				"missing_session_storage",
				"missing_indexed_db":
				t.Errorf("Firefox artifacts should pass, but indicator fired: %s", ind)
			}
		}
	}
}

func TestJSArtifacts_WrongVendor_Detected(t *testing.T) {
	// Chrome UA with Firefox vendor (empty string)
	navData := map[string]interface{}{
		"vendor":            "",
		"productSub":        "20030107",
		"hasChrome":         true,
		"chrome":            map[string]interface{}{},
		"pluginCount":       float64(5),
		"cookieEnabled":     true,
		"webdriver":         false,
		"platform":          "Win32",
		"userAgent":         chromeUA(),
		"languages":         []interface{}{"en-US", "en"},
		"language":          "en-US",
		"maxTouchPoints":    float64(0),
		"hasLocalStorage":   true,
		"hasSessionStorage": true,
		"hasIndexedDB":      true,
	}

	req := buildNavRequest(t, chromeUA(), navData)
	detector := adversarial.NewStealthDetector()
	detection := detector.AnalyzeRequest(req, nil)

	found := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if ind == "vendor_browser_mismatch: chrome_ua_vendor=\"\"" {
				found = true
			}
		}
	}

	if !found {
		t.Error("expected vendor_browser_mismatch for Chrome UA with empty vendor")
	}
}

func TestJSArtifacts_MissingChrome_Detected(t *testing.T) {
	// Chrome UA without window.chrome object
	navData := map[string]interface{}{
		"vendor":            "Google Inc.",
		"productSub":        "20030107",
		"pluginCount":       float64(5),
		"cookieEnabled":     true,
		"webdriver":         false,
		"platform":          "Win32",
		"userAgent":         chromeUA(),
		"languages":         []interface{}{"en-US", "en"},
		"language":          "en-US",
		"maxTouchPoints":    float64(0),
		"hasLocalStorage":   true,
		"hasSessionStorage": true,
		"hasIndexedDB":      true,
	}

	req := buildNavRequest(t, chromeUA(), navData)
	detector := adversarial.NewStealthDetector()
	detection := detector.AnalyzeRequest(req, nil)

	found := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if ind == "missing_window_chrome" || ind == "missing_chrome_runtime" {
				found = true
			}
		}
	}

	if !found {
		t.Error("expected missing_window_chrome or missing_chrome_runtime for Chrome UA without window.chrome")
	}
}

func TestJSArtifacts_WebDriverTrue_Detected(t *testing.T) {
	navData := map[string]interface{}{
		"vendor":            "Google Inc.",
		"productSub":        "20030107",
		"hasChrome":         true,
		"chrome":            map[string]interface{}{},
		"pluginCount":       float64(5),
		"cookieEnabled":     true,
		"webdriver":         true, // CAUGHT
		"platform":          "Win32",
		"userAgent":         chromeUA(),
		"languages":         []interface{}{"en-US", "en"},
		"language":          "en-US",
		"maxTouchPoints":    float64(0),
		"hasLocalStorage":   true,
		"hasSessionStorage": true,
		"hasIndexedDB":      true,
	}

	req := buildNavRequest(t, chromeUA(), navData)
	detector := adversarial.NewStealthDetector()
	detection := detector.AnalyzeRequest(req, nil)

	found := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if ind == "webdriver_true" || ind == "webdriver=true" {
				found = true
			}
		}
	}

	if !found {
		t.Error("expected webdriver detection for webdriver=true")
	}
}

func TestStorageCoherence_Normal_Passes(t *testing.T) {
	navData := map[string]interface{}{
		"vendor":            "Google Inc.",
		"productSub":        "20030107",
		"hasChrome":         true,
		"chrome":            map[string]interface{}{},
		"cookieEnabled":     true,
		"webdriver":         false,
		"hasLocalStorage":   true,
		"hasSessionStorage": true,
		"hasIndexedDB":      true,
		"platform":          "Win32",
		"userAgent":         chromeUA(),
		"languages":         []interface{}{"en-US", "en"},
		"language":          "en-US",
		"maxTouchPoints":    float64(0),
	}

	req := buildNavRequest(t, chromeUA(), navData)
	detector := adversarial.NewStealthDetector()
	detection := detector.AnalyzeRequest(req, nil)

	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			switch ind {
			case "missing_local_storage",
				"missing_session_storage",
				"missing_indexed_db":
				t.Errorf("storage coherence should pass, but indicator fired: %s", ind)
			}
		}
	}
}

func TestStorageCoherence_MissingIndexedDB_Detected(t *testing.T) {
	navData := map[string]interface{}{
		"vendor":            "Google Inc.",
		"productSub":        "20030107",
		"hasChrome":         true,
		"chrome":            map[string]interface{}{},
		"cookieEnabled":     true,
		"webdriver":         false,
		"hasLocalStorage":   true,
		"hasSessionStorage": true,
		"hasIndexedDB":      false, // CAUGHT
		"platform":          "Win32",
		"userAgent":         chromeUA(),
		"languages":         []interface{}{"en-US", "en"},
		"language":          "en-US",
		"maxTouchPoints":    float64(0),
	}

	req := buildNavRequest(t, chromeUA(), navData)
	detector := adversarial.NewStealthDetector()
	detection := detector.AnalyzeRequest(req, nil)

	found := false
	for _, vec := range detection.Vectors {
		for _, ind := range vec.Indicators {
			if ind == "missing_indexed_db" {
				found = true
			}
		}
	}

	if !found {
		t.Error("expected missing_indexed_db for hasIndexedDB=false")
	}
}

// TestSwordJSArtifacts_FullRequest verifies that the sword's full request
// generator includes proper JS engine artifacts that pass the shield.
func TestSwordJSArtifacts_FullRequest(t *testing.T) {
	profiles := behavior.DefaultProfiles()

	for _, profile := range profiles {
		t.Run(profile.Name, func(t *testing.T) {
			gen := behavior.NewRequestGenerator(&behavior.RequestGeneratorConfig{
				Profile:                    profile,
				EvadeHeaderOrder:           true,
				EvadePlugins:               true,
				EvadePointerInteraction:    true,
				EvadeMediaQueryHover:       true,
				EvadeNavigatorConnectivity: true,
				EvadeNavigatorHardware:     true,
				EvadeNavigatorModernAPIs:   true,
				EvadeNavigatorMediaAPIs:    true,
			})

			req := gen.GenerateRequest("http://test/api/ml/trap")

			// Verify the navigator data contains expected fields
			navHeader := req.Header.Get(constants.HeaderNavigatorData)
			if navHeader == "" {
				t.Fatal("missing X-Navigator-Data header")
			}

			var navData map[string]interface{}
			if err := json.Unmarshal([]byte(navHeader), &navData); err != nil {
				t.Fatalf("failed to parse nav data: %v", err)
			}

			// Check hasChrome flag
			if profile.Browser == "chrome" {
				if hasChrome, ok := navData["hasChrome"].(bool); !ok || !hasChrome {
					t.Error("Chrome profile should have hasChrome=true")
				}
			}

			// Check storage flags
			if hasLocal, ok := navData["hasLocalStorage"].(bool); !ok || !hasLocal {
				t.Error("missing or false hasLocalStorage")
			}
			if hasSession, ok := navData["hasSessionStorage"].(bool); !ok || !hasSession {
				t.Error("missing or false hasSessionStorage")
			}
			if hasIDB, ok := navData["hasIndexedDB"].(bool); !ok || !hasIDB {
				t.Error("missing or false hasIndexedDB")
			}

			// Check that vendor matches profile
			vendor, _ := navData["vendor"].(string)
			if vendor != profile.NavVendor {
				t.Errorf("vendor=%q, want %q", vendor, profile.NavVendor)
			}

			// Check productSub matches profile
			productSub, _ := navData["productSub"].(string)
			if productSub != profile.ProductSub {
				t.Errorf("productSub=%q, want %q", productSub, profile.ProductSub)
			}

			// Verify timing data includes connection timing
			timingHeader := req.Header.Get(constants.HeaderTimingData)
			if timingHeader != "" {
				var timingData map[string]interface{}
				if err := json.Unmarshal([]byte(timingHeader), &timingData); err == nil {
					if cs, ok := timingData["connectStart"].(float64); ok {
						ce, _ := timingData["connectEnd"].(float64)
						if ce-cs <= 0 {
							t.Errorf("connectEnd-connectStart should be >0, got %.0f", ce-cs)
						}
					}
					if re, ok := timingData["responseEnd"].(float64); ok {
						di, _ := timingData["domInteractive"].(float64)
						if di-re < 5 {
							t.Errorf("domInteractive-responseEnd should be >=5ms, got %.0f", di-re)
						}
					}
				}
			}
		})
	}
}
