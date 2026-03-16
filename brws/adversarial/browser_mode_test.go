package adversarial

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/skunkworq/stealth/brws/constants"
)

// TestShield_CatchesOldStealthPlugins verifies that the shield detects the
// outdated 5-plugin stealth kit signature (Native Client + dual PDF variants).
func TestShield_CatchesOldStealthPlugins(t *testing.T) {
	sd := NewStealthDetector()

	// Old stealth script plugin signature: 5 plugins including Native Client
	plugins := []map[string]interface{}{
		{"name": "Chrome PDF Plugin", "filename": "internal-pdf-viewer"},
		{"name": "Chrome PDF Viewer", "filename": "mhjfbmdgcfjbbpaeojofohoefgiehjai"},
		{"name": "Native Client", "filename": "internal-nacl-plugin"},
		{"name": "Chromium PDF Plugin", "filename": "internal-pdf-viewer"},
		{"name": "Chromium PDF Viewer", "filename": "mhjfbmdgcfjbbpaeojofohoefgiehjai"},
	}
	navData := map[string]interface{}{
		"webdriver": false,
		"platform":  "Win32",
		"vendor":    "Google Inc.",
		"plugins":   plugins,
	}
	navJSON, _ := json.Marshal(navData)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set(constants.HeaderNavigatorData, string(navJSON))

	detection := sd.AnalyzeRequest(req, nil)

	t.Logf("Score: %.2f, IsBot: %v", detection.Score, detection.IsBot)
	for _, v := range detection.Vectors {
		if v.Score > 0 {
			t.Logf("  Vector %s: score=%.2f indicators=%v", v.Name, v.Score, v.Indicators)
		}
	}

	// Should detect both Native Client anachronism and dual PDF signature
	found := map[string]bool{}
	for _, v := range detection.Vectors {
		for _, ind := range v.Indicators {
			found[ind] = true
		}
	}

	if !found["plugin_anachronism_native_client"] {
		t.Error("expected plugin_anachronism_native_client indicator")
	}
	if !found["plugin_dual_pdf_signature"] {
		t.Error("expected plugin_dual_pdf_signature indicator")
	}
}

// TestShield_CatchesLoadTimesZeroFPAL verifies detection of spoofed
// chrome.loadTimes() where firstPaintAfterLoadTime is always 0.
func TestShield_CatchesLoadTimesZeroFPAL(t *testing.T) {
	sd := NewStealthDetector()

	navData := map[string]interface{}{
		"webdriver": false,
		"platform":  "Win32",
		"vendor":    "Google Inc.",
		"chrome_loadTimes": map[string]interface{}{
			"requestTime":             1710000000.0,
			"startLoadTime":           1710000000.5,
			"commitLoadTime":          1710000001.0,
			"firstPaintTime":          1710000001.5,
			"finishDocumentLoadTime":  1710000002.0,
			"finishLoadTime":          1710000002.5,
			"firstPaintAfterLoadTime": 0.0, // stealth script signature!
		},
	}
	navJSON, _ := json.Marshal(navData)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set(constants.HeaderNavigatorData, string(navJSON))

	detection := sd.AnalyzeRequest(req, nil)

	t.Logf("Score: %.2f, IsBot: %v", detection.Score, detection.IsBot)

	found := false
	for _, v := range detection.Vectors {
		for _, ind := range v.Indicators {
			if ind == "loadtimes_zero_first_paint_after_load" {
				found = true
			}
		}
	}

	if !found {
		t.Error("expected loadtimes_zero_first_paint_after_load indicator")
	}
}

// TestShield_CatchesGeometryGapSignature verifies detection of the exact 85px
// or 165px geometry gap that stealth scripts commonly use.
func TestShield_CatchesGeometryGapSignature(t *testing.T) {
	sd := NewStealthDetector()

	for _, gap := range []float64{85, 165} {
		t.Run("gap_"+string(rune('0'+int(gap/85)*80+'5')), func(t *testing.T) {
			navData := map[string]interface{}{
				"webdriver":   false,
				"platform":    "Win32",
				"outerHeight": 1000 + gap,
				"innerHeight": 1000.0,
			}
			navJSON, _ := json.Marshal(navData)

			req, _ := http.NewRequest("GET", "https://example.com", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
			req.Header.Set(constants.HeaderNavigatorData, string(navJSON))

			detection := sd.AnalyzeRequest(req, nil)

			found := false
			for _, v := range detection.Vectors {
				for _, ind := range v.Indicators {
					if ind == "geometry_gap_stealth_signature_85" || ind == "geometry_gap_stealth_signature_165" {
						found = true
					}
				}
			}

			if !found {
				t.Errorf("expected geometry_gap_stealth_signature for gap=%.0f", gap)
			}
		})
	}
}

// TestShield_PassesModernStealthPlugins verifies that the updated stealth
// script's 2-plugin list (PDF Viewer + Chrome PDF Viewer) does NOT trigger
// the anachronism or dual-variant gates.
func TestShield_PassesModernStealthPlugins(t *testing.T) {
	sd := NewStealthDetector()

	// Modern stealth script: only 2 PDF plugins, no Native Client
	plugins := []map[string]interface{}{
		{"name": "PDF Viewer", "filename": "internal-pdf-viewer"},
		{"name": "Chrome PDF Viewer", "filename": "internal-pdf-viewer"},
	}
	navData := map[string]interface{}{
		"webdriver": false,
		"platform":  "Win32",
		"vendor":    "Google Inc.",
		"plugins":   plugins,
	}
	navJSON, _ := json.Marshal(navData)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set(constants.HeaderNavigatorData, string(navJSON))

	detection := sd.AnalyzeRequest(req, nil)

	for _, v := range detection.Vectors {
		for _, ind := range v.Indicators {
			if ind == "plugin_anachronism_native_client" {
				t.Error("modern plugin list should NOT trigger plugin_anachronism_native_client")
			}
			if ind == "plugin_dual_pdf_signature" {
				t.Error("modern plugin list should NOT trigger plugin_dual_pdf_signature")
			}
		}
	}
}

// TestShield_PassesRealisticLoadTimes verifies that properly constructed
// chrome.loadTimes() with non-zero firstPaintAfterLoadTime passes cleanly.
func TestShield_PassesRealisticLoadTimes(t *testing.T) {
	sd := NewStealthDetector()

	navData := map[string]interface{}{
		"webdriver": false,
		"platform":  "Win32",
		"vendor":    "Google Inc.",
		"chrome_loadTimes": map[string]interface{}{
			"requestTime":             1710000000.0,
			"startLoadTime":           1710000000.05,
			"commitLoadTime":          1710000000.5,
			"firstPaintTime":          1710000000.8,
			"finishDocumentLoadTime":  1710000001.3,
			"finishLoadTime":          1710000001.5,
			"firstPaintAfterLoadTime": 1710000001.65, // non-zero!
		},
	}
	navJSON, _ := json.Marshal(navData)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set(constants.HeaderNavigatorData, string(navJSON))

	detection := sd.AnalyzeRequest(req, nil)

	for _, v := range detection.Vectors {
		for _, ind := range v.Indicators {
			if ind == "loadtimes_zero_first_paint_after_load" {
				t.Error("realistic loadTimes should NOT trigger loadtimes_zero_first_paint_after_load")
			}
		}
	}
}

// TestShield_PassesVariableGeometryGap verifies that non-signature geometry
// gaps (e.g. 92px, 78px) pass without triggering the stealth signature gate.
func TestShield_PassesVariableGeometryGap(t *testing.T) {
	sd := NewStealthDetector()

	for _, gap := range []float64{78, 92, 103} {
		navData := map[string]interface{}{
			"webdriver":   false,
			"platform":    "Win32",
			"outerHeight": 1000 + gap,
			"innerHeight": 1000.0,
		}
		navJSON, _ := json.Marshal(navData)

		req, _ := http.NewRequest("GET", "https://example.com", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
		req.Header.Set(constants.HeaderNavigatorData, string(navJSON))

		detection := sd.AnalyzeRequest(req, nil)

		for _, v := range detection.Vectors {
			for _, ind := range v.Indicators {
				if ind == "geometry_gap_stealth_signature_85" || ind == "geometry_gap_stealth_signature_165" {
					t.Errorf("gap=%.0f should NOT trigger geometry signature detection", gap)
				}
			}
		}
	}
}

// TestShield_CatchesToStringOverride verifies detection when toString is overridden.
func TestShield_CatchesToStringOverride(t *testing.T) {
	sd := NewStealthDetector()

	navData := map[string]interface{}{
		"webdriver":           false,
		"platform":            "Win32",
		"toString_overridden": true,
	}
	navJSON, _ := json.Marshal(navData)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set(constants.HeaderNavigatorData, string(navJSON))

	detection := sd.AnalyzeRequest(req, nil)

	found := false
	for _, v := range detection.Vectors {
		for _, ind := range v.Indicators {
			if ind == "function_tostring_override_detected" {
				found = true
			}
		}
	}

	if !found {
		t.Error("expected function_tostring_override_detected indicator")
	}
}

// TestShield_CatchesWebdriverGetterNameAnomaly verifies detection when
// the webdriver getter has a non-standard function name.
func TestShield_CatchesWebdriverGetterNameAnomaly(t *testing.T) {
	sd := NewStealthDetector()

	navData := map[string]interface{}{
		"webdriver":       false,
		"platform":        "Win32",
		"webdriverString": "function get webdriver() { [native code] }",
		"webdriver_descriptor": map[string]interface{}{
			"configurable": true,
			"enumerable":   true,
			"getter_name":  "webdriver", // wrong — should be "get webdriver"
		},
	}
	navJSON, _ := json.Marshal(navData)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set(constants.HeaderNavigatorData, string(navJSON))

	detection := sd.AnalyzeRequest(req, nil)

	found := false
	for _, v := range detection.Vectors {
		for _, ind := range v.Indicators {
			if ind == "webdriver_getter_name_anomaly" {
				found = true
			}
		}
	}

	if !found {
		t.Error("expected webdriver_getter_name_anomaly indicator")
	}
}

// TestShield_PassesCorrectWebdriverGetter verifies that a properly named
// "get webdriver" getter does NOT trigger the anomaly detection.
func TestShield_PassesCorrectWebdriverGetter(t *testing.T) {
	sd := NewStealthDetector()

	navData := map[string]interface{}{
		"webdriver":       false,
		"platform":        "Win32",
		"webdriverString": "function get webdriver() { [native code] }",
		"webdriver_descriptor": map[string]interface{}{
			"configurable": true,
			"enumerable":   true,
			"getter_name":  "get webdriver", // correct Chrome name
		},
	}
	navJSON, _ := json.Marshal(navData)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set(constants.HeaderNavigatorData, string(navJSON))

	detection := sd.AnalyzeRequest(req, nil)

	for _, v := range detection.Vectors {
		for _, ind := range v.Indicators {
			if ind == "webdriver_getter_name_anomaly" {
				t.Error("correctly named getter should NOT trigger webdriver_getter_name_anomaly")
			}
		}
	}
}

// TestShield_CatchesLockedWebdriverDescriptor verifies detection when
// the webdriver property descriptor has configurable=false (post-patch lockdown).
func TestShield_CatchesLockedWebdriverDescriptor(t *testing.T) {
	sd := NewStealthDetector()

	navData := map[string]interface{}{
		"webdriver":       false,
		"platform":        "Win32",
		"webdriverString": "function get webdriver() { [native code] }",
		"webdriver_descriptor": map[string]interface{}{
			"configurable": false, // locked after patching
			"enumerable":   true,
			"getter_name":  "get webdriver",
		},
	}
	navJSON, _ := json.Marshal(navData)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	req.Header.Set(constants.HeaderNavigatorData, string(navJSON))

	detection := sd.AnalyzeRequest(req, nil)

	found := false
	for _, v := range detection.Vectors {
		for _, ind := range v.Indicators {
			if ind == "webdriver_descriptor_locked" {
				found = true
			}
		}
	}

	if !found {
		t.Error("expected webdriver_descriptor_locked indicator")
	}
}
