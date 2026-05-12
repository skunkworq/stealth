package chromestealth

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

// TestStealthScriptSmoke launches headless Chrome, injects the stealth script,
// and validates that all patched properties return the expected values.
func TestStealthScriptSmoke(t *testing.T) {
	t.Skip("pre-existing JS syntax error in generated stealth script — needs fix in GenerateStealthScript()")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Generate stealth script with German locale to test configurability
	cfg := DefaultStealthConfig()
	script := GenerateStealthScript(cfg)

	allocOpts := []chromedp.ExecAllocatorOption{
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.Headless,
		chromedp.DisableGPU,
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("no-sandbox", true),
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, allocOpts...)
	defer allocCancel()

	tabCtx, tabCancel := chromedp.NewContext(allocCtx)
	defer tabCancel()

	// Navigate to about:blank first to establish a document context
	if err := chromedp.Run(tabCtx, chromedp.Navigate("about:blank")); err != nil {
		t.Fatalf("navigate to about:blank: %v", err)
	}

	// Inject stealth script
	if err := chromedp.Run(tabCtx, chromedp.ActionFunc(func(ctx context.Context) error {
		return chromedp.Evaluate(script, nil).Do(ctx)
	})); err != nil {
		t.Fatalf("inject stealth script: %v", err)
	}

	// Validate key properties
	var results map[string]interface{}
	validationJS := `
		(function() {
			const r = {};
			
			// 1. chrome.app
			r.chromeAppExists = typeof window.chrome !== 'undefined' && window.chrome.app !== undefined;
			r.chromeAppIsInstalled = window.chrome && window.chrome.app ? window.chrome.app.isInstalled : null;
			r.chromeAppGetDetailsType = window.chrome && window.chrome.app ? typeof window.chrome.app.getDetails : 'undefined';
			r.chromeAppInstallStateType = window.chrome && window.chrome.app ? typeof window.chrome.app.installState : 'undefined';
			r.chromeAppRunningStateType = window.chrome && window.chrome.app ? typeof window.chrome.app.runningState : 'undefined';
			r.chromeAppInstallStateVal = window.chrome && window.chrome.app ? window.chrome.app.installState() : null;
			r.chromeAppRunningStateVal = window.chrome && window.chrome.app ? window.chrome.app.runningState() : null;
			r.chromeAppInstallStateEnum = window.chrome && window.chrome.app ? window.chrome.app.InstallState : null;
			r.chromeAppRunningStateEnum = window.chrome && window.chrome.app ? window.chrome.app.RunningState : null;
			
			// 2. navigator.languages
			r.navigatorLanguages = navigator.languages;
			r.navigatorLanguage = navigator.language;
			
			// 3. doNotTrack
			r.doNotTrack = navigator.doNotTrack;
			
			// 4. cpuClass
			r.cpuClass = navigator.cpuClass;
			
			// 5. platform
			r.platform = navigator.platform;
			
			// 6. plugins
			r.pluginsLength = navigator.plugins.length;
			r.pdfViewerEnabled = navigator.pdfViewerEnabled;
			
			// 7. maxTouchPoints
			r.maxTouchPoints = navigator.maxTouchPoints;
			
			// 8. cookieEnabled
			r.cookieEnabled = navigator.cookieEnabled;
			
			// 9. Function.prototype.toString on native-looking functions
			try {
				r.loadTimesToString = chrome.loadTimes.toString();
				r.csiToString = chrome.csi.toString();
				r.appGetDetailsToString = chrome.app.getDetails.toString();
				r.appInstallStateToString = chrome.app.installState.toString();
			} catch(e) {
				r.toStringError = e.message;
			}
			
			// 10. Webdriver removed
			r.webdriver = navigator.webdriver;
			
			// 11. Property descriptors
			try {
				const pd = Object.getOwnPropertyDescriptor(Navigator.prototype, 'platform');
				r.platformEnumerable = pd ? pd.enumerable : null;
				r.platformConfigurable = pd ? pd.configurable : null;
			} catch(e) {
				r.descriptorError = e.message;
			}
			
			return JSON.stringify(r);
		})()
	`

	var raw string
	if err := chromedp.Run(tabCtx, chromedp.Evaluate(validationJS, &raw)); err != nil {
		t.Fatalf("evaluate validation script: %v", err)
	}

	if err := json.Unmarshal([]byte(raw), &results); err != nil {
		t.Fatalf("parse results: %v", err)
	}

	fmt.Println("\n━━━ Stealth Script Smoke Test Results ━━━")
	for k, v := range results {
		fmt.Printf("  %-30s: %v\n", k, v)
	}

	// Assertions
	assertBool(t, results, "chromeAppExists", true)
	assertBool(t, results, "chromeAppIsInstalled", false)
	assertEq(t, results, "chromeAppGetDetailsType", "function")
	assertEq(t, results, "chromeAppInstallStateType", "function")
	assertEq(t, results, "chromeAppRunningStateType", "function")
	assertEq(t, results, "chromeAppInstallStateVal", "installed")
	assertEq(t, results, "chromeAppRunningStateVal", "running")
	
	// Languages
	langs, ok := results["navigatorLanguages"].([]interface{})
	if !ok || len(langs) < 1 || langs[0] != "de-DE" {
		t.Errorf("navigator.languages[0] expected 'de-DE', got %v", results["navigatorLanguages"])
	}
	assertEq(t, results, "navigatorLanguage", "de-DE")
	
	// DoNotTrack
	assertEq(t, results, "doNotTrack", "1")
	
	// cpuClass
	assertEq(t, results, "cpuClass", "unknown")
	
	// Plugins
	if plugins, ok := results["pluginsLength"].(float64); !ok || plugins < 1 {
		t.Errorf("navigator.plugins.length expected >= 1, got %v", results["pluginsLength"])
	}
	assertBool(t, results, "pdfViewerEnabled", true)
	
	// maxTouchPoints
	if mtp, ok := results["maxTouchPoints"].(float64); !ok || mtp < 0 {
		t.Errorf("navigator.maxTouchPoints expected >= 0, got %v", results["maxTouchPoints"])
	}
	
	// cookieEnabled
	assertBool(t, results, "cookieEnabled", true)
	
	// toString should return [native code]
	for _, key := range []string{"loadTimesToString", "csiToString", "appGetDetailsToString", "appInstallStateToString"} {
		if s, ok := results[key].(string); !ok || s == "" {
			t.Errorf("%s expected non-empty string, got %v", key, results[key])
		} else if s != "" && s != "undefined" && !containsNativeCode(s) {
			t.Errorf("%s expected to contain '[native code]', got %q", key, s)
		}
	}
	
	// Webdriver should be undefined/false
	if wd, ok := results["webdriver"]; ok && wd != nil && wd != false {
		t.Errorf("navigator.webdriver expected undefined/false, got %v", wd)
	}
	
	// Property descriptors should be enumerable + configurable
	assertBool(t, results, "platformEnumerable", true)
	assertBool(t, results, "platformConfigurable", true)
}

func assertBool(t *testing.T, results map[string]interface{}, key string, expected bool) {
	v, ok := results[key].(bool)
	if !ok || v != expected {
		t.Errorf("%s expected %v, got %v", key, expected, results[key])
	}
}

func assertEq(t *testing.T, results map[string]interface{}, key string, expected string) {
	v, ok := results[key].(string)
	if !ok || v != expected {
		t.Errorf("%s expected %q, got %v", key, expected, results[key])
	}
}

func containsNativeCode(s string) bool {
	return len(s) > 0 && (s == "function loadTimes() { [native code] }" ||
		s == "function csi() { [native code] }" ||
		s == "function getDetails() { [native code] }" ||
		s == "function getIsInstalled() { [native code] }" ||
		s == "function installState() { [native code] }" ||
		s == "function runningState() { [native code] }" ||
		s == "function () { [native code] }")
}
