package detection

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
)

func (na *navigatorAnalyzer) checkWebdriver(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	// Check webdriver (naive boolean leak)
	if webdriver, ok := navData["webdriver"].(bool); ok && webdriver {
		indicators = append(indicators, "webdriver=true")
		vec.Score += 0.5
	}

	// Phase 10: Check stringification leak (Nodriver toString bypass failure)
	if wdStr, ok := navData["webdriverString"].(string); ok {
		if !strings.Contains(wdStr, "[native code]") {
			indicators = append(indicators, "inconsistent_webdriver_stringification")
			vec.Score += 0.6
		}
	} else {
		// If they patched the object but forgot the toString proxy
		indicators = append(indicators, "missing_webdriver_toString")
		vec.Score += 0.3
	}

	// Check property descriptor flags for webdriver.
	// In real Chrome, navigator.webdriver descriptor is:
	//   { get: [native], set: undefined, enumerable: true, configurable: true }
	// However, the getter's .name should be "get webdriver" and its toString
	// should return 'function get webdriver() { [native code] }'.
	// Stealth scripts that delete+redefine produce a getter with different
	// function body or name.
	if desc, ok := navData["webdriver_descriptor"].(map[string]interface{}); ok {
		// If configurable is explicitly false, it was patched then locked
		if configurable, ok := desc["configurable"].(bool); ok && !configurable {
			indicators = append(indicators, "webdriver_descriptor_locked")
			vec.Score += 0.25
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "webdriver_descriptor_locked",
				Fired:       true,
				Weight:      0.25,
				Score:       0.25,
				Field:       "webdriver descriptor.configurable",
				Actual:      "false",
				Expected:    "true (Chrome default)",
				Severity:    "medium",
				Description: "navigator.webdriver property descriptor has configurable=false, indicating post-patch lockdown.",
			})
		}
		// Check getter name — real Chrome getter is named "get webdriver"
		if getterName, ok := desc["getter_name"].(string); ok {
			if getterName != "get webdriver" && getterName != "" {
				indicators = append(indicators, "webdriver_getter_name_anomaly")
				vec.Score += 0.30
				vec.CheckReports = append(vec.CheckReports, CheckReport{
					Name:        "webdriver_getter_name_anomaly",
					Fired:       true,
					Weight:      0.30,
					Score:       0.30,
					Field:       "webdriver getter.name",
					Actual:      getterName,
					Expected:    "get webdriver",
					Severity:    "medium",
					Description: "navigator.webdriver getter function has unexpected name, indicating stealth redefinition.",
				})
			}
		}
	}

	return indicators
}

func (na *navigatorAnalyzer) checkChromeRuntime(navData map[string]interface{}, vec *DetectionVector, indicators []string, reqUA string) []string {
	isChromeNav := strings.Contains(strings.ToLower(reqUA), "chrome")
	if !isChromeNav {
		return indicators
	}

	if _, ok := navData["chrome"]; !ok {
		indicators = append(indicators, "missing_chrome_runtime")
		vec.Score += 0.2
	}

	// P11: chrome.app API shape
	if chromeApp, ok := navData["chrome_app"].(map[string]interface{}); ok {
		if _, hasInstalled := chromeApp["isInstalled"]; !hasInstalled {
			indicators = append(indicators, "chrome_app_missing_isInstalled")
			vec.Score += 0.15
		}
		if _, hasInstallState := chromeApp["InstallState"]; !hasInstallState {
			indicators = append(indicators, "chrome_app_missing_InstallState")
			vec.Score += 0.10
		}
		if _, hasRunningState := chromeApp["RunningState"]; !hasRunningState {
			indicators = append(indicators, "chrome_app_missing_RunningState")
			vec.Score += 0.10
		}
	} else {
		indicators = append(indicators, "missing_chrome_app")
		vec.Score += 0.25
	}

	// P11: chrome.csi
	if _, hasCsi := navData["chrome_csi"]; !hasCsi {
		indicators = append(indicators, "missing_chrome_csi")
		vec.Score += 0.15
	}

	// P11: performance.memory
	if perfMem, ok := navData["performance_memory"].(map[string]interface{}); ok {
		if _, hasLimit := perfMem["jsHeapSizeLimit"]; !hasLimit {
			indicators = append(indicators, "performance_memory_missing_limit")
			vec.Score += 0.10
		}
		if _, hasTotal := perfMem["totalJSHeapSize"]; !hasTotal {
			indicators = append(indicators, "performance_memory_missing_total")
			vec.Score += 0.10
		}
		used, _ := perfMem["usedJSHeapSize"].(float64)
		total, _ := perfMem["totalJSHeapSize"].(float64)
		limit, _ := perfMem["jsHeapSizeLimit"].(float64)
		if used > 0 && total > 0 && used > total {
			indicators = append(indicators, "performance_memory_used_exceeds_total")
			vec.Score += 0.20
		}
		if total > 0 && limit > 0 && total > limit {
			indicators = append(indicators, "performance_memory_total_exceeds_limit")
			vec.Score += 0.20
		}

		// Phase 83: Cross-check limit with deviceMemory
		deviceMem, okMem := navData["deviceMemory"].(float64)
		if okMem && deviceMem > 0 {
			// standard Chrome rule: jsHeapSizeLimit is ~0.5x RAM up to 4GB, then ~4GB.
			// 8GB -> 4.2GB, 4GB -> 2.1GB, 2GB -> 1.1GB
			expectedLimit := 4294705152.0
			if deviceMem <= 4 {
				expectedLimit = 2172641280.0
			}
			if deviceMem <= 2 {
				expectedLimit = 1073741824.0
			}

			// Allow a bit of leeway for browser patches/jitter
			if math.Abs(limit-expectedLimit) > 500*1024*1024 {
				name := "performance_memory_limit_mismatch"
				indicators = append(indicators, name)
				vec.Score += 0.35
				vec.CheckReports = append(vec.CheckReports, CheckReport{
					Name:        name,
					Fired:       true,
					Weight:      0.35,
					Score:       0.35,
					Field:       "performance.memory.jsHeapSizeLimit",
					Actual:      fmt.Sprintf("%.0f", limit),
					Expected:    fmt.Sprintf("%.0f (for %.0fGB RAM)", expectedLimit, deviceMem),
					Severity:    "high",
					Description: "Reported JS heap size limit does not match the expected value for the claimed device memory.",
				})
			}
		}
	} else {
		indicators = append(indicators, "missing_performance_memory")
		vec.Score += 0.15
	}

	// Phase 83: performance.navigation
	if perfNav, ok := navData["performance_navigation"].(map[string]interface{}); ok {
		if navType, ok := perfNav["type"].(float64); ok {
			// type 0 = TYPE_NAVIGATE (direct link, bookmark, etc).
			// type 1 = TYPE_RELOAD. type 2 = TYPE_BACK_FORWARD.
			// Most simple bots/scrapers should report 0 unless specifically testing reloads.
			if navType != 0 {
				name := "performance_navigation_type_mismatch"
				indicators = append(indicators, name)
				vec.Score += 0.25
				vec.CheckReports = append(vec.CheckReports, CheckReport{
					Name:        name,
					Fired:       true,
					Weight:      0.25,
					Score:       0.25,
					Field:       "performance.navigation.type",
					Actual:      fmt.Sprintf("%.0f", navType),
					Expected:    "0",
					Severity:    "medium",
					Description: "Performance.navigation.type is not TYPE_NAVIGATE (0), which is unexpected for an initial page load.",
				})
			}
		}
	}

	// Phase 24: chrome.loadTimes() temporal ordering
	if lt, ok := navData["chrome_loadTimes"].(map[string]interface{}); ok {
		requestT, _ := lt["requestTime"].(float64)
		startT, _ := lt["startLoadTime"].(float64)
		commitT, _ := lt["commitLoadTime"].(float64)
		firstPaintT, _ := lt["firstPaintTime"].(float64)
		finishDocT, _ := lt["finishDocumentLoadTime"].(float64)
		finishT, _ := lt["finishLoadTime"].(float64)

		if requestT > 0 && startT > 0 && commitT > 0 && firstPaintT > 0 && finishDocT > 0 && finishT > 0 {
			if !(requestT < startT && startT < commitT && commitT < firstPaintT &&
				firstPaintT < finishDocT && finishDocT < finishT) {
				indicators = append(indicators, "chrome_loadtimes_ordering_violation")
				vec.Score += 0.35
				vec.CheckReports = append(vec.CheckReports, CheckReport{
					Name:        "chrome_loadtimes_ordering",
					Fired:       true,
					Weight:      0.35,
					Score:       0.35,
					Field:       "chrome_loadTimes",
					Actual:      fmt.Sprintf("req=%.3f start=%.3f commit=%.3f paint=%.3f docEnd=%.3f load=%.3f", requestT, startT, commitT, firstPaintT, finishDocT, finishT),
					Expected:    "strictly increasing temporal order",
					Severity:    "high",
					Description: "chrome.loadTimes() fields are not in valid temporal order",
				})
			}
			totalLoadSec := finishT - requestT
			if totalLoadSec < 0.1 || totalLoadSec > 60 {
				indicators = append(indicators, fmt.Sprintf("chrome_loadtimes_implausible_duration: %.3fs", totalLoadSec))
				vec.Score += 0.25
			}
		}
	} else {
		indicators = append(indicators, "missing_chrome_loadTimes")
		vec.Score += 0.15
	}

	return indicators
}

func (na *navigatorAnalyzer) checkAutomationFlags(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	automationFlags := []string{"__webdriver_script_fn__", "__selenium_unwrapped", "callSelenium"}
	for _, flag := range automationFlags {
		if _, ok := navData[flag]; ok {
			indicators = append(indicators, fmt.Sprintf("automation_flag: %s", flag))
			vec.Score += 0.6
		}
	}
	return indicators
}

func (na *navigatorAnalyzer) checkMandatoryProperties(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if _, hasLangs := navData["languages"]; !hasLangs {
		indicators = append(indicators, "missing_navigator_languages")
		vec.Score += 0.5
	}
	if _, hasProductSub := navData["productSub"]; !hasProductSub {
		indicators = append(indicators, "missing_navigator_productSub")
		vec.Score += 0.3
	}
	if _, hasMaxTouch := navData["maxTouchPoints"]; !hasMaxTouch {
		indicators = append(indicators, "missing_navigator_maxTouchPoints")
		vec.Score += 0.2
	}
	return indicators
}

func (na *navigatorAnalyzer) checkAppVersion(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	ua, _ := navData["userAgent"].(string)
	if appVer, hasAppVer := navData["appVersion"].(string); !hasAppVer {
		indicators = append(indicators, "missing_navigator_appVersion")
		vec.Score += 0.45
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "missing_app_version",
			Fired:       true,
			Weight:      0.45,
			Score:       0.45,
			Field:       "appVersion",
			Actual:      "",
			Expected:    "UA minus 'Mozilla/' prefix",
			Severity:    "high",
			Description: "navigator.appVersion is missing (real browsers always populate it)",
		})
	} else if ua != "" && strings.HasPrefix(ua, "Mozilla/") {
		expectedAppVer := ua[len("Mozilla/"):]
		if appVer != expectedAppVer {
			indicators = append(indicators, "inconsistent_navigator_appVersion")
			vec.Score += 0.40
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "inconsistent_app_version",
				Fired:       true,
				Weight:      0.40,
				Score:       0.40,
				Field:       "appVersion",
				Actual:      appVer,
				Expected:    expectedAppVer,
				Severity:    "high",
				Description: "navigator.appVersion does not match UA minus 'Mozilla/' prefix",
			})
		}
	}
	return indicators
}

func (na *navigatorAnalyzer) checkAutomationLeaks(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	// Serialize back to string to search for leaks across all properties
	dataStr, _ := json.Marshal(navData)
	leaks := []string{
		" Evaluation.eval", // common in CDP evaluation
		"__puppeteer",
		"__playwright",
		"selenium",
		"chrome-extension://", // sometimes leaks in stacks
	}

	for _, leak := range leaks {
		if strings.Contains(string(dataStr), leak) {
			indicators = append(indicators, fmt.Sprintf("automation_leak_detected:%s", strings.TrimSpace(leak)))
			vec.Score += 0.5
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "automation_leak",
				Fired:       true,
				Weight:      0.5,
				Score:       0.5,
				Field:       "navigator_data",
				Actual:      leak,
				Expected:    "clean",
				Severity:    "critical",
				Description: fmt.Sprintf("Found automation-related string '%s' in navigator data.", leak),
			})
		}
	}
	return indicators
}

// checkRuntimeIntrospection (Phase 92)
func (na *navigatorAnalyzer) checkRuntimeIntrospection(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	// Proxy detection
	if proxied, ok := navData["navigator_proxied"].(bool); ok && proxied {
		name := "navigator_proxy_detected"
		indicators = append(indicators, name)
		vec.Score += 0.50
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        name,
			Fired:       true,
			Weight:      0.50,
			Score:       0.50,
			Field:       "navigator",
			Actual:      "Proxy object",
			Expected:    "Native object",
			Severity:    "high",
			Description: "Internal introspection suggests the Navigator object or its properties are Proxy-wrapped hooks.",
		})
	}

	// toString integrity
	if toStringLeaks, ok := navData["toString_integrity_leaks"].([]interface{}); ok && len(toStringLeaks) > 0 {
		name := "native_function_toString_leak"
		indicators = append(indicators, name)
		vec.Score += 0.40
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        name,
			Fired:       true,
			Weight:      0.40,
			Score:       0.40,
			Field:       "Function.prototype.toString",
			Actual:      "non-native",
			Expected:    "native",
			Severity:    "high",
			Description: "Introspection found polyfilled or shadowed native functions with non-standard toString() output.",
		})
	}
	return indicators
}
