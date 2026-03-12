package adversarial

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"

	"github.com/skunkworq/stealth/brws/constants"
)

// NavigatorAnalyzer handles detection of automation via navigator object properties.
type NavigatorAnalyzer struct{}

// NewNavigatorAnalyzer creates a new instance of NavigatorAnalyzer.
func NewNavigatorAnalyzer() *NavigatorAnalyzer {
	return &NavigatorAnalyzer{}
}

// Analyze performs deep analysis of navigator properties sent via custom headers.
func (na *NavigatorAnalyzer) Analyze(req *http.Request) *DetectionVector {
	navHeader := req.Header.Get(constants.HeaderNavigatorData)
	if navHeader == "" {
		return nil
	}

	vec := &DetectionVector{
		Name:        "Navigator Properties",
		Category:    "navigator",
		Weight:      0.2,
		Description: "Analyzes navigator object properties for automation detection",
	}

	var navData map[string]interface{}
	if err := json.Unmarshal([]byte(navHeader), &navData); err != nil {
		return nil
	}

	indicators := make([]string, 0)
	reqUA := req.Header.Get("User-Agent")

	indicators = na.checkWebdriver(navData, vec, indicators)
	indicators = na.checkChromeRuntime(navData, vec, indicators, reqUA)
	indicators = na.checkAudioLatency(req, vec, indicators)
	indicators = na.checkAudioBaseLatency(req, vec, indicators)
	indicators = na.checkAutomationFlags(navData, vec, indicators)
	indicators = na.checkMandatoryProperties(navData, vec, indicators)
	indicators = na.checkAppVersion(navData, vec, indicators)
	indicators = na.checkPDFViewer(navData, vec, indicators)
	indicators = na.checkHardwareCoherence(navData, vec, indicators)
	indicators = na.checkTimezone(navData, vec, indicators)

	// Auxiliary checks
	indicators = na.checkNetworkInformation(navData, vec, indicators)
	indicators = na.checkPluginsArray(navData, vec, indicators)
	indicators = na.checkScreenGeometry(navData, vec, indicators)
	indicators = na.checkScreenOrientation(navData, vec, indicators)
	indicators = na.checkVideoElement(navData, vec, indicators)
	indicators = na.checkPermissionsAPI(navData, vec, indicators)
	indicators = na.checkTimezoneParity(navData, vec, indicators)
	indicators = na.checkKeyboardAPI(navData, vec, indicators, reqUA)
	indicators = na.checkVendor(navData, vec, indicators, reqUA)
	indicators = na.checkNetworkCoherence(navData, vec, indicators)
	indicators = na.checkNotificationPermission(navData, vec, indicators)
	indicators = na.checkMediaQueryHover(navData, vec, indicators, reqUA)
	indicators = na.checkWebGPUSupport(navData, vec, indicators, reqUA)
	indicators = na.checkPermissionsExtended(navData, vec, indicators)
	indicators = na.checkBatteryStatus(navData, vec, indicators)
	indicators = na.checkStorageQuota(navData, vec, indicators)
	indicators = na.checkStorageQuotaCoherence(navData, vec, indicators)
	indicators = na.checkStoragePersistence(navData, vec, indicators)
	indicators = na.checkMediaDevices(navData, vec, indicators)
	indicators = na.checkWebRTC(navData, vec, indicators, reqUA)
	indicators = na.checkUserAgentData(navData, vec, indicators, req)
	indicators = na.checkMaxTouchPointsConsistency(navData, vec, indicators, reqUA)
	indicators = na.checkUserActivation(navData, vec, indicators, reqUA)
	indicators = na.checkSchedulingAPI(navData, vec, indicators, reqUA)
	indicators = na.checkLocksAPI(navData, vec, indicators, reqUA)
	indicators = na.checkIntlConsistency(navData, vec, indicators)
	indicators = na.checkMemoryPlausibility(navData, vec, indicators)
	indicators = na.checkAutomationLeaks(navData, vec, indicators)
	indicators = na.checkAudioWorklet(navData, vec, indicators, reqUA)
	indicators = na.checkNavigatorVibrate(navData, vec, indicators)
	indicators = na.checkNavigatorConnectivity(navData, vec, indicators)
	indicators = na.checkNavigatorHardwareAPIs(navData, vec, indicators)
	indicators = na.checkNavigatorModernAPIs(navData, vec, indicators)
	indicators = na.checkNavigatorMediaAPIs(navData, vec, indicators)
	indicators = na.checkNavigatorWorkers(navData, vec, indicators)
	indicators = na.checkGamepadAPI(navData, vec, indicators)
	indicators = na.checkNavigatorPrototype(navData, vec, indicators)
	indicators = na.checkWorkerContextCoherence(navData, vec, indicators)
	indicators = na.checkRuntimeIntrospection(navData, vec, indicators)
	indicators = na.checkCanvasMeasureText(navData, vec, indicators)
	indicators = na.checkMathPrecision(navData, vec, indicators)

	vec.Indicators = indicators
	vec.Detected = len(indicators) > 0
	return vec
}

func (na *NavigatorAnalyzer) checkWebdriver(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
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
	return indicators
}

func (na *NavigatorAnalyzer) checkChromeRuntime(navData map[string]interface{}, vec *DetectionVector, indicators []string, reqUA string) []string {
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

func (na *NavigatorAnalyzer) checkAudioLatency(req *http.Request, vec *DetectionVector, indicators []string) []string {
	if audioHeader := req.Header.Get(constants.HeaderAudioData); audioHeader != "" {
		var audioData map[string]interface{}
		if err := json.Unmarshal([]byte(audioHeader), &audioData); err == nil {
			if outputLatency, hasOL := audioData["output_latency"].(float64); hasOL {
				if outputLatency == 0.0 {
					indicators = append(indicators, "audio_zero_output_latency")
					vec.Score += 0.20
					vec.CheckReports = append(vec.CheckReports, CheckReport{
						Name:        "audio_zero_output_latency",
						Fired:       true,
						Weight:      0.20,
						Score:       0.20,
						Field:       "output_latency",
						Actual:      "0.0",
						Expected:    "0.005-0.05 (real hardware latency)",
						Severity:    "medium",
						Description: "AudioContext.outputLatency=0 indicates no real audio hardware connection",
					})
				}
			}
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkAutomationFlags(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	automationFlags := []string{"__webdriver_script_fn__", "__selenium_unwrapped", "callSelenium"}
	for _, flag := range automationFlags {
		if _, ok := navData[flag]; ok {
			indicators = append(indicators, fmt.Sprintf("automation_flag: %s", flag))
			vec.Score += 0.6
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkMandatoryProperties(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
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

func (na *NavigatorAnalyzer) checkAppVersion(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
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

func (na *NavigatorAnalyzer) checkPDFViewer(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if pdfViewer, hasPdfViewer := navData["pdfViewerEnabled"]; hasPdfViewer {
		pdfBool, isBool := pdfViewer.(bool)
		if isBool && !pdfBool {
			indicators = append(indicators, "pdfViewerEnabled_false_modern_browser")
			vec.Score += 0.25
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "pdf_viewer_disabled",
				Fired:       true,
				Weight:      0.25,
				Score:       0.25,
				Field:       "pdfViewerEnabled",
				Actual:      "false",
				Expected:    "true (all modern browsers)",
				Severity:    "medium",
				Description: "navigator.pdfViewerEnabled=false is inconsistent with modern Chrome/Firefox UAs",
			})
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkHardwareCoherence(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if devMem, hasMem := navData["deviceMemory"].(float64); hasMem {
		if conc, hasConc := navData["hardwareConcurrency"].(float64); hasConc {
			memGB := int(devMem)
			cores := int(conc)
			if memGB >= 32 && cores <= 4 {
				indicators = append(indicators, fmt.Sprintf("hardware_coherence_improbable: %dGB_RAM_%d_cores", memGB, cores))
				vec.Score += 0.20
				vec.CheckReports = append(vec.CheckReports, CheckReport{
					Name:        "hardware_coherence_high_ram_low_cores",
					Fired:       true,
					Weight:      0.20,
					Score:       0.20,
					Field:       "deviceMemory+hardwareConcurrency",
					Actual:      fmt.Sprintf("%dGB/%dcores", memGB, cores),
					Expected:    "correlated RAM/core counts",
					Severity:    "medium",
					Description: "High RAM with very low core count is statistically improbable",
				})
			}
			if memGB <= 4 && cores >= 16 {
				indicators = append(indicators, fmt.Sprintf("hardware_coherence_improbable: %dGB_RAM_%d_cores", memGB, cores))
				vec.Score += 0.20
				vec.CheckReports = append(vec.CheckReports, CheckReport{
					Name:        "hardware_coherence_low_ram_high_cores",
					Fired:       true,
					Weight:      0.20,
					Score:       0.20,
					Field:       "deviceMemory+hardwareConcurrency",
					Actual:      fmt.Sprintf("%dGB/%dcores", memGB, cores),
					Expected:    "correlated RAM/core counts",
					Severity:    "medium",
					Description: "Low RAM with very high core count is statistically improbable",
				})
			}
			if cores > 1 && int(cores)%2 != 0 {
				indicators = append(indicators, fmt.Sprintf("improbable_hardware_concurrency: %d cores", int(cores)))
				vec.Score += 0.25
				vec.CheckReports = append(vec.CheckReports, CheckReport{
					Name:        "improbable_hardware_concurrency",
					Fired:       true,
					Weight:      0.25,
					Score:       0.25,
					Field:       "hardwareConcurrency",
					Actual:      fmt.Sprintf("%d", int(cores)),
					Expected:    "even core count",
					Severity:    "medium",
					Description: "Odd core count detected. Real hardware typically follows even power-of-two or common multi-core patterns.",
				})
			}
		}

		if devMem > 8.0 {
			indicators = append(indicators, fmt.Sprintf("improbable_device_memory: %.1f (expected <= 8)", devMem))
			vec.Score += 0.35
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "improbable_device_memory",
				Fired:       true,
				Weight:      0.35,
				Score:       0.35,
				Field:       "deviceMemory",
				Actual:      fmt.Sprintf("%.1f", devMem),
				Expected:    "<= 8",
				Severity:    "high",
				Description: "Reported deviceMemory > 8. Browsers intentionally cap this API to 8 to prevent high-entropy hardware fingerprinting.",
			})
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkKeyboardAPI(navData map[string]interface{}, vec *DetectionVector, indicators []string, reqUA string) []string {
	if strings.Contains(strings.ToLower(reqUA), "chrome") {
		if _, hasKeyboard := navData["keyboard"]; !hasKeyboard {
			indicators = append(indicators, "missing_navigator_keyboard")
			vec.Score += 0.25
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "missing_navigator_keyboard",
				Fired:       true,
				Weight:      0.25,
				Score:       0.25,
				Field:       "navigator.keyboard",
				Actual:      "absent",
				Expected:    "present (for Chrome)",
				Severity:    "medium",
				Description: "navigator.keyboard is missing. Modern Chromium browsers always include this object.",
			})
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkVendor(navData map[string]interface{}, vec *DetectionVector, indicators []string, reqUA string) []string {
	if vendor, hasVendor := navData["vendor"].(string); hasVendor {
		uaLower := strings.ToLower(reqUA)
		if strings.Contains(uaLower, "chrome") && vendor != "Google Inc." {
			indicators = append(indicators, fmt.Sprintf("vendor_browser_mismatch: chrome_ua_vendor=%q", vendor))
			vec.Score += 0.30
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "vendor_browser_mismatch",
				Fired:       true,
				Weight:      0.30,
				Score:       0.30,
				Field:       "vendor",
				Actual:      vendor,
				Expected:    "Google Inc. (for Chrome UA)",
				Severity:    "high",
				Description: "navigator.vendor does not match the browser type in UA",
			})
		} else if strings.Contains(uaLower, "firefox") && vendor != "" {
			indicators = append(indicators, fmt.Sprintf("vendor_browser_mismatch: firefox_ua_vendor=%q", vendor))
			vec.Score += 0.30
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "vendor_browser_mismatch",
				Fired:       true,
				Weight:      0.30,
				Score:       0.30,
				Field:       "vendor",
				Actual:      vendor,
				Expected:    "empty string (for Firefox UA)",
				Severity:    "high",
				Description: "navigator.vendor does not match the browser type in UA",
			})
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkNetworkCoherence(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if conn, ok := navData["connection"].(map[string]interface{}); ok {
		effType, _ := conn["effectiveType"].(string)
		rtt, hasRTT := conn["rtt"].(float64)
		downlink, hasDown := conn["downlink"].(float64)

		if effType == "4g" && hasRTT && rtt > 200 {
			name := "network_effectivetype_rtt_mismatch"
			indicators = append(indicators, name)
			vec.Score += 0.20
		}
		
		if hasDown && downlink > 10.0 && (effType == "2g" || effType == "3g") {
			name := "network_high_downlink_low_efftype"
			indicators = append(indicators, fmt.Sprintf("%s: %s_downlink=%.1fMbps", name, effType, downlink))
			vec.Score += 0.25
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        name,
				Fired:       true,
				Weight:      0.25,
				Score:       0.25,
				Field:       "connection.downlink + connection.effectiveType",
				Actual:      fmt.Sprintf("%s downlink on %s", fmt.Sprintf("%.1fMbps", downlink), effType),
				Expected:    "Low downlink for 2g/3g",
				Severity:    "medium",
				Description: "Reported downlink is too high for the effective connection type.",
			})
		}

		// Phase 87: SaveData vs Platform
		saveData, hasSaveData := conn["saveData"].(bool)
		isDesktop := !strings.Contains(strings.ToLower(effType), "mobile")
		if hasSaveData && saveData && isDesktop && !strings.Contains(strings.ToLower(fmt.Sprint(navData["platform"])), "linux") {
			name := "suspicious_desktop_savedata"
			indicators = append(indicators, name)
			vec.Score += 0.15
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        name,
				Fired:       true,
				Weight:      0.15,
				Score:       0.15,
				Field:       "connection.saveData",
				Actual:      "true",
				Expected:    "false (on desktop)",
				Severity:    "low",
				Description: "SaveData is enabled on a desktop profile, which is suspicious.",
			})
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkNotificationPermission(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if _, hasNotif := navData["Notification_permission"]; !hasNotif {
		indicators = append(indicators, "missing_notification_permission")
		vec.Score += 0.15
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "missing_notification_permission",
			Fired:       true,
			Weight:      0.15,
			Score:       0.15,
			Field:       "Notification_permission",
			Actual:      "absent",
			Expected:    "'default', 'granted', or 'denied'",
			Severity:    "medium",
			Description: "Notification.permission missing — real browsers always expose this Web API",
		})
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkTimezone(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if _, hasTZ := navData["timezone"]; !hasTZ {
		indicators = append(indicators, "missing_timezone")
		vec.Score += 0.15
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkNetworkInformation(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	var rtt float64
	var hasRTT bool

	if conn, ok := navData["connection"].(map[string]interface{}); ok {
		rtt, hasRTT = conn["rtt"].(float64)
		downlink, _ := conn["downlink"].(float64)

		if rtt == 50 && downlink == 10 {
			indicators = append(indicators, "spoofed_network_api_detected")
			vec.Score += 0.4
		}

		if _, hasEffType := conn["effectiveType"].(string); !hasEffType {
			indicators = append(indicators, "missing_connection_effectiveType")
			vec.Score += 0.30
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "missing_connection_effective_type",
				Fired:       true,
				Weight:      0.30,
				Score:       0.30,
				Field:       "effectiveType",
				Actual:      "",
				Expected:    "4g",
				Severity:    "medium",
				Description: "navigator.connection.effectiveType is missing (Chrome always includes it)",
			})
		}

		ua, _ := navData["userAgent"].(string)
		isChrome := strings.Contains(strings.ToLower(ua), "chrome")
		if isChrome {
			if _, hasSaveData := conn["saveData"].(bool); !hasSaveData {
				indicators = append(indicators, "missing_connection_saveData")
				vec.Score += 0.30
				vec.CheckReports = append(vec.CheckReports, CheckReport{
					Name:        "missing_connection_saveData",
					Fired:       true,
					Weight:      0.30,
					Score:       0.30,
					Field:       "saveData",
					Actual:      "",
					Expected:    "true/false",
					Severity:    "medium",
					Description: "navigator.connection.saveData is missing. Chromium-based browsers always include this property.",
				})
			}
		}
	} else if r, ok := navData["connection_rtt"].(float64); ok {
		rtt = r
		hasRTT = true
		downlink, _ := navData["connection_downlink"].(float64)
		if rtt == 50 && downlink == 10 {
			indicators = append(indicators, "spoofed_network_api_detected")
			vec.Score += 0.4
		}
	}

	if hasRTT && rtt > 0 && int(rtt)%25 != 0 {
		indicators = append(indicators, fmt.Sprintf("non_quantized_rtt: %.0fms (not multiple of 25)", rtt))
		vec.Score += 0.3
	}

	if hasRTT {
		downlink := 0.0
		hasDownlink := false
		if conn, ok := navData["connection"].(map[string]interface{}); ok {
			downlink, hasDownlink = conn["downlink"].(float64)
		} else if dl, ok := navData["connection_downlink"].(float64); ok {
			downlink = dl
			hasDownlink = true
		}
		if hasDownlink {
			if rtt <= 50 && downlink < 3.0 {
				indicators = append(indicators, fmt.Sprintf("rtt_downlink_anticorrelated: rtt=%.0f downlink=%.1f (low RTT should have high downlink)", rtt, downlink))
				vec.Score += 0.35
			}
			if rtt >= 150 && downlink > 8.0 {
				indicators = append(indicators, fmt.Sprintf("rtt_downlink_anticorrelated: rtt=%.0f downlink=%.1f (high RTT should have low downlink)", rtt, downlink))
				vec.Score += 0.35
			}
		}
	}

	return indicators
}

func (na *NavigatorAnalyzer) checkPluginsArray(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if plugins, ok := navData["plugins"].([]interface{}); ok {
		if len(plugins) == 5 {
			isIntArray := true
			for _, p := range plugins {
				if _, isNum := p.(float64); !isNum {
					isIntArray = false
					break
				}
			}
			if isIntArray {
				indicators = append(indicators, "spoofed_plugins_array_detected")
				vec.Score += 0.5
			}
		}
	} else if length, ok := navData["plugins_length"].(float64); ok {
		if length == 5 && navData["plugins_is_array"] == true {
			indicators = append(indicators, "spoofed_plugins_array_detected")
			vec.Score += 0.5
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkScreenGeometry(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	var colorDepth, innerWidth, outerWidth float64
	if screen, ok := navData["screen"].(map[string]interface{}); ok {
		colorDepth, _ = screen["colorDepth"].(float64)
		innerWidth, _ = navData["innerWidth"].(float64)
		outerWidth, _ = navData["outerWidth"].(float64)
	} else if cd, ok := navData["screen_color_depth"].(float64); ok {
		colorDepth = cd
		innerWidth, _ = navData["screen_inner_width"].(float64)
		outerWidth, _ = navData["screen_outer_width"].(float64)
	}

	if colorDepth == 24 {
		if innerWidth > 0 && outerWidth > 0 && innerWidth == outerWidth {
			indicators = append(indicators, "impossible_window_geometry_detected")
			vec.Score += 0.4
		}
	}

	return indicators
}

func (na *NavigatorAnalyzer) checkVideoElement(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if video, ok := navData["video_can_play_mp4"].(string); ok {
		if video == "probably" {
			indicators = append(indicators, "spoofed_video_element_detected")
			vec.Score += 0.3
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkTimezoneParity(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if tz, ok := navData["timezone"].(string); ok {
		if offset, ok := navData["timezone_offset"].(float64); ok {
			if tz == "America/New_York" && offset != 300 {
				indicators = append(indicators, "timezone_offset_mismatch")
				vec.Score += 0.4
			}
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkPermissionsAPI(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if perm, ok := navData["notifications_prompt"].(string); ok {
		if perm == "default" && navData["permissions_is_proxy"] == true {
			indicators = append(indicators, "spoofed_permissions_api_detected")
			vec.Score += 0.6
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkMediaQueryHover(navData map[string]interface{}, vec *DetectionVector, indicators []string, reqUA string) []string {
	// Desktop browsers (Chrome, Firefox, Safari) in real environments always support hover.
	// Headless Chrome (even with --headless=new) sometimes defaults to (hover: none).
	uaLower := strings.ToLower(reqUA)
	isDesktop := (strings.Contains(uaLower, "macintosh") || strings.Contains(uaLower, "windows") || strings.Contains(uaLower, "linux")) &&
		!strings.Contains(uaLower, "android") && !strings.Contains(uaLower, "iphone") && !strings.Contains(uaLower, "ipad")

	if isDesktop {
		if hover, ok := navData["media_query_hover"].(string); ok {
			if hover == "none" {
				indicators = append(indicators, "none_media_query_hover")
				vec.Score += 0.40
				vec.CheckReports = append(vec.CheckReports, CheckReport{
					Name:        "media_query_hover_none",
					Fired:       true,
					Weight:      0.40,
					Score:       0.40,
					Field:       "media_query_hover",
					Actual:      "none",
					Expected:    "hover",
					Severity:    "high",
					Description: "Desktop User-Agent reports (hover: none) media query, indicating a headless/virtual environment.",
				})
			}
		} else {
			// Missing property is also suspicious for desktop UAs
			indicators = append(indicators, "missing_media_query_hover")
			vec.Score += 0.15
		}
	}
	return indicators
}
func (na *NavigatorAnalyzer) checkWebGPUSupport(navData map[string]interface{}, vec *DetectionVector, indicators []string, reqUA string) []string {
	isModernChrome := strings.Contains(strings.ToLower(reqUA), "chrome")
	// WebGPU (navigator.gpu) was added in Chrome 113.
	if isModernChrome {
		if gpu, hasGPU := navData["gpu_present"].(bool); hasGPU {
			if !gpu {
				indicators = append(indicators, "missing_webgpu")
				vec.Score += 0.35
				vec.CheckReports = append(vec.CheckReports, CheckReport{
					Name:        "missing_webgpu",
					Fired:       true,
					Weight:      0.35,
					Score:       0.35,
					Field:       "navigator.gpu",
					Actual:      "absent",
					Expected:    "present",
					Severity:    "medium",
					Description: "Modern Chrome browsers (113+) should expose the WebGPU API.",
				})
			}
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkPermissionsExtended(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	// 1. Notification vs Query state
	notifPerm, hasNotifPerm := navData["Notification_permission"].(string)
	permState, hasPermState := navData["permissions_notifications_state"].(string)

	if hasNotifPerm && hasPermState {
		if notifPerm != permState {
			indicators = append(indicators, "permissions_query_mismatch")
			vec.Score += 0.45
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "permissions_query_mismatch",
				Fired:       true,
				Weight:      0.45,
				Score:       0.45,
				Field:       "Notification.permission vs permissions.query",
				Actual:      fmt.Sprintf("notif=%s query=%s", notifPerm, permState),
				Expected:    "matching states",
				Severity:    "high",
				Description: "The Notification permission state is inconsistent with the Permissions API query result.",
			})
		}
	}

	// 2. Headless/Bot Metadata Leak
	if isProxy, ok := navData["permissions_is_proxy"].(bool); ok && isProxy {
		indicators = append(indicators, "permissions_metadata_leak")
		vec.Score += 0.8
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "permissions_metadata_leak",
			Fired:       true,
			Weight:      0.8,
			Score:       0.8,
			Field:       "permissions.query result",
			Actual:      "isProxy=true",
			Expected:    "no proxy indicators",
			Severity:    "critical",
			Description: "Permissions status object contains unexpected 'isProxy' property, indicating a shallow evasion script.",
		})
	}

	// 3. Multi-permission consistency (e.g., camera/mic)
	camState, hasCam := navData["permissions_camera_state"].(string)
	micState, hasMic := navData["permissions_microphone_state"].(string)
	
	devices, hasDevices := navData["media_devices"].([]interface{})
	if (hasCam && camState == "granted") || (hasMic && micState == "granted") {
		// If granted, we should have labeled devices
		hasLabels := false
		if hasDevices {
			for _, d := range devices {
				if dm, ok := d.(map[string]interface{}); ok {
					if label, ok := dm["label"].(string); ok && label != "" {
						hasLabels = true
						break
					}
				}
			}
		}
		if !hasLabels {
			indicators = append(indicators, "permissions_media_mismatch")
			vec.Score += 0.5
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "permissions_media_mismatch",
				Fired:       true,
				Weight:      0.5,
				Score:       0.5,
				Field:       "mediaDevice labels",
				Actual:      "no labels with granted permission",
				Expected:    "labels present when granted",
				Severity:    "high",
				Description: "Media device labels are missing despite camera/microphone permissions being granted, indicating spoofed permissions.",
			})
		}
	}

	// 4. Geolocation vs Timezone/IP (Simplified check for now)
	geoState, hasGeo := navData["permissions_geolocation_state"].(string)
	if hasGeo && geoState == "granted" {
		// In automated environments, granting geolocation without actual location providers usually looks fake
		// unless we see specific lat/long data (handled in a separate analyzer usually)
	}

	return indicators
}

func (na *NavigatorAnalyzer) checkAudioBaseLatency(req *http.Request, vec *DetectionVector, indicators []string) []string {
	if audioHeader := req.Header.Get(constants.HeaderAudioData); audioHeader != "" {
		var audioData map[string]interface{}
		if err := json.Unmarshal([]byte(audioHeader), &audioData); err == nil {
			if baseLatency, hasBL := audioData["base_latency"].(float64); hasBL {
				if baseLatency == 0.0 {
					indicators = append(indicators, "audio_zero_base_latency")
					vec.Score += 0.20
					vec.CheckReports = append(vec.CheckReports, CheckReport{
						Name:        "audio_zero_base_latency",
						Fired:       true,
						Weight:      0.20,
						Score:       0.20,
						Field:       "base_latency",
						Actual:      "0.0",
						Expected:    "0.002-0.005",
						Severity:    "medium",
						Description: "AudioContext.baseLatency=0 is suspicious and common in headless environments.",
					})
				}
			} else {
				// Base latency is missing, which is also suspicious for modern browsers
				indicators = append(indicators, "missing_audio_base_latency")
				vec.Score += 0.15
			}
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkScreenOrientation(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	orientation, hasOrientation := navData["screen_orientation"].(string)
	if !hasOrientation {
		return indicators
	}

	innerWidth, _ := navData["screen_inner_width"].(float64)
	innerHeight, _ := navData["screen_inner_height"].(float64)

	if innerWidth > 0 && innerHeight > 0 {
		isLandscape := innerWidth > innerHeight
		isPortrait := innerHeight > innerWidth

		if isLandscape && strings.Contains(orientation, "portrait") {
			indicators = append(indicators, "screen_orientation_mismatch")
			vec.Score += 0.35
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "screen_orientation_mismatch",
				Fired:       true,
				Weight:      0.35,
				Score:       0.35,
				Field:       "screen_orientation vs aspect ratio",
				Actual:      fmt.Sprintf("orientation=%s dims=%.0fx%.0f", orientation, innerWidth, innerHeight),
				Expected:    "landscape-primary or landscape-secondary",
				Severity:    "medium",
				Description: "Screen orientation type does not match the window aspect ratio (landscape).",
			})
		} else if isPortrait && strings.Contains(orientation, "landscape") {
			indicators = append(indicators, "screen_orientation_mismatch")
			vec.Score += 0.35
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "screen_orientation_mismatch",
				Fired:       true,
				Weight:      0.35,
				Score:       0.35,
				Field:       "screen_orientation vs aspect ratio",
				Actual:      fmt.Sprintf("orientation=%s dims=%.0fx%.0f", orientation, innerWidth, innerHeight),
				Expected:    "portrait-primary or portrait-secondary",
				Severity:    "medium",
				Description: "Screen orientation type does not match the window aspect ratio (portrait).",
			})
		}
	}

	return indicators
}

func (na *NavigatorAnalyzer) checkBatteryStatus(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	battery, hasBattery := navData["battery_status"].(map[string]interface{})
	if !hasBattery {
		return indicators
	}

	level, _ := battery["level"].(float64)
	charging, _ := battery["charging"].(bool)
	chargingTime, _ := battery["chargingTime"].(float64)
	dischargingTime, _ := battery["dischargingTime"].(float64)

	// Suspicious static state: 100% level, charging, 0 charging time, infinity discharging
	// This is the default state for many headless/emulated battery mocks.
	if level == 1.0 && charging && chargingTime == 0 && dischargingTime > 1e10 {
		indicators = append(indicators, "suspicious_battery_status")
		vec.Score += 0.30
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "suspicious_battery_status",
			Fired:       true,
			Weight:      0.30,
			Score:       0.30,
			Field:       "navigator.getBattery()",
			Actual:      fmt.Sprintf("level=%.1f charging=%v cTime=%.0f dTime=%.0f", level, charging, chargingTime, dischargingTime),
			Expected:    "variable battery state",
			Severity:    "medium",
			Description: "Static 100% charging battery state is a common headless bot signature.",
		})
	}

	return indicators
}

func (na *NavigatorAnalyzer) checkStorageQuota(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	quota, hasQuota := navData["storage_quota"].(float64)
	usage, hasUsage := navData["storage_usage"].(float64)

	if !hasQuota {
		indicators = append(indicators, "missing_storage_quota")
		vec.Score += 0.20
		return indicators
	}

	// 1. Quota Plausibility
	// Web browsers usually have a significant quota (GBs).
	// Zero or very low quota (e.g. < 1MB) is suspicious for desktop.
	if quota <= 1024*1024 {
		name := "low_storage_quota"
		indicators = append(indicators, name)
		vec.Score += 0.25
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        name,
			Fired:       true,
			Weight:      0.25,
			Score:       0.25,
			Field:       "navigator.storage.estimate().quota",
			Actual:      fmt.Sprintf("%.0f bytes", quota),
			Expected:    "> 1MB",
			Severity:    "medium",
			Description: "Storage quota is zero or suspiciously low, indicating restricted environment.",
		})
	}

	// 2. Usage Check
	if !hasUsage {
		indicators = append(indicators, "missing_storage_usage")
		vec.Score += 0.15
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "missing_storage_usage",
			Fired:       true,
			Weight:      0.15,
			Score:       0.15,
			Field:       "navigator.storage.estimate().usage",
			Actual:      "absent",
			Expected:    "present",
			Severity:    "low",
			Description: "Storage usage metric is missing from the estimate reports.",
		})
	} else if usage == 0 {
		// Soft indicator: fresh profiles are often bots
		indicators = append(indicators, "zero_storage_usage")
		vec.Score += 0.10
	}

	return indicators
}

func (na *NavigatorAnalyzer) checkStoragePersistence(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	persisted, hasPersisted := navData["storage_persisted"].(bool)
	if !hasPersisted {
		indicators = append(indicators, "missing_storage_persistence")
		vec.Score += 0.15
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "missing_storage_persistence",
			Fired:       true,
			Weight:      0.15,
			Score:       0.15,
			Field:       "navigator.storage.persisted()",
			Actual:      "absent",
			Expected:    "present",
			Severity:    "low",
			Description: "Storage persistence API response is missing.",
		})
	}
	_ = persisted // currently only checking presence
	return indicators
}
func (na *NavigatorAnalyzer) checkStorageQuotaCoherence(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	quota, hasQuota := navData["storage_quota"].(float64)
	deviceMem, hasMem := navData["deviceMemory"].(float64)

	if hasQuota && hasMem && deviceMem > 0 {
		// Phase 88: Quota vs RAM
		// On modern Chrome, quota is typically ~10% of disk, but linked to deviceMemory bucket.
		// 8GB RAM usually implies a machine with at least 128GB disk -> ~12GB+ quota.
		// If quota is very low (e.g. < 5GB) for high RAM (>= 8GB), it's suspicious.
		if deviceMem >= 8 && quota < 5.0*1024*1024*1024 {
			name := "storage_quota_memory_mismatch"
			indicators = append(indicators, name)
			vec.Score += 0.30
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        name,
				Fired:       true,
				Weight:      0.30,
				Score:       0.30,
				Field:       "navigator.storage.estimate().quota",
				Actual:      fmt.Sprintf("%.1f GB", quota/(1024*1024*1024)),
				Expected:    "> 5 GB (for 8GB+ RAM)",
				Severity:    "medium",
				Description: "Storage quota is unexpectedly low given the reported device memory.",
			})
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkMediaDevices(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	devices, _ := navData["media_devices"].([]interface{})
	
	if len(devices) == 0 {
		indicators = append(indicators, "empty_media_devices")
		vec.Score += 0.25
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "empty_media_devices",
			Fired:       true,
			Weight:      0.25,
			Score:       0.25,
			Field:       "navigator.mediaDevices.enumerateDevices()",
			Actual:      "0 devices",
			Expected:    "> 0 devices (mic/camera/speakers)",
			Severity:    "medium",
			Description: "Empty media devices list is highly suspicious for a real user device.",
		})
		return indicators
	}

	for _, d := range devices {
		device, ok := d.(map[string]interface{})
		if !ok {
			continue
		}

		deviceId, _ := device["deviceId"].(string)
		groupId, _ := device["groupId"].(string)
		kind, _ := device["kind"].(string)

		// deviceId is empty if permissions are not granted (prompt state)
		// but groupId is usually still present as a session-persistent identifier.
		if groupId == "" {
			indicators = append(indicators, "suspicious_media_device_id")
			vec.Score += 0.15
		}

		// Real browser deviceIds are usually 64-character hex strings (hashes)
		// but "default" is also used for the primary device.
		if len(deviceId) > 0 && deviceId != "default" && len(deviceId) != 64 {
			indicators = append(indicators, "non_standard_media_device_id_format")
			vec.Score += 0.10
		}

		if kind == "" {
			indicators = append(indicators, "missing_media_device_kind")
			vec.Score += 0.10
		}
	}

	return indicators
}

func (na *NavigatorAnalyzer) checkWebRTC(navData map[string]interface{}, vec *DetectionVector, indicators []string, reqUA string) []string {
	webrtc, ok := navData["webrtc_data"].(map[string]interface{})
	if !ok {
		// Chrome browsers (desktop) should always have WebRTC available.
		if strings.Contains(reqUA, "Chrome") && !strings.Contains(reqUA, "Mobile") {
			indicators = append(indicators, "missing_webrtc")
			vec.Score += 0.20
		}
		return indicators
	}

	iceCandidates, _ := webrtc["ice_candidates"].([]interface{})
	if len(iceCandidates) == 0 {
		indicators = append(indicators, "empty_ice_candidates")
		vec.Score += 0.25
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "empty_ice_candidates",
			Fired:       true,
			Weight:      0.25,
			Score:       0.25,
			Field:       "RTCPeerConnection.onicecandidate",
			Actual:      "0 candidates",
			Expected:    "> 0 candidates (local/mDNS)",
			Severity:    "medium",
			Description: "Empty ICE candidates list is suspicious for a real browser environment.",
		})
	} else {
		// Check for suspicious candidate formats
		for _, c := range iceCandidates {
			cand, ok := c.(string)
			if !ok {
				continue
			}
			// Basic heuristic: ICE candidates usually have 'candidate:' prefix
			if !strings.HasPrefix(cand, "candidate:") {
				indicators = append(indicators, "suspicious_ice_format")
				vec.Score += 0.15
			}
		}
	}

	return indicators
}

func (na *NavigatorAnalyzer) checkUserAgentData(navData map[string]interface{}, vec *DetectionVector, indicators []string, req *http.Request) []string {
	uaData, hasUAData := navData["userAgentData"].(map[string]interface{})
	isChrome := strings.Contains(strings.ToLower(req.Header.Get("User-Agent")), "chrome")

	if isChrome && !hasUAData {
		indicators = append(indicators, "missing_navigator_userAgentData")
		vec.Score += 0.35
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "missing_navigator_userAgentData",
			Fired:       true,
			Weight:      0.35,
			Score:       0.35,
			Field:       "navigator.userAgentData",
			Actual:      "absent",
			Expected:    "present (for Chrome)",
			Severity:    "high",
			Description: "Modern Chromium browsers always expose navigator.userAgentData for Client Hints parity.",
		})
	}

	if hasUAData {
		// Cross-check platform with Sec-CH-UA-Platform header if present
		if platform, ok := uaData["platform"].(string); ok {
			chPlatform := req.Header.Get("Sec-CH-UA-Platform")
			if chPlatform != "" {
				trimmedCH := strings.Trim(chPlatform, "\"")
				if !strings.EqualFold(platform, trimmedCH) {
					indicators = na.addindicator(vec, indicators, "inconsistent_userAgentData_platform", 0.40, "userAgentData.platform", platform, trimmedCH, "high", "Navigator userAgentData.platform does not match Sec-CH-UA-Platform header.")
				}
			}
		}

		// Phase 96: check architecture
		if arch, ok := uaData["architecture"].(string); ok {
			chArch := req.Header.Get("Sec-CH-UA-Arch")
			if chArch != "" {
				trimmedCH := strings.Trim(chArch, "\"")
				if !strings.EqualFold(arch, trimmedCH) {
					indicators = na.addindicator(vec, indicators, "inconsistent_userAgentData_arch", 0.30, "userAgentData.architecture", arch, trimmedCH, "medium", "Navigator userAgentData.architecture does not match Sec-CH-UA-Arch header.")
				}
			}
		}

		// Phase 96: check bitness
		if bitness, ok := uaData["bitness"].(string); ok {
			chBitness := req.Header.Get("Sec-CH-UA-Bitness")
			if chBitness != "" {
				trimmedCH := strings.Trim(chBitness, "\"")
				if bitness != trimmedCH {
					indicators = na.addindicator(vec, indicators, "inconsistent_userAgentData_bitness", 0.30, "userAgentData.bitness", bitness, trimmedCH, "medium", "Navigator userAgentData.bitness does not match Sec-CH-UA-Bitness header.")
				}
			}
		}

		// Phase 96: check fullVersionList correlation
		if fullVersionList, ok := uaData["fullVersionList"].([]interface{}); ok {
			chFullVersion := req.Header.Get("Sec-CH-UA-Full-Version-List")
			if chFullVersion != "" {
				// We won't do a perfect string match because order might vary,
				// but we'll check if the brands and full versions exist.
				for _, brand := range fullVersionList {
					if bMap, ok := brand.(map[string]interface{}); ok {
						bName, _ := bMap["brand"].(string)
						bVersion, _ := bMap["version"].(string)
						if bName != "" && bVersion != "" {
							if !strings.Contains(chFullVersion, fmt.Sprintf("\"%s\";v=\"%s\"", bName, bVersion)) {
								indicators = na.addindicator(vec, indicators, "inconsistent_userAgentData_fullVersionList", 0.40, "userAgentData.fullVersionList", fmt.Sprintf("%s:%s", bName, bVersion), "present in header", "high", "Navigator userAgentData.fullVersionList contains brands not present in Sec-CH-UA-Full-Version-List header.")
								break
							}
						}
					}
				}
			}
		}
	}

	return indicators
}

func (na *NavigatorAnalyzer) addindicator(vec *DetectionVector, indicators []string, name string, score float64, field, actual, expected, severity, desc string) []string {
	indicators = append(indicators, name)
	vec.Score += score
	vec.CheckReports = append(vec.CheckReports, CheckReport{
		Name:        name,
		Fired:       true,
		Weight:      score,
		Score:       score,
		Field:       field,
		Actual:      actual,
		Expected:    expected,
		Severity:    severity,
		Description: desc,
	})
	return indicators
}

func (na *NavigatorAnalyzer) checkMaxTouchPointsConsistency(navData map[string]interface{}, vec *DetectionVector, indicators []string, reqUA string) []string {
	maxTouch, hasMaxTouch := navData["maxTouchPoints"].(float64)
	if !hasMaxTouch {
		return indicators
	}

	uaLower := strings.ToLower(reqUA)
	isMobile := strings.Contains(uaLower, "mobile") || strings.Contains(uaLower, "android") || strings.Contains(uaLower, "iphone") || strings.Contains(uaLower, "ipad")

	if !isMobile && maxTouch > 0 {
		// Rare for desktop to have touch points unless it's a touch screen, but bots often spoof it.
		// We'll be conservative and flag high values (>0) on desktop as suspicious if other flags exist.
		indicators = append(indicators, "suspicious_desktop_max_touch_points")
		vec.Score += 0.20
	} else if isMobile && maxTouch == 0 {
		indicators = append(indicators, "inconsistent_mobile_max_touch_points")
		vec.Score += 0.45
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "inconsistent_mobile_max_touch_points",
			Fired:       true,
			Weight:      0.45,
			Score:       0.45,
			Field:       "maxTouchPoints",
			Actual:      "0",
			Expected:    "> 0 (for mobile)",
			Severity:    "high",
			Description: "Mobile User-Agent reports 0 maxTouchPoints, which is impossible for modern touch devices.",
		})
	}

	return indicators
}

func (na *NavigatorAnalyzer) checkUserActivation(navData map[string]interface{}, vec *DetectionVector, indicators []string, reqUA string) []string {
	isChrome := strings.Contains(strings.ToLower(reqUA), "chrome")
	if isChrome {
		if _, hasActivation := navData["userActivation"]; !hasActivation {
			indicators = append(indicators, "missing_navigator_userActivation")
			vec.Score += 0.25
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "missing_navigator_userActivation",
				Fired:       true,
				Weight:      0.25,
				Score:       0.25,
				Field:       "navigator.userActivation",
				Actual:      "absent",
				Expected:    "present",
				Severity:    "medium",
				Description: "Modern Chromium browsers expose navigator.userActivation to track user interaction state.",
			})
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkSchedulingAPI(navData map[string]interface{}, vec *DetectionVector, indicators []string, reqUA string) []string {
	isChrome := strings.Contains(strings.ToLower(reqUA), "chrome")
	if isChrome {
		if _, hasScheduling := navData["scheduling"]; !hasScheduling {
			indicators = append(indicators, "missing_navigator_scheduling")
			vec.Score += 0.25
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "missing_navigator_scheduling",
				Fired:       true,
				Weight:      0.25,
				Score:       0.25,
				Field:       "navigator.scheduling",
				Actual:      "absent",
				Expected:    "present",
				Severity:    "medium",
				Description: "Modern Chromium browsers expose navigator.scheduling for task prioritization and input pending checks.",
			})
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkLocksAPI(navData map[string]interface{}, vec *DetectionVector, indicators []string, reqUA string) []string {
	// Web Locks API is standard in modern browsers
	if _, hasLocks := navData["locks"]; !hasLocks {
		indicators = append(indicators, "missing_navigator_locks")
		vec.Score += 0.2
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        "missing_navigator_locks",
			Fired:       true,
			Weight:      0.2,
			Score:       0.2,
			Field:       "navigator.locks",
			Actual:      "absent",
			Expected:    "present",
			Severity:    "low",
			Description: "The Web Locks API (navigator.locks) is a standard modern browser API available in all major engines.",
		})
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkIntlConsistency(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if intlTZ, ok := navData["intl_timezone"].(string); ok {
		if browserTZ, ok := navData["timezone"].(string); ok {
			if intlTZ != browserTZ {
				indicators = append(indicators, "intl_timezone_mismatch")
				vec.Score += 0.4
				vec.CheckReports = append(vec.CheckReports, CheckReport{
					Name:        "intl_timezone_mismatch",
					Fired:       true,
					Weight:      0.4,
					Score:       0.4,
					Field:       "Intl.DateTimeFormat().resolvedOptions().timeZone",
					Actual:      intlTZ,
					Expected:    browserTZ,
					Severity:    "medium",
					Description: "Intl API timezone reports a different value than the primary navigator timezone property.",
				})
			}
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkMemoryPlausibility(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	perfMem, hasPerf := navData["performance_memory"].(map[string]interface{})
	deviceMem, _ := navData["deviceMemory"].(float64)

	if hasPerf {
		limit, _ := perfMem["jsHeapSizeLimit"].(float64)
		// Standard Chrome heap limits based on deviceMemory (GB):
		// 4GB -> ~2GB limit, 8GB+ -> ~4GB limit.
		// If limit is < 1GB or doesn't match expected scale, it's suspicious.
		if deviceMem >= 8 && limit < 3.5e9 {
			indicators = append(indicators, "performance_memory_limit_too_low_for_ram")
			vec.Score += 0.35
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "performance_memory_plausibility",
				Fired:       true,
				Weight:      0.35,
				Score:       0.35,
				Field:       "performance.memory.jsHeapSizeLimit",
				Actual:      fmt.Sprintf("%.0f", limit),
				Expected:    "> 3.5GB (for 8GB+ RAM)",
				Severity:    "high",
				Description: "The reported JS heap size limit is too low for the claimed device memory, suggesting a headless or restricted environment.",
			})
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkAutomationLeaks(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
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

func (na *NavigatorAnalyzer) checkAudioWorklet(navData map[string]interface{}, vec *DetectionVector, indicators []string, ua string) []string {
	// Only for modern browsers
	uaLower := strings.ToLower(ua)
	isChrome := strings.Contains(uaLower, "chrome")
	isFirefox := strings.Contains(uaLower, "firefox")
	
	if isChrome || isFirefox {
		awAvailable, ok := navData["audio_worklet_available"].(bool)
		// If it's explicitly false or missing in a modern browser navigator data (if reported there)
		if ok && !awAvailable {
			indicators = append(indicators, "missing_audio_worklet")
			vec.Score += 0.4
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "missing_audio_worklet",
				Fired:       true,
				Weight:      0.4,
				Score:       0.4,
				Field:       "audioWorklet",
				Actual:      "false/missing",
				Expected:    "true",
				Severity:    "high",
				Description: "BaseAudioContext.audioWorklet is missing, which is standard in modern browsers and often absent in restricted or older bot environments.",
			})
		}
	}
	return indicators
}
func (na *NavigatorAnalyzer) checkNavigatorVibrate(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if _, ok := navData["vibrate"]; !ok {
		name := "missing_navigator_vibrate"
		indicators = append(indicators, name)
		vec.Score += 0.20
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        name,
			Fired:       true,
			Weight:      0.20,
			Score:       0.20,
			Field:       "navigator.vibrate",
			Actual:      "absent",
			Expected:    "present",
			Severity:    "medium",
			Description: "The Navigator.vibrate() API is a standard browser feature and is often missing in simplified bot environments.",
		})
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkNavigatorConnectivity(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	if _, ok := navData["onLine"]; !ok {
		name := "missing_navigator_onLine"
		indicators = append(indicators, name)
		vec.Score += 0.15
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        name,
			Fired:       true,
			Weight:      0.15,
			Score:       0.15,
			Field:       "navigator.onLine",
			Actual:      "absent",
			Expected:    "present (true)",
			Severity:    "low",
			Description: "The Navigator.onLine property is missing, which is highly unusual for a connected browser session.",
		})
	}
	return indicators
}
func (na *NavigatorAnalyzer) checkNavigatorHardwareAPIs(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	// Bluetooth and USB are part of the standard Chromium navigator object.
	apis := []string{"bluetooth", "usb"}
	for _, api := range apis {
		val, ok := navData[api]
		if !ok {
			name := fmt.Sprintf("missing_navigator_%s", api)
			indicators = append(indicators, name)
			vec.Score += 0.20
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        name,
				Fired:       true,
				Weight:      0.20,
				Score:       0.20,
				Field:       "navigator." + api,
				Actual:      "absent",
				Expected:    "present",
				Severity:    "medium",
				Description: fmt.Sprintf("The Navigator.%s API is a standard browser feature and is often missing in simplified bot environments.", api),
			})
		} else {
			// Check for shallow stubs (Phase 78)
			apiData, isMap := val.(map[string]interface{})
			if isMap {
				if api == "bluetooth" {
					if _, hasAvail := apiData["getAvailability"]; !hasAvail {
						name := "bluetooth_api_stubbed"
						indicators = append(indicators, name)
						vec.Score += 0.30
						vec.CheckReports = append(vec.CheckReports, CheckReport{
							Name:        name,
							Fired:       true,
							Weight:      0.30,
							Score:       0.30,
							Field:       "navigator.bluetooth.getAvailability",
							Actual:      "absent",
							Expected:    "present",
							Severity:    "medium",
							Description: "The Bluetooth API is stubbed without the getAvailability method.",
						})
					}
				} else if api == "usb" {
					if _, hasGetDevices := apiData["getDevices"]; !hasGetDevices {
						name := "usb_api_stubbed"
						indicators = append(indicators, name)
						vec.Score += 0.30
						vec.CheckReports = append(vec.CheckReports, CheckReport{
							Name:        name,
							Fired:       true,
							Weight:      0.30,
							Score:       0.30,
							Field:       "navigator.usb.getDevices",
							Actual:      "absent",
							Expected:    "present",
							Severity:    "medium",
							Description: "The USB API is stubbed without the getDevices method.",
						})
					}
				}
			}
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkGamepadAPI(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	// Gamepad API (Phase 77)
	if _, ok := navData["getGamepads"]; !ok {
		if len(navData) > 10 {
			name := "missing_navigator_getGamepads"
			indicators = append(indicators, name)
			vec.Score += 0.25
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        name,
				Fired:       true,
				Weight:      0.25,
				Score:       0.25,
				Field:       "navigator.getGamepads",
				Actual:      "absent",
				Expected:    "present",
				Severity:    "medium",
				Description: "The Gamepad API is missing, which is standard in modern browsers.",
			})
		}
	} else {
		if stubbed, ok := navData["gamepad_api_stubbed"].(bool); ok && stubbed {
			name := "gamepad_api_stubbed"
			indicators = append(indicators, name)
			vec.Score += 0.35
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        name,
				Fired:       true,
				Weight:      0.35,
				Score:       0.35,
				Field:       "navigator.getGamepads",
				Actual:      "stubbed",
				Expected:    "native",
				Severity:    "medium",
				Description: "The Gamepad API is detectably stubbed.",
			})
		}
	}
	return indicators
}

func (na *NavigatorAnalyzer) checkNavigatorModernAPIs(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	// Clipboard and Credentials are standard modern browser APIs.
	// Often missing in headless/restricted environments.
	apis := []string{"clipboard", "credentials"}
	for _, api := range apis {
		if _, ok := navData[api]; !ok {
			name := fmt.Sprintf("missing_navigator_%s", api)
			indicators = append(indicators, name)
			vec.Score += 0.20
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        name,
				Fired:       true,
				Weight:      0.20,
				Score:       0.20,
				Field:       "navigator." + api,
				Actual:      "absent",
				Expected:    "present",
				Severity:    "medium",
				Description: fmt.Sprintf("The Navigator.%s API is a standard browser feature and is often missing in simplified bot environments.", api),
			})
		}
	}
	return indicators
}
func (na *NavigatorAnalyzer) checkNavigatorMediaAPIs(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	// mediaCapabilities (Chrome 66+) and mediaSession (Chrome 73+) are standard modern browser APIs.
	apis := []string{"mediaCapabilities", "mediaSession"}
	for _, api := range apis {
		if _, ok := navData[api]; !ok {
			name := fmt.Sprintf("missing_navigator_%s", api)
			indicators = append(indicators, name)
			vec.Score += 0.20
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        name,
				Fired:       true,
				Weight:      0.20,
				Score:       0.20,
				Field:       "navigator." + api,
				Actual:      "absent",
				Expected:    "present",
				Severity:    "medium",
				Description: fmt.Sprintf("The Navigator.%s API is a standard browser feature and is often missing in simplified bot environments.", api),
			})
		}
	}
	return indicators
}
func (na *NavigatorAnalyzer) checkNavigatorWorkers(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	// serviceWorker and SharedWorker are standard modern browser APIs.
	// serviceWorker is usually available on secure contexts (which we assume here).
	apis := []string{"serviceWorker", "sharedWorker"}
	for _, api := range apis {
		if _, ok := navData[api]; !ok {
			name := fmt.Sprintf("missing_navigator_%s", api)
			indicators = append(indicators, name)
			vec.Score += 0.20
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        name,
				Fired:       true,
				Weight:      0.20,
				Score:       0.20,
				Field:       "navigator." + api,
				Actual:      "absent",
				Expected:    "present",
				Severity:    "medium",
				Description: fmt.Sprintf("The Navigator.%s API is a standard browser feature and is often missing in simplified bot environments.", api),
			})
		}
	}
	return indicators
}
func (na *NavigatorAnalyzer) checkNavigatorPrototype(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	// Phase 80: Navigator Prototype chain.
	if stubbed, ok := navData["navigator_prototype_stubbed"].(bool); ok && stubbed {
		name := "navigator_prototype_mismatch"
		indicators = append(indicators, name)
		vec.Score += 0.45
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        name,
			Fired:       true,
			Weight:      0.45,
			Score:       0.45,
			Field:       "navigator.__proto__",
			Actual:      "own properties",
			Expected:    "prototype properties",
			Severity:    "high",
			Description: "The Navigator object has own properties where getter/setter properties on the prototype are expected.",
		})
	}
	return indicators
}

// checkWorkerContextCoherence (Phase 91)
func (na *NavigatorAnalyzer) checkWorkerContextCoherence(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	workerRaw, ok := navData["worker_navigator"]
	if !ok {
		return indicators
	}
	workerData, ok := workerRaw.(map[string]interface{})
	if !ok {
		return indicators
	}

	checks := []struct {
		prop string
		name string
	}{
		{"userAgent", "worker_userAgent_mismatch"},
		{"platform", "worker_platform_mismatch"},
		{"hardwareConcurrency", "worker_hardwareConcurrency_mismatch"},
	}

	for _, c := range checks {
		mainVal := navData[c.prop]
		workerVal := workerData[c.prop]
		if mainVal != nil && workerVal != nil && mainVal != workerVal {
			name := c.name
			indicators = append(indicators, name)
			vec.Score += 0.35
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        name,
				Fired:       true,
				Weight:      0.35,
				Score:       0.35,
				Field:       "worker." + c.prop,
				Actual:      fmt.Sprintf("%v", workerVal),
				Expected:    fmt.Sprintf("%v", mainVal),
				Severity:    "medium",
				Description: fmt.Sprintf("Navigator properties in the Worker context do not match the main thread (mismatch on %s).", c.prop),
			})
		}
	}
	return indicators
}

// checkRuntimeIntrospection (Phase 92)
func (na *NavigatorAnalyzer) checkRuntimeIntrospection(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
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

func (na *NavigatorAnalyzer) checkCanvasMeasureText(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	metrics, ok := navData["canvas_measure_text"].(map[string]interface{})
	if !ok {
		return indicators
	}

	// Basic check: 'i' and 'W' should have different widths in non-monospace fonts
	iWidth, okI := metrics["i"].(float64)
	wWidth, okW := metrics["W"].(float64)

	if okI && okW && iWidth == wWidth && iWidth > 0 {
		name := "canvas_measureText_fixed_width_stub"
		indicators = append(indicators, name)
		vec.Score += 0.50
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        name,
			Fired:       true,
			Weight:      0.50,
			Score:       0.50,
			Field:       "canvas.measureText",
			Actual:      fmt.Sprintf("i=%f, W=%f", iWidth, wWidth),
			Expected:    "i < W",
			Severity:    "high",
			Description: "Canvas measureText(text).width returns identical values for 'i' and 'W', indicating a simplified fixed-width stub.",
		})
	}

	return indicators
}

func (na *NavigatorAnalyzer) checkMathPrecision(navData map[string]interface{}, vec *DetectionVector, indicators []string) []string {
	mathProps, ok := navData["math_precision"].(map[string]interface{})
	if !ok {
		return indicators
	}

	// Example values for Math.sin(1e15) and Math.cos(1e15)
	// V8 (Chrome/Deno/Node): cos(1e15) = -0.9352358826620556
	// SpiderMonkey (Firefox): cos(1e15) = -0.9352358826620556
	// However, edge cases like Math.tan(1e15) or very large inputs can vary.
	// We'll check for "common" bot-stubbed or inconsistent values.

	sin1e15, _ := mathProps["sin1e15"].(float64)
	cos1e15, _ := mathProps["cos1e15"].(float64)

	// If these are exactly 0 or 1, or missing, it's a huge red flag
	if sin1e15 == 0 && cos1e15 == 0 {
		name := "math_precision_stubbed"
		indicators = append(indicators, name)
		vec.Score += 0.40
		vec.CheckReports = append(vec.CheckReports, CheckReport{
			Name:        name,
			Fired:       true,
			Weight:      0.40,
			Score:       0.40,
			Field:       "Math.sin/cos",
			Actual:      "zero/stubbed",
			Expected:    "precise float",
			Severity:    "high",
			Description: "Math trigonometric functions return suspiciously clean or zeroed values, suggesting a naive JS engine stub.",
		})
	}

	return indicators
}
