package adversarial

import (
	"encoding/json"
	"fmt"
	"log"
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

	log.Printf("NAV_DATA JSON: %+v", navData)

	indicators := make([]string, 0)
	reqUA := req.Header.Get("User-Agent")

	indicators = na.checkWebdriver(navData, vec, indicators)
	indicators = na.checkChromeRuntime(navData, vec, indicators, reqUA)
	indicators = na.checkAudioLatency(req, vec, indicators)
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
	indicators = na.checkVideoElement(navData, vec, indicators)
	indicators = na.checkPermissionsAPI(navData, vec, indicators)
	indicators = na.checkTimezoneParity(navData, vec, indicators)
	indicators = na.checkKeyboardAPI(navData, vec, indicators, reqUA)
	indicators = na.checkVendor(navData, vec, indicators, reqUA)
	indicators = na.checkNetworkCoherence(navData, vec, indicators)
	indicators = na.checkNotificationPermission(navData, vec, indicators)

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
	} else {
		indicators = append(indicators, "missing_performance_memory")
		vec.Score += 0.15
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
			indicators = append(indicators, fmt.Sprintf("network_effectivetype_rtt_mismatch: 4g_rtt=%.0fms", rtt))
			vec.Score += 0.20
			vec.CheckReports = append(vec.CheckReports, CheckReport{
				Name:        "network_effectivetype_rtt_mismatch",
				Fired:       true,
				Weight:      0.20,
				Score:       0.20,
				Field:       "connection.effectiveType + connection.rtt",
				Actual:      fmt.Sprintf("4g / %0.fms", rtt),
				Expected:    "4g with RTT < 200ms",
				Severity:    "medium",
				Description: "effectiveType '4g' is inconsistent with high RTT",
			})
		}
		if effType == "4g" && hasDown && downlink < 1.0 {
			indicators = append(indicators, fmt.Sprintf("network_effectivetype_downlink_mismatch: 4g_downlink=%.1fMbps", downlink))
			vec.Score += 0.20
		}

		// Phase 43: Non-Quantized Network Quality
		if hasRTT {
			if int(rtt)%25 != 0 {
				indicators = append(indicators, fmt.Sprintf("non_quantized_network_rtt: %.0fms", rtt))
				vec.Score += 0.20
				vec.CheckReports = append(vec.CheckReports, CheckReport{
					Name:        "non_quantized_network_rtt",
					Fired:       true,
					Weight:      0.20,
					Score:       0.20,
					Field:       "connection.rtt",
					Actual:      fmt.Sprintf("%.0fms", rtt),
					Expected:    "multiple of 25ms",
					Severity:    "medium",
					Description: "RTT value is not quantized.",
				})
			}
		}
		if hasDown {
			downStr := fmt.Sprintf("%f", downlink)
			if strings.Contains(downStr, ".") {
				parts := strings.Split(downStr, ".")
				if len(parts) > 1 {
					decimals := strings.TrimRight(parts[1], "0")
					if len(decimals) > 2 {
						indicators = append(indicators, fmt.Sprintf("non_quantized_network_downlink: %.4fMbps", downlink))
						vec.Score += 0.20
					}
				}
			}
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
